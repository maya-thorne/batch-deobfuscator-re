# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "pyyaml>=6.0",
#   "datasets>=3.0.0",
#   "huggingface_hub>=0.26.0",
#   "pysigma>=0.11.0",
#   "pysigma-backend-splunk>=1.1.0",
#   "pysigma-backend-elasticsearch>=1.1.0",
#   "pysigma-backend-kusto>=0.4.0",
#   "requests>=2.31.0",
# ]
# ///
"""SigmaForge dataset builder.

Downloads the SigmaHQ rule corpus, normalizes every rule, and produces three
dataset configurations:

  1. description_to_sigma - natural-language detection description -> Sigma YAML
  2. logs_to_sigma        - synthesized positive/negative events -> Sigma YAML
  3. sigma_repair         - programmatically corrupted rule + validation errors -> fixed rule

Each record also carries SIEM compilations (Splunk SPL, Elastic Lucene, and
Microsoft Sentinel KQL) produced with pySigma backends, plus MITRE ATT&CK
mappings extracted from rule tags. Runs entirely on Hugging Face Jobs.
"""

from __future__ import annotations

import copy
import io
import json
import os
import random
import re
import zipfile

import requests
import yaml
from datasets import Dataset

RULES_ZIP = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
REPO_ID = os.environ.get("DATASET_REPO", "alirezaaminzadeh/sigmaforge-detection-rules")
SEED = 20260809
MAX_RULES = int(os.environ.get("MAX_RULES", "0"))  # 0 = all

random.seed(SEED)

# ---------------------------------------------------------------------------
# pySigma backends
# ---------------------------------------------------------------------------
from sigma.collection import SigmaCollection

BACKENDS = {}
try:
    from sigma.backends.splunk import SplunkBackend

    BACKENDS["splunk_spl"] = SplunkBackend()
except Exception as exc:  # pragma: no cover
    print(f"[warn] Splunk backend unavailable: {exc}")

try:
    from sigma.backends.elasticsearch import LuceneBackend

    BACKENDS["elastic_lucene"] = LuceneBackend()
except Exception as exc:
    print(f"[warn] Elasticsearch backend unavailable: {exc}")

try:
    from sigma.backends.kusto import KustoBackend
    from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

    BACKENDS["sentinel_kql"] = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
except Exception as exc:
    print(f"[warn] Kusto backend unavailable: {exc}")


def compile_rule(rule_yaml: str) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for name, backend in BACKENDS.items():
        try:
            collection = SigmaCollection.from_yaml(rule_yaml)
            queries = backend.convert(collection)
            out[name] = queries[0] if queries else None
        except Exception:
            out[name] = None
    for name in ("splunk_spl", "elastic_lucene", "sentinel_kql"):
        out.setdefault(name, None)
    return out


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

def download_rules() -> list[tuple[str, dict]]:
    print("Downloading SigmaHQ rule corpus...")
    resp = requests.get(RULES_ZIP, timeout=300)
    resp.raise_for_status()
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    rules: list[tuple[str, dict]] = []
    for name in zf.namelist():
        if "/rules/" not in name or not name.endswith(".yml"):
            continue
        try:
            text = zf.read(name).decode("utf-8")
            doc = yaml.safe_load(text)
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        if not all(k in doc for k in ("title", "logsource", "detection")):
            continue
        rel = name.split("/rules/", 1)[1]
        rules.append((rel, doc))
    print(f"Loaded {len(rules)} parseable rules")
    return rules


def dump_yaml(doc: dict) -> str:
    return yaml.safe_dump(doc, sort_keys=False, default_flow_style=False, allow_unicode=True, width=120)


ATTACK_RE = re.compile(r"^attack\.((?:t\d{4})(?:\.\d{3})?)$", re.IGNORECASE)
TACTIC_RE = re.compile(r"^attack\.([a-z_-]+)$")


def extract_attack(doc: dict) -> tuple[list[str], list[str]]:
    techniques, tactics = [], []
    for tag in doc.get("tags") or []:
        tag = str(tag)
        m = ATTACK_RE.match(tag)
        if m:
            techniques.append(m.group(1).upper())
            continue
        m = TACTIC_RE.match(tag)
        if m:
            tactics.append(m.group(1))
    return techniques, tactics


# ---------------------------------------------------------------------------
# Config 2 helpers: synthesize events from the detection block
# ---------------------------------------------------------------------------

def _concretize(value):
    if isinstance(value, list):
        value = value[0] if value else "value"
    value = str(value)
    value = value.replace("*", "x").replace("?", "y")
    return value or "value"


def synth_events(doc: dict) -> tuple[list[dict], list[dict]]:
    """Build one matching event per mapping-selection and mutated negatives."""
    detection = doc.get("detection", {})
    positives, negatives = [], []
    for key, sel in detection.items():
        if key == "condition" or not isinstance(sel, dict):
            continue
        event = {}
        for field, val in sel.items():
            base = field.split("|", 1)[0]
            event[base] = _concretize(val)
        if not event:
            continue
        positives.append(event)
        neg = dict(event)
        mut_field = random.choice(list(neg))
        neg[mut_field] = "benign_" + neg[mut_field][::-1][:40]
        negatives.append(neg)
        if len(positives) >= 3:
            break
    return positives, negatives


# ---------------------------------------------------------------------------
# Config 3 helpers: corruption strategies
# ---------------------------------------------------------------------------

def corrupt_rule(doc: dict) -> tuple[dict, list[str]] | None:
    strategies = []
    if "id" in doc:
        strategies.append("drop_id")
    if "status" in doc:
        strategies.append("bad_status")
    if "level" in doc:
        strategies.append("bad_level")
    if isinstance(doc.get("detection"), dict) and "condition" in doc["detection"]:
        strategies.append("dangling_condition")
        strategies.append("drop_condition")
    if "logsource" in doc:
        strategies.append("empty_logsource")
    if "date" in doc:
        strategies.append("bad_date")
    if not strategies:
        return None

    broken = copy.deepcopy(doc)
    errors: list[str] = []
    for strategy in random.sample(strategies, k=min(len(strategies), random.choice((1, 1, 2)))):
        if strategy == "drop_id":
            broken.pop("id", None)
            errors.append("Missing required attribute: rule identifier 'id' (UUID) is not set.")
        elif strategy == "bad_status":
            broken["status"] = "in-progress"
            errors.append("Invalid value for 'status': 'in-progress' is not one of stable/test/experimental/deprecated/unsupported.")
        elif strategy == "bad_level":
            broken["level"] = "severe"
            errors.append("Invalid value for 'level': 'severe' is not one of informational/low/medium/high/critical.")
        elif strategy == "dangling_condition":
            broken["detection"]["condition"] = str(broken["detection"]["condition"]) + " and selection_missing"
            errors.append("Condition references undefined detection item 'selection_missing'.")
        elif strategy == "drop_condition":
            broken["detection"].pop("condition", None)
            errors.append("Detection section has no 'condition' expression.")
        elif strategy == "empty_logsource":
            broken["logsource"] = {}
            errors.append("Logsource section is empty: at least one of product/category/service must be defined.")
        elif strategy == "bad_date":
            broken["date"] = "09/08/2026"
            errors.append("Invalid 'date' format: expected ISO 8601 (YYYY-MM-DD).")
    return broken, errors


# ---------------------------------------------------------------------------
# Build records
# ---------------------------------------------------------------------------

def main() -> None:
    rules = download_rules()
    if MAX_RULES:
        rules = rules[:MAX_RULES]
    random.shuffle(rules)

    desc_records, logs_records, repair_records = [], [], []
    compiled_ok = 0

    for idx, (path, doc) in enumerate(rules):
        if idx and idx % 500 == 0:
            print(f"  processed {idx}/{len(rules)} rules")
        rule_yaml = dump_yaml(doc)
        techniques, tactics = extract_attack(doc)
        logsource = doc.get("logsource", {}) or {}
        compiled = compile_rule(rule_yaml)
        if compiled["splunk_spl"]:
            compiled_ok += 1

        description = (doc.get("description") or doc.get("title") or "").strip()
        if description:
            desc_records.append(
                {
                    "rule_id": str(doc.get("id", "")),
                    "title": str(doc.get("title", "")),
                    "description": description,
                    "logsource_product": str(logsource.get("product", "") or ""),
                    "logsource_category": str(logsource.get("category", "") or ""),
                    "logsource_service": str(logsource.get("service", "") or ""),
                    "sigma_rule": rule_yaml,
                    "attack_techniques": techniques,
                    "attack_tactics": tactics,
                    "level": str(doc.get("level", "") or ""),
                    "status": str(doc.get("status", "") or ""),
                    "false_positives": [str(x) for x in (doc.get("falsepositives") or [])],
                    "references": [str(x) for x in (doc.get("references") or [])],
                    "splunk_spl": compiled["splunk_spl"],
                    "elastic_lucene": compiled["elastic_lucene"],
                    "sentinel_kql": compiled["sentinel_kql"],
                    "source_path": path,
                }
            )

        positives, negatives = synth_events(doc)
        if positives:
            logs_records.append(
                {
                    "rule_id": str(doc.get("id", "")),
                    "title": str(doc.get("title", "")),
                    "logsource_product": str(logsource.get("product", "") or ""),
                    "logsource_category": str(logsource.get("category", "") or ""),
                    "positive_events": json.dumps(positives, ensure_ascii=False),
                    "negative_events": json.dumps(negatives, ensure_ascii=False),
                    "expected_rule": rule_yaml,
                    "false_positive_cases": [str(x) for x in (doc.get("falsepositives") or [])],
                    "attack_techniques": techniques,
                    "source_path": path,
                }
            )

        corrupted = corrupt_rule(doc)
        if corrupted:
            broken, errors = corrupted
            repair_records.append(
                {
                    "rule_id": str(doc.get("id", "")),
                    "title": str(doc.get("title", "")),
                    "broken_rule": dump_yaml(broken),
                    "validation_errors": errors,
                    "corrected_rule": rule_yaml,
                    "attack_techniques": techniques,
                    "source_path": path,
                }
            )

    print(
        f"Records: description_to_sigma={len(desc_records)}, "
        f"logs_to_sigma={len(logs_records)}, sigma_repair={len(repair_records)}; "
        f"splunk-compilable={compiled_ok}"
    )

    token = os.environ["HF_TOKEN"]
    for config_name, records in (
        ("description_to_sigma", desc_records),
        ("logs_to_sigma", logs_records),
        ("sigma_repair", repair_records),
    ):
        ds = Dataset.from_list(records)
        split = ds.train_test_split(test_size=0.05, seed=SEED)
        split["train"].push_to_hub(REPO_ID, config_name=config_name, split="train", token=token)
        split["test"].push_to_hub(REPO_ID, config_name=config_name, split="test", token=token)
        print(f"Pushed config '{config_name}': train={len(split['train'])}, test={len(split['test'])}")

    print("Dataset build complete.")


if __name__ == "__main__":
    main()
