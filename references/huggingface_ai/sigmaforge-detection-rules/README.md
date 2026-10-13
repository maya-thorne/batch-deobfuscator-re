---
license: mit
task_categories:
- text-generation
language:
- en
tags:
- cybersecurity
- detection-engineering
- sigma
- siem
- mitre-attack
- threat-detection
pretty_name: SigmaForge Detection Rules
size_categories:
- 1K<n<10K
configs:
- config_name: description_to_sigma
  data_files:
  - split: train
    path: description_to_sigma/train-*
  - split: test
    path: description_to_sigma/test-*
- config_name: logs_to_sigma
  data_files:
  - split: train
    path: logs_to_sigma/train-*
  - split: test
    path: logs_to_sigma/test-*
- config_name: sigma_repair
  data_files:
  - split: train
    path: sigma_repair/train-*
  - split: test
    path: sigma_repair/test-*
---

# SigmaForge Detection Rules

SigmaForge is a structured, operational dataset for building and evaluating
systems that generate, validate, and translate [Sigma](https://sigmahq.io/)
detection rules. Sigma is a vendor-agnostic YAML format that describes
detection logic so it can be shared across SIEM platforms.

The dataset is derived from the open-source [SigmaHQ](https://github.com/SigmaHQ/sigma)
rule corpus. Every rule is normalized and enriched with:

- MITRE ATT&CK technique and tactic mappings extracted from rule tags.
- Compiled SIEM queries produced with [pySigma](https://github.com/SigmaHQ/pySigma)
  backends: **Splunk SPL**, **Elastic Lucene**, and **Microsoft Sentinel KQL**.
- Documented false-positive guidance and references where available.

## Configurations

### `description_to_sigma`
Maps a natural-language detection description (plus log-source hints and ATT&CK
context) to the target Sigma YAML rule and its compiled SIEM queries.

Key fields: `description`, `logsource_product`, `logsource_category`,
`sigma_rule`, `attack_techniques`, `attack_tactics`, `false_positives`,
`splunk_spl`, `elastic_lucene`, `sentinel_kql`.

### `logs_to_sigma`
Provides synthesized positive and negative events for a rule and the detection
rule that should match the positives while excluding the negatives. Useful for
detection-by-example and for testing recall / false-positive behavior.

Key fields: `positive_events` (JSON), `negative_events` (JSON),
`expected_rule`, `false_positive_cases`, `attack_techniques`.

### `sigma_repair`
Pairs a programmatically corrupted rule and the corresponding validation errors
with the corrected rule. Corruptions cover missing identifiers, invalid
status/level enums, dangling or missing conditions, empty log sources, and
malformed dates.

Key fields: `broken_rule`, `validation_errors`, `corrected_rule`,
`attack_techniques`.

## Intended Uses

- Fine-tuning models to draft and repair Sigma rules from analyst input.
- Building agents that convert detection ideas into deployable SIEM queries.
- Benchmarking valid-YAML rate, schema pass rate, backend compilation rate,
  MITRE mapping F1, and repair success rate.

## Provenance and License

Rules originate from the SigmaHQ project (Detection Rule License / DRL 1.1).
Derived fields and this packaging are released under the MIT license. Refer to
the upstream repository for the authoritative rule provenance.
