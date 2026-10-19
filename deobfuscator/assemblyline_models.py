"""
CCCS Assemblyline 4 Service Result Ontology & Data Structures.
Defines models for Sections, Heuristics, Extracted Files, and Results
matching Canadian Centre for Cyber Security (CCCS) Assemblyline 4 specifications.

Engineered by Maya Thorne.
"""

import hashlib
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

# Assemblyline file identification headers
CUSTOM_BATCH_ID = b":: --- BATCH SCRIPT IDENTIFIER --- ::\r\n"
CUSTOM_PS1_ID = b"# --- POWERSHELL SCRIPT IDENTIFIER --- #\r\n"

# Network & File regex patterns matching Assemblyline ODM specifications
IP_REGEX = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
DOMAIN_REGEX = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
FILE_NAME_REGEX = r"[^\\]*\.(\w+)$"

# Standard CCCS Heuristic definitions from Assemblyline service_manifest.yml
CCCS_HEURISTICS: Dict[int, Dict[str, Any]] = {
    1: {
        "name": "Additional command grouping after command normalization",
        "score": 50,
        "attack_ids": ["T1059.003", "T1027"],
    },
    2: {
        "name": "Possible rare LOLBAS found",
        "score": 50,
        "attack_ids": ["T1059.003", "T1218"],
    },
    3: {
        "name": "Execution of variable content",
        "score": 250,
        "attack_ids": ["T1059.003", "T1027"],
    },
    4: {
        "name": "Multiple variable were used on the same line",
        "score": 200,
        "attack_ids": ["T1027"],
    },
    5: {
        "name": "External file download in batch script",
        "score": 0,
        "attack_ids": ["T1105", "T1059.003"],
    },
    6: {
        "name": "Complexe One-Liner",
        "score": 10,
        "attack_ids": ["T1027"],
    },
    7: {
        "name": "Windows Utility Manipulation",
        "score": 10,
        "attack_ids": ["T1036", "T1059.003"],
    },
    8: {
        "name": "File creation using set /p",
        "score": 10,
        "attack_ids": ["T1027", "T1059.003"],
    },
    9: {
        "name": "Execution of manipulated content",
        "score": 0,
        "attack_ids": ["T1059.003"],
    },
    10: {
        "name": "Rundll32 execution",
        "score": 0,
        "attack_ids": ["T1218.011"],
    },
}

KNOWN_LOLBAS_BINARIES = {
    "powershell", "pwsh", "certutil", "bitsadmin", "mshta", "rundll32",
    "cscript", "wscript", "regsvr32", "curl", "certreq", "vssadmin",
    "schtasks", "reg", "xcopy", "expand", "makecab", "hh.exe", "cmstp",
    "installutil", "wmic", "wbadmin", "findstr", "attrib", "wmic.exe"
}


def truncate_command(key: str, value: str, max_len: int = 100) -> Tuple[str, str]:
    """Truncate command strings and adjust key name per CCCS Assemblyline convention."""
    if len(value) > max_len:
        return f"{key} [trunc]", value[:max_len]
    return key, value


def zeroize_bytes(b: Union[bytearray, bytes]) -> None:
    """Cryptographically overwrite a byte buffer in place with null bytes."""
    if isinstance(b, bytearray):
        for i in range(len(b)):
            b[i] = 0


def zeroize_dict(d: Dict[str, Any]) -> None:
    """Recursively scrub sensitive keys and clear dictionary in place."""
    for k in list(d.keys()):
        v = d[k]
        if isinstance(v, (bytearray, bytes)):
            zeroize_bytes(v)
        elif isinstance(v, dict):
            zeroize_dict(v)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    zeroize_dict(item)
        d[k] = None
    d.clear()


class AssemblylineHeuristic:
    """Represents an Assemblyline Heuristic tag, score, and signature mapping."""

    def __init__(
        self,
        heur_id: int,
        name: Optional[str] = None,
        score: Optional[int] = None,
        attack_ids: Optional[List[str]] = None,
    ):
        self.heur_id = heur_id
        spec = CCCS_HEURISTICS.get(heur_id, {})
        self.name = name or spec.get("name", f"Heuristic {heur_id}")
        self.score = spec.get("score", 0) if score is None else score
        self.attack_ids: List[str] = list(attack_ids or spec.get("attack_ids", []))
        self.signatures: Dict[str, int] = {}
        self.score_map: Dict[str, int] = {}
        self.frequency: int = 1

    def add_signature_id(self, signature_name: str, score: int = 0) -> None:
        """Register a triggered signature ID and its optional score contribution."""
        self.signatures[signature_name] = score
        if score > 0:
            self.score_map[signature_name] = score

    def calculate_effective_score(self) -> int:
        """Compute base score plus signature bonuses."""
        sig_bonus = sum(self.signatures.values())
        return self.score + sig_bonus

    def to_dict(self) -> Dict[str, Any]:
        """Serialize heuristic to Assemblyline Section JSON format."""
        return {
            "heur_id": self.heur_id,
            "name": self.name,
            "score": self.calculate_effective_score(),
            "attack_ids": self.attack_ids,
            "frequency": self.frequency,
            "signatures": self.signatures,
            "score_map": self.score_map,
        }


class AssemblylineSection:
    """Represents an Assemblyline ResultSection or Subsection."""

    def __init__(
        self,
        title_text: str,
        body: Optional[Any] = None,
        body_format: str = "TABLE",
        heuristic: Optional[AssemblylineHeuristic] = None,
        classification: str = "TLP:C",
        depth: int = 0,
        auto_collapse: bool = False,
    ):
        self.title_text = title_text
        self.body: Any = body if body is not None else []
        self.body_format = body_format
        self.body_config: Dict[str, Any] = {}
        self.heuristic = heuristic
        self.classification = classification
        self.depth = depth
        self.auto_collapse = auto_collapse
        self.tags: Dict[str, List[str]] = {}
        self.subsections: List["AssemblylineSection"] = []
        self.promote_to: Optional[str] = None
        self.zeroize_on_tag_safe: bool = False

    def add_tag(self, tag_type: str, tag_value: str) -> bool:
        """Add a structured tag if non-empty and not already present."""
        if not tag_value or not tag_type:
            return False
        if tag_type not in self.tags:
            self.tags[tag_type] = []
        if tag_value not in self.tags[tag_type]:
            self.tags[tag_type].append(tag_value)
            return True
        return False

    def add_row(self, row: Dict[str, Any]) -> None:
        """Append a table row to section body."""
        if isinstance(self.body, list):
            self.body.append(row)

    def add_subsection(self, subsection: "AssemblylineSection") -> None:
        """Nest a child subsection under this section."""
        subsection.depth = self.depth + 1
        self.subsections.append(subsection)

    def set_column_order(self, order: List[str]) -> None:
        """Specify column display order for table rendering."""
        self.body_config["column_order"] = order

    def to_dict(self) -> Dict[str, Any]:
        """Serialize section and child subsections to Assemblyline JSON structure."""
        sec_dict: Dict[str, Any] = {
            "title_text": self.title_text,
            "body": self.body,
            "body_format": self.body_format,
            "body_config": self.body_config,
            "classification": self.classification,
            "depth": self.depth,
            "auto_collapse": self.auto_collapse,
            "heuristic": self.heuristic.to_dict() if self.heuristic else None,
            "tags": self.tags,
            "promote_to": self.promote_to,
            "zeroize_on_tag_safe": self.zeroize_on_tag_safe,
        }
        if self.subsections:
            sec_dict["subsections"] = [sub.to_dict() for sub in self.subsections]
        return sec_dict


class AssemblylineExtractedFile:
    """Represents an artifact or stager extracted during batch deobfuscation."""

    def __init__(
        self,
        name: str,
        sha256: str,
        description: str,
        content: Optional[Union[bytes, str]] = None,
        classification: str = "TLP:C",
    ):
        self.name = name
        self.sha256 = sha256
        self.description = description
        self.content = content.encode("utf-8") if isinstance(content, str) else content
        self.classification = classification

    def to_dict(self) -> Dict[str, Any]:
        """Return Assemblyline extracted file record."""
        return {
            "name": self.name,
            "sha256": self.sha256,
            "description": self.description,
        }


class AssemblylineResult:
    """Top-level container for CCCS Assemblyline 4 Service Results."""

    def __init__(self, classification: str = "TLP:C", drop_file: bool = False):
        self.classification = classification
        self.drop_file = drop_file
        self.sections: List[AssemblylineSection] = []
        self.extracted_files: List[AssemblylineExtractedFile] = []
        self.supplementary_files: List[Dict[str, Any]] = []
        self.temp_submission_data: Dict[str, Any] = {}

    def add_section(self, section: AssemblylineSection) -> None:
        """Register a root-level analysis section."""
        self.sections.append(section)

    def add_extracted_file(self, extracted: AssemblylineExtractedFile) -> None:
        """Register an extracted payload or root deobfuscated file."""
        self.extracted_files.append(extracted)

    def calculate_total_score(self) -> int:
        """Sum scores across all heuristics in sections and subsections."""
        total = 0

        def _walk(sec: AssemblylineSection):
            nonlocal total
            if sec.heuristic:
                total += sec.heuristic.calculate_effective_score()
            for sub in sec.subsections:
                _walk(sub)

        for s in self.sections:
            _walk(s)
        return total

    def aggregate_heuristics_and_tags(self) -> Tuple[List[Dict[str, Any]], Dict[str, List[str]]]:
        """Aggregate unique heuristics and tags across entire section tree."""
        heur_map: Dict[int, Dict[str, Any]] = {}
        tag_map: Dict[str, List[str]] = {}

        def _walk(sec: AssemblylineSection):
            if sec.heuristic:
                hid = sec.heuristic.heur_id
                if hid not in heur_map:
                    heur_map[hid] = {
                        "heur_id": hid,
                        "attack_ids": list(sec.heuristic.attack_ids),
                        "signatures": list(sec.heuristic.signatures.keys()),
                    }
                else:
                    for att in sec.heuristic.attack_ids:
                        if att not in heur_map[hid]["attack_ids"]:
                            heur_map[hid]["attack_ids"].append(att)
                    for sig in sec.heuristic.signatures.keys():
                        if sig not in heur_map[hid]["signatures"]:
                            heur_map[hid]["signatures"].append(sig)

            for t_type, t_vals in sec.tags.items():
                if t_type not in tag_map:
                    tag_map[t_type] = []
                for tv in t_vals:
                    if tv not in tag_map[t_type]:
                        tag_map[t_type].append(tv)

            for sub in sec.subsections:
                _walk(sub)

        for s in self.sections:
            _walk(s)

        return list(heur_map.values()), tag_map

    def to_dict(self) -> Dict[str, Any]:
        """Serialize complete service response to CCCS Assemblyline result.json format."""
        score = self.calculate_total_score()
        heurs, tags = self.aggregate_heuristics_and_tags()
        return {
            "extra": {
                "drop_file": self.drop_file,
                "score": score,
                "sections": [s.to_dict() for s in self.sections],
            },
            "files": {
                "extracted": [f.to_dict() for f in self.extracted_files],
                "supplementary": self.supplementary_files,
            },
            "results": {
                "heuristics": heurs,
                "tags": tags,
                "temp_submission_data": self.temp_submission_data,
            },
        }

    def to_json(self, indent: int = 2) -> str:
        """Export serialized JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def save(self, dest_path_or_dir: Union[str, Path], filename: str = "result.json") -> Path:
        """Write JSON report and optional extracted artifacts to destination."""
        target = Path(dest_path_or_dir)
        if target.is_dir() or (not target.suffix and not target.exists()):
            target.mkdir(parents=True, exist_ok=True)
            out_json = target / filename
            work_dir = target
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            out_json = target
            work_dir = target.parent

        out_json.write_text(self.to_json(), encoding="utf-8")

        for exf in self.extracted_files:
            if exf.content:
                out_path = work_dir / exf.name
                out_path.write_bytes(exf.content)

        return out_json
