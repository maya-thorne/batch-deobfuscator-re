"""
CCCS Assemblyline Service Interoperability Bridge & Report Generator.
Translates multi-pass batch deobfuscation results, heuristics, extracted payloads,
and forensic metadata into standard Canadian Centre for Cyber Security (CCCS)
Assemblyline 4 Service Result JSON ontology.

Engineered by Maya Thorne.
"""

import hashlib
import ntpath
import os
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union
from urllib.parse import urlparse

from .assemblyline_models import (
    CUSTOM_BATCH_ID,
    CUSTOM_PS1_ID,
    IP_REGEX,
    DOMAIN_REGEX,
    CCCS_HEURISTICS,
    KNOWN_LOLBAS_BINARIES,
    truncate_command,
    zeroize_bytes,
    zeroize_dict,
    AssemblylineHeuristic,
    AssemblylineSection,
    AssemblylineExtractedFile,
    AssemblylineResult,
)


def extract_batch_traits(
    original_script: str,
    deobfuscated_script: str,
    meta: Dict[str, Any],
    complex_one_liner_threshold: int = 4,
) -> Dict[str, Any]:
    """
    Extract CCCS Assemblyline traits from script transformations and telemetry.
    Matches traits produced by Assemblyline batchdeobfuscator service.
    """
    traits: Dict[str, Any] = {}

    orig_lines = [line.strip() for line in original_script.splitlines() if line.strip()]
    norm_lines = [line.strip() for line in deobfuscated_script.splitlines() if line.strip()]

    # Trait 6: Complex One-Liner
    if len(orig_lines) <= 2 and len(norm_lines) >= complex_one_liner_threshold:
        traits["complex-one-liner"] = len(norm_lines)

    # Trait 1: Command grouping after normalization
    grouping_items = []
    for orig, norm in zip(orig_lines, norm_lines):
        if ("&" in norm or "|" in norm) and not ("&" in orig or "|" in orig):
            grouping_items.append({"Command": orig, "Normalized": norm})
    if grouping_items:
        traits["command-grouping"] = grouping_items

    # Trait 2: LOLBAS found
    lolbas_found = []
    for line in norm_lines:
        line_lower = line.lower()
        for lb in KNOWN_LOLBAS_BINARIES:
            if re.search(r"\b" + re.escape(lb) + r"\b", line_lower):
                lolbas_found.append({"LOLBAS": lb, "Command": line})
    if lolbas_found:
        traits["LOLBAS"] = lolbas_found

    # Trait 3: Execution of variable content
    start_with_var = []
    for orig, norm in zip(orig_lines, norm_lines):
        if re.match(r"^\s*[%!][a-zA-Z0-9_#@]+[%!]", orig):
            start_with_var.append((orig, norm))
    if start_with_var:
        traits["start_with_var"] = start_with_var

    # Trait 4: Multiple variables on the same line (> 10)
    var_used = []
    for orig, norm in zip(orig_lines, norm_lines):
        count = len(re.findall(r"%[a-zA-Z0-9_#@]+%|![a-zA-Z0-9_#@]+!", orig))
        if count > 10:
            var_used.append((orig, norm, count))
    if var_used:
        traits["var_used"] = var_used

    # Trait 5: External file download
    downloads = []
    ct = meta.get("cradlecrafter_telemetry", {})
    if ct.get("extracted_urls"):
        for url in ct["extracted_urls"]:
            dst = (ct.get("extracted_destinations") or ["unknown"])[0]
            downloads.append((f"powershell download {url}", {"src": url, "dst": dst}))

    url_pattern = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
    for line in norm_lines:
        urls = url_pattern.findall(line)
        for u in urls:
            dst = ""
            dst_m = re.search(r"-o\s+([^\s]+)|-OutFile\s+([^\s]+)|>([^\s]+)", line, re.IGNORECASE)
            if dst_m:
                dst = dst_m.group(1) or dst_m.group(2) or dst_m.group(3) or ""
            if not any(d[1]["src"] == u for d in downloads):
                downloads.append((line, {"src": u, "dst": dst}))
    if downloads:
        traits["download"] = downloads

    # Trait 7: Windows Utility Manipulation
    util_manipulation = []
    for line in norm_lines:
        if re.search(r"\b(copy|move|ren|rename|xcopy)\b.*(cmd\.exe|powershell\.exe|certutil\.exe)", line, re.I):
            parts = re.split(r"\s+", line.strip())
            src = parts[1] if len(parts) > 1 else "unknown"
            dst = parts[-1] if len(parts) > 2 else "unknown"
            util_manipulation.append((line, {"src": src, "dst": dst}))
    if util_manipulation:
        traits["windows-util-manipulation"] = util_manipulation

    # Trait 8: File creation using set /p
    setp_redirects = []
    for line in norm_lines:
        m = re.search(r"set\s+/p.*?>(?:>)?\s*([^\s<|&]+)", line, re.I)
        if not m:
            m = re.search(r"set\s+/p\s+[^=]+=\s*<\s*([^\s>&|]+)", line, re.I)
        if m:
            target_fn = m.group(1).strip("\"' \t")
            setp_redirects.append((line, target_fn))
    if setp_redirects:
        traits["setp-file-redirection"] = setp_redirects

    # Trait 9: Execution of manipulated content
    if util_manipulation or setp_redirects:
        created_files = {ntpath.basename(u[1]["dst"]).lower() for u in util_manipulation}
        created_files.update({ntpath.basename(s[1]).lower() for s in setp_redirects})
        manip_exec = []
        for line in norm_lines:
            for cf in created_files:
                if cf and re.search(r"\b" + re.escape(cf) + r"\b", line.lower()):
                    manip_exec.append((line, cf))
        if manip_exec:
            traits["manipulated-content-execution"] = manip_exec

    # Trait 10: Rundll32 execution
    rundll_exec = []
    for line in norm_lines:
        if "rundll32" in line.lower():
            urls = url_pattern.findall(line)
            rundll_struct = {"url": urls[0]} if urls else {}
            rundll_exec.append((line, rundll_struct))
    if rundll_exec:
        traits["rundll32-execution"] = rundll_exec

    # mshta trait
    mshta_cmds = [line for line in norm_lines if "mshta" in line.lower()]
    if mshta_cmds:
        traits["mshta"] = mshta_cmds

    # net-use trait
    net_uses = []
    for line in norm_lines:
        if re.search(r"\bnet\s+use\b", line, re.I):
            struct = {"Command": line}
            m_srv = re.search(r"\\\\[a-zA-Z0-9_\.\-]+(?:\\[^\s]+)?", line)
            if m_srv:
                struct["server"] = m_srv.group(0)
            m_pass = re.search(r"/user:\S+\s+(\S+)", line, re.I)
            if m_pass:
                struct["password"] = m_pass.group(1)
            net_uses.append((line, struct))
    if net_uses:
        traits["net-use"] = net_uses

    return traits


class AssemblylineBridge:
    """
    CCCS Assemblyline 4 Service Interoperability Bridge.
    Converts batch deobfuscation outputs into structured Assemblyline Results.
    """

    def __init__(self, complex_one_liner_threshold: int = 4, classification: str = "TLP:C"):
        self.complex_one_liner_threshold = complex_one_liner_threshold
        self.classification = classification

    def generate_service_result(
        self,
        script_text: str,
        deobfuscated_text: str,
        meta: Dict[str, Any],
        file_path: Optional[str] = None,
        working_dir: Optional[str] = None,
    ) -> AssemblylineResult:
        """Construct a complete AssemblylineResult object matching CCCS specifications."""
        result = AssemblylineResult(classification=self.classification)
        traits = extract_batch_traits(script_text, deobfuscated_text, meta, self.complex_one_liner_threshold)

        # 1. Register root deobfuscated batch file
        clean_bytes = deobfuscated_text.encode("utf-8")
        clean_sha256 = hashlib.sha256(clean_bytes).hexdigest()
        root_name = f"{clean_sha256[:10]}_deobfuscated.bat"
        orig_sha = hashlib.sha256(script_text.encode("utf-8")).hexdigest()

        if clean_sha256 != orig_sha:
            result.add_extracted_file(
                AssemblylineExtractedFile(
                    name=root_name,
                    sha256=clean_sha256,
                    description="Root deobfuscated batch file",
                    content=clean_bytes,
                )
            )

        # 2. Extract secondary stagers from specialized engine telemetry
        self._extract_secondary_artifacts(result, meta)

        # 3. Populate CCCS Sections
        if "command-grouping" in traits:
            heur = AssemblylineHeuristic(1)
            sec = AssemblylineSection(heur.name, heuristic=heur, body_format="TABLE")
            for item in traits["command-grouping"]:
                c_k, c_v = truncate_command("Command", item["Command"])
                n_k, n_v = truncate_command("Normalized", item["Normalized"])
                sec.add_row({c_k: c_v, n_k: n_v})
            sec.set_column_order(["Command [trunc]", "Normalized [trunc]"])
            result.add_section(sec)

        if "LOLBAS" in traits:
            heur = AssemblylineHeuristic(2)
            if "complex-one-liner" in traits:
                heur.add_signature_id("complex_one_liner", score=400)
            sec = AssemblylineSection(heur.name, heuristic=heur, body_format="TABLE")
            for item in traits["LOLBAS"]:
                c_k, c_v = truncate_command("Command", item["Command"])
                sec.add_row({"LOLBAS": item["LOLBAS"], c_k: c_v})
                sec.add_tag("dynamic.process.command_line", item["Command"])
            result.add_section(sec)

        if "start_with_var" in traits:
            heur = AssemblylineHeuristic(3)
            sec = AssemblylineSection(heur.name, heuristic=heur, body_format="TABLE")
            for cmd, norm in traits["start_with_var"]:
                c_k, c_v = truncate_command("Command", cmd)
                n_k, n_v = truncate_command("Normalized", norm)
                sec.add_row({c_k: c_v, n_k: n_v})
            result.add_section(sec)

        if "var_used" in traits:
            heur = AssemblylineHeuristic(4)
            sec = AssemblylineSection(heur.name, heuristic=heur, body_format="TABLE")
            for cmd, norm, count in traits["var_used"]:
                c_k, c_v = truncate_command("Command", cmd)
                n_k, n_v = truncate_command("Normalized", norm)
                sec.add_row({"Count": count, c_k: c_v, n_k: n_v})
            result.add_section(sec)

        if "download" in traits:
            heur = AssemblylineHeuristic(5)
            if "complex-one-liner" in traits:
                heur.add_signature_id("complex_one_liner", score=400)
            sec = AssemblylineSection("External file download in batch script", heuristic=heur, body_format="TABLE")

            for cmd, trait in traits["download"]:
                sec.add_tag("dynamic.process.command_line", cmd)
                c_k, c_v = truncate_command("Command", cmd)
                sec.add_row({"URL": trait["src"], "Destination": trait["dst"], c_k: c_v})

                src_uri = trait["src"]
                if not src_uri.startswith("$"):
                    if "://" not in src_uri[:8]:
                        src_uri = f"http://{src_uri}"

                    parsed = urlparse(src_uri)
                    host = parsed.hostname or ""
                    sec.add_tag("network.static.uri", src_uri)
                    if re.match(IP_REGEX, host):
                        sec.add_tag("network.static.ip", host)
                    elif re.match(DOMAIN_REGEX, host):
                        sec.add_tag("network.static.domain", host)

                    sub_sec = AssemblylineSection(src_uri, heuristic=AssemblylineHeuristic(5), auto_collapse=True)
                    dst_lower = (trait.get("dst") or "").lower()

                    if "appdata\\local\\temp" in dst_lower or "%temp%" in dst_lower:
                        sub_sec.add_tag("file.path", trait["dst"])
                        sub_sec.heuristic.add_signature_id("downloads_file_to_temp", 250)
                    elif "programdata" in dst_lower or "%programdata%" in dst_lower:
                        sub_sec.add_tag("file.path", trait["dst"])
                        sub_sec.heuristic.add_signature_id("downloads_file_to_programdata", 250)

                    if sub_sec.heuristic.signatures:
                        sec.add_subsection(sub_sec)

            result.add_section(sec)

        if "complex-one-liner" in traits:
            heur = AssemblylineHeuristic(6)
            sec = AssemblylineSection(
                heur.name,
                body={"Number of line after deobfuscation": traits["complex-one-liner"]},
                body_format="KEY_VALUE",
                heuristic=heur,
            )
            result.add_section(sec)

        if "windows-util-manipulation" in traits:
            heur = AssemblylineHeuristic(7)
            sec = AssemblylineSection(heur.name, heuristic=heur, body_format="TABLE")
            for cmd, copy_trait in traits["windows-util-manipulation"]:
                sec.add_tag("dynamic.process.command_line", cmd)
                c_k, c_v = truncate_command("Command", cmd)
                sec.add_row({"Source": copy_trait["src"], "Destination": copy_trait["dst"], c_k: c_v})
            result.add_section(sec)

        if "setp-file-redirection" in traits:
            heur = AssemblylineHeuristic(8)
            sec = AssemblylineSection(heur.name, heuristic=heur, body_format="TABLE")
            for cmd, filename in traits["setp-file-redirection"]:
                c_k, c_v = truncate_command("Command", cmd)
                sec.add_row({"Filename": filename, c_k: c_v})
                sec.add_tag("file.path", filename)
            result.add_section(sec)

        if "manipulated-content-execution" in traits:
            heur = AssemblylineHeuristic(9)
            sec = AssemblylineSection(heur.name, heuristic=heur, body_format="TABLE")
            for cmd, executed_file in traits["manipulated-content-execution"]:
                c_k, c_v = truncate_command("Command", cmd)
                sec.add_row({"Filename": executed_file, c_k: c_v})
            result.add_section(sec)

        if "rundll32-execution" in traits:
            heur = AssemblylineHeuristic(10)
            sec = AssemblylineSection(heur.name, heuristic=heur, body_format="TABLE")
            for cmd, r_struct in traits["rundll32-execution"]:
                sec.add_tag("dynamic.process.command_line", cmd)
                c_k, c_v = truncate_command("Command", cmd)
                sec.add_row({c_k: c_v})
                if r_struct.get("url"):
                    heur.add_signature_id("internet_download", 500)
                    sec.add_tag("network.static.uri", r_struct["url"])
            result.add_section(sec)

        if "mshta" in traits:
            sec = AssemblylineSection("Mshta command found", body_format="TABLE")
            for cmd in traits["mshta"]:
                sec.add_tag("dynamic.process.command_line", cmd)
                c_k, c_v = truncate_command("Command", cmd)
                sec.add_row({c_k: c_v})
            result.add_section(sec)

        if "net-use" in traits:
            sec = AssemblylineSection("Net Use found", body_format="TABLE")
            if "complex-one-liner" in traits:
                h = AssemblylineHeuristic(6)
                h.add_signature_id("net-use", score=100)
                sec.heuristic = h
            for cmd, net_struct in traits["net-use"]:
                if "server" in net_struct:
                    sec.add_tag("network.static.uri", net_struct["server"])
                if "password" in net_struct:
                    sec.add_tag("info.password", net_struct["password"])
                c_k, c_v = truncate_command("Command", cmd)
                row_data = dict(net_struct)
                row_data.pop("Command", None)
                row_data[c_k] = c_v
                sec.add_row(row_data)
            result.add_section(sec)

        # 4. Specialized Engine Forensics Section
        self._attach_specialized_engine_section(result, meta)

        return result

    def _extract_secondary_artifacts(self, result: AssemblylineResult, meta: Dict[str, Any]) -> None:
        """Discover and record decoded PowerShell, Certutil payloads, and polyglots."""
        c_meta = meta.get("cradlecrafter_telemetry", {})
        if c_meta.get("decoded_payloads_count", 0) > 0 and c_meta.get("decoded_payloads"):
            for idx, p in enumerate(c_meta["decoded_payloads"]):
                b_content = CUSTOM_PS1_ID + p.encode("utf-8")
                h = hashlib.sha256(b_content).hexdigest()
                result.add_extracted_file(
                    AssemblylineExtractedFile(
                        name=f"ps1_stager_{idx}_{h[:8]}.ps1",
                        sha256=h,
                        description="Discovered PowerShell code",
                        content=b_content,
                    )
                )

        bpe = meta.get("batchtoapp_pe", {})
        if bpe.get("extracted_script"):
            b_content = CUSTOM_BATCH_ID + bpe["extracted_script"].encode("utf-8")
            h = hashlib.sha256(b_content).hexdigest()
            result.add_extracted_file(
                AssemblylineExtractedFile(
                    name=f"embedded_batchtoapp_{h[:8]}.bat",
                    sha256=h,
                    description="Embedded BatchToApp PE payload",
                    content=b_content,
                )
            )

    def _attach_specialized_engine_section(self, result: AssemblylineResult, meta: Dict[str, Any]) -> None:
        """Summarize multi-engine forensic detections in an Assemblyline section."""
        engine_rows = []

        checks = [
            ("batcloak_telemetry", "BatCloak", "T1027"),
            ("somalifuscator_telemetry", "Somalifuscator", "T1027"),
            ("oxidizer_telemetry", "0xidiz3r", "T1027"),
            ("abobus_telemetry", "Abobus", "T1027"),
            ("dosfuscation_telemetry", "Invoke-DOSfuscation", "T1027"),
            ("cradlecrafter_telemetry", "Invoke-CradleCrafter", "T1059.001"),
            ("bedecode_telemetry", "BEDeCode", "T1027"),
            ("batchshield_telemetry", "BatchShield", "T1027"),
            ("pandacrypter_telemetry", "PandaCrypter", "T1140"),
            ("exorcism_telemetry", "Exorcism", "T1027"),
            ("batchtoapp_telemetry", "BatchToApp", "T1027"),
            ("machine1337_telemetry", "machine1337", "T1027"),
            ("cmd_deobfuscator_telemetry", "CMD-DeObfuscator", "T1027"),
            ("simple_obfuscator_telemetry", "simple-batch-obfuscator", "T1027"),
            ("jsbatch_telemetry", "JSBatch", "T1027"),
            ("batchstealer_telemetry", "BatchStealer", "T1555.003"),
            ("wirebits_telemetry", "WireBits", "T1027"),
        ]

        for meta_key, name, att_id in checks:
            t = meta.get(meta_key, {})
            is_detected = (
                t.get("detected")
                or t.get("is_" + name.lower().replace("-", "_"))
                or (t.get("signatures") and t["signatures"].get("confidence", 0) > 0.3)
            )
            if is_detected:
                conf = t.get("confidence") or (t.get("signatures", {}).get("confidence", 0.0))
                engine_rows.append({
                    "Engine": name,
                    "Confidence": round(float(conf), 2),
                    "ATT&CK Technique": att_id,
                })

        if engine_rows:
            heur = AssemblylineHeuristic(1, name="Specialized Batch Obfuscation Engines Detected", score=100)
            heur.attack_ids = list({r["ATT&CK Technique"] for r in engine_rows})
            sec = AssemblylineSection(
                "Specialized Batch Obfuscator Engine Detections",
                body=engine_rows,
                body_format="TABLE",
                heuristic=heur,
            )
            for r in engine_rows:
                sec.add_tag("technique.obfuscation", r["Engine"])
            result.add_section(sec)


def generate_assemblyline_report(
    script_text: str,
    deobfuscated_text: str,
    meta: Dict[str, Any],
    file_path: Optional[str] = None,
    working_dir: Optional[str] = None,
    classification: str = "TLP:C",
) -> Dict[str, Any]:
    """Functional convenience helper to generate standard Assemblyline JSON report dictionary."""
    bridge = AssemblylineBridge(classification=classification)
    res = bridge.generate_service_result(
        script_text=script_text,
        deobfuscated_text=deobfuscated_text,
        meta=meta,
        file_path=file_path,
        working_dir=working_dir,
    )
    return res.to_dict()


def export_assemblyline_result(
    output_path: Union[str, Path],
    script_text: str,
    deobfuscated_text: str,
    meta: Dict[str, Any],
    file_path: Optional[str] = None,
    classification: str = "TLP:C",
) -> Path:
    """Export CCCS Assemblyline result to file on disk and return destination Path."""
    bridge = AssemblylineBridge(classification=classification)
    res = bridge.generate_service_result(
        script_text=script_text,
        deobfuscated_text=deobfuscated_text,
        meta=meta,
        file_path=file_path,
    )
    return res.save(output_path)
