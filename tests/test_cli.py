"""
Automated Test Suite for batch-deobfuscator CLI Toolchain.
Validates CLI flags, output formats, JSON telemetry, and diff generation.
"""

import unittest
import subprocess
import sys
import os
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

class TestBatchDeobfuscatorCLI(unittest.TestCase):
    def setUp(self):
        self.samples_dir = REPO_ROOT / "samples"
        self.sample1 = self.samples_dir / "01_env_slicing_sample.bat"
        self.sample2 = self.samples_dir / "02_caret_and_delimiters_sample.bat"
        self.sample3 = self.samples_dir / "03_dynamic_substitution_table_sample.bat"
        self.temp_out = REPO_ROOT / "tests" / "temp_clean_output.bat"

    def tearDown(self):
        if self.temp_out.exists():
            self.temp_out.unlink()

    def run_cli(self, args):
        cmd = [sys.executable, "-m", "deobfuscator"] + args
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT)
        env["PYTHONIOENCODING"] = "utf-8"
        return subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="replace",
            env=env
        )

    def test_cli_version(self):
        res = self.run_cli(["--version"])
        self.assertEqual(res.returncode, 0)
        from deobfuscator import __version__
        self.assertIn(f"batch-deobfuscator {__version__}", res.stdout)

    def test_cli_help(self):
        res = self.run_cli(["--help"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("batch-deobfuscator", res.stdout)
        self.assertIn("--passes", res.stdout)
        self.assertIn("--diff", res.stdout)
        self.assertIn("--format", res.stdout)

    def test_cli_stdout_deobfuscation(self):
        res = self.run_cli([str(self.sample1)])
        self.assertEqual(res.returncode, 0)
        self.assertIn("cmd /c whoami", res.stdout)
        self.assertNotIn("%_cmd%", res.stdout)

    def test_cli_output_file(self):
        res = self.run_cli([str(self.sample2), "-o", str(self.temp_out)])
        self.assertEqual(res.returncode, 0)
        self.assertTrue(self.temp_out.exists())
        content = self.temp_out.read_text(encoding="utf-8")
        self.assertIn("cmd /c whoami", content)
        self.assertNotIn("w^h^o^a^m^i", content)

    def test_cli_diff_mode(self):
        res = self.run_cli([str(self.sample2), "--diff", "--no-color"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("--- a/02_caret_and_delimiters_sample.bat (obfuscated)", res.stdout)
        self.assertIn("+++ b/02_caret_and_delimiters_sample.bat (deobfuscated)", res.stdout)

    def test_cli_json_mode(self):
        res = self.run_cli([str(self.sample3), "--format", "json"])
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertIn("meta", data)
        self.assertIn("deobfuscated_script", data)
        self.assertTrue(data["meta"]["converged"])
        self.assertGreaterEqual(data["meta"]["passes_executed"], 1)
        self.assertIn("cmd /c whomai", data["deobfuscated_script"])

    def test_cli_no_abobus_flag(self):
        res = self.run_cli(["--help"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("--no-abobus", res.stdout)

    def test_cli_no_cradlecrafter_flag(self):
        res = self.run_cli(["--help"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("--no-cradlecrafter", res.stdout)

    def test_cli_no_batchtoapp_flag(self):
        res = self.run_cli(["--help"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("--no-batchtoapp", res.stdout)

    def test_cli_batchtoapp_script_sample(self):
        sample7 = self.samples_dir / "07_batchtoapp_dosx_sample.bat"
        if not sample7.exists():
            self.skipTest("sample7 not found")
        res = self.run_cli([str(sample7), "--format", "json"])
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertIn("meta", data)
        self.assertIn("cmd /c whoami", data["deobfuscated_script"])
        b2at = data["meta"].get("batchtoapp_telemetry", {})
        self.assertTrue(b2at.get("detected") or b2at.get("is_batchtoapp"))

    def test_cli_batchtoapp_pe_forensics(self):
        import zlib
        from tests.test_batchtoapp import create_minimal_pe
        payload = b"@shift /0\r\necho CLI PE Extraction Test\r\n:b2a_ExitProcess"
        compressor = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
        comp = compressor.compress(payload) + compressor.flush()
        pe_bytes = create_minimal_pe(comp, app_id="feedbeef")
        temp_pe = REPO_ROOT / "tests" / "temp_cli_test.exe"
        try:
            temp_pe.write_bytes(pe_bytes)
            res = self.run_cli([str(temp_pe), "--format", "json", "-v"])
            self.assertEqual(res.returncode, 0)
            data = json.loads(res.stdout)
            self.assertIn("echo CLI PE Extraction Test", data["deobfuscated_script"])
            self.assertIn("batchtoapp_pe", data["meta"])
            self.assertEqual(data["meta"]["batchtoapp_pe"]["app_id"], "feedbeef")
            self.assertIn("BatchToApp PE Wrapper Forensics", res.stderr)
        finally:
            if temp_pe.exists():
                temp_pe.unlink()

    def test_cli_web_flag_help(self):
        res = self.run_cli(["--help"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("--web", res.stdout)
        self.assertIn("--dashboard", res.stdout)
        self.assertIn("--port", res.stdout)

    def test_cli_no_args_error(self):
        res = self.run_cli([])
        self.assertEqual(res.returncode, 2)
        self.assertIn("required: input", res.stderr)


if __name__ == "__main__":
    unittest.main()
