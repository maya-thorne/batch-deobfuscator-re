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
        self.assertIn("batch-deobfuscator 1.0.0", res.stdout)

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

if __name__ == "__main__":
    unittest.main()
