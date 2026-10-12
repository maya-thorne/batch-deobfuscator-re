#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit Test Suite for 28-Corpus Benchmark Evaluation Harness & Metrics.
Validates corpus loading, metrics calculations, programmatic execution,
CLI options (--format, --output, --min-score, --verbose), and normalizers.
"""

import sys
import unittest
import subprocess
import json
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmarks.corpus_data import (
    CORPUS_SUITE,
    BenchmarkCorpus,
    get_corpus_suite,
    get_corpus_by_id,
    get_corpus_by_name,
)
from benchmarks.metrics import (
    calculate_shannon_entropy,
    calculate_size_compression_ratio,
    calculate_caret_stripping_ratio,
    calculate_symbol_resolution_density,
    calculate_convergence_speed,
    calculate_readability_clarity_index,
    calculate_composite_score,
    calculate_all_metrics,
)
from benchmarks.eval_corpus_runner import (
    CorpusBenchmarkRunner,
    BenchmarkResult,
    run_corpus_benchmark,
    format_text_table,
    format_markdown_table,
)
from deobfuscator.normalizers import (
    strip_carets,
    strip_empty_quotes,
    split_chained_commands,
    strip_undefined_vars,
    resolve_slicing,
    resolve_substitution,
)
from deobfuscator.core import BatchDeobfuscator


class TestBenchmarkCorpusData(unittest.TestCase):
    """Test suite for benchmarks/corpus_data.py."""

    def test_corpus_suite_count(self):
        """Verify the suite contains exactly 28 distinct corpora."""
        self.assertEqual(len(CORPUS_SUITE), 28)

    def test_corpus_unique_ids(self):
        """Verify all corpus IDs are unique and numbered 1 through 28."""
        ids = [c.corpus_id for c in CORPUS_SUITE]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(sorted(ids), list(range(1, 29)))

    def test_corpus_metadata_fields(self):
        """Verify each corpus has all required metadata fields populated."""
        valid_difficulties = {"Easy", "Medium", "Hard", "Advanced"}
        for c in CORPUS_SUITE:
            self.assertTrue(c.name, "Corpus must have a name")
            self.assertTrue(c.archetype, f"Corpus {c.name} must have an archetype")
            self.assertTrue(c.script, f"Corpus {c.name} must have a script")
            self.assertTrue(c.ground_truth, f"Corpus {c.name} must have a ground truth")
            self.assertIsInstance(c.expected_tokens, list)
            self.assertGreater(len(c.expected_tokens), 0, f"Corpus {c.name} must have expected tokens")
            self.assertIn(c.difficulty, valid_difficulties, f"Invalid difficulty {c.difficulty} in {c.name}")
            self.assertIsInstance(c.detection_tags, list)
            self.assertGreater(len(c.detection_tags), 0, f"Corpus {c.name} must have detection tags")
            self.assertTrue(c.description, f"Corpus {c.name} must have a description")

    def test_get_corpus_helpers(self):
        """Verify get_corpus_by_id and get_corpus_by_name lookups."""
        c1 = get_corpus_by_id(1)
        self.assertIsNotNone(c1)
        self.assertEqual(c1.name, "BatCloak")

        self.assertIsNone(get_corpus_by_id(999))

        c_name = get_corpus_by_name("BatCloak")
        self.assertIsNotNone(c_name)
        self.assertEqual(c_name.corpus_id, 1)

        c_sub = get_corpus_by_name("somalifuscator")
        self.assertIsNotNone(c_sub)
        self.assertEqual(c_sub.name, "Somalifuscator")

        self.assertIsNone(get_corpus_by_name("non_existent_xyz"))

    def test_corpus_to_dict(self):
        """Verify serialization to dictionary."""
        c = get_corpus_by_id(1)
        d = c.to_dict()
        self.assertEqual(d["corpus_id"], 1)
        self.assertEqual(d["name"], "BatCloak")
        self.assertIn("archetype", d)
        self.assertIn("detection_tags", d)


class TestBenchmarkMetrics(unittest.TestCase):
    """Test suite for benchmarks/metrics.py."""

    def test_shannon_entropy(self):
        """Verify Shannon entropy calculations."""
        self.assertEqual(calculate_shannon_entropy(""), 0.0)
        self.assertEqual(calculate_shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(calculate_shannon_entropy("ab"), 1.0, places=3)
        self.assertGreater(calculate_shannon_entropy("abcdefghijklmnopqrstuvwxyz0123456789"), 5.0)

    def test_size_compression_ratio(self):
        """Verify size compression calculation."""
        self.assertEqual(calculate_size_compression_ratio("", ""), 0.0)
        # 100 chars raw, 50 chars clean -> 50% compression
        raw = "a" * 100
        clean = "a" * 50
        self.assertEqual(calculate_size_compression_ratio(raw, clean), 50.0)
        # Expansion
        self.assertEqual(calculate_size_compression_ratio("a", "aaa"), -200.0)

    def test_caret_stripping_ratio(self):
        """Verify caret stripping ratio."""
        # 5 carets in raw, 0 in clean -> 100.0% stripped
        self.assertEqual(calculate_caret_stripping_ratio("w^h^o^a^m^i", "whoami"), 100.0)
        # 4 carets in raw, 2 remaining -> 50.0% stripped
        self.assertEqual(calculate_caret_stripping_ratio("w^h^o^a^m", "w^h^oam"), 50.0)

    def test_symbol_resolution_density(self):
        """Verify symbol density calculation."""
        clean = "line1\nline2\nline3"
        self.assertEqual(calculate_symbol_resolution_density(6, clean), 2.0)
        self.assertEqual(calculate_symbol_resolution_density(0, clean), 0.0)

    def test_convergence_speed(self):
        """Verify convergence speed telemetry profile."""
        res = calculate_convergence_speed(2, 15, 10.0)
        self.assertEqual(res["passes_executed"], 2)
        self.assertEqual(res["speed_score"], 90.0)
        self.assertEqual(res["ms_per_pass"], 5.0)

    def test_readability_clarity_index(self):
        """Verify readability clarity index calculation."""
        self.assertEqual(calculate_readability_clarity_index(""), 0.0)
        clarity = calculate_readability_clarity_index("cmd.exe /c whoami")
        self.assertGreaterEqual(clarity, 70.0)
        self.assertLessEqual(clarity, 100.0)

    def test_composite_score(self):
        """Verify composite score bounds and weighting."""
        perfect = calculate_composite_score(
            token_accuracy=1.0,
            converged=True,
            passes=1,
            max_passes=15,
            clarity_index=100.0,
            compression_ratio=50.0,
        )
        self.assertEqual(perfect, 100.0)

        zero = calculate_composite_score(
            token_accuracy=0.0,
            converged=False,
            passes=15,
            max_passes=15,
            clarity_index=0.0,
            compression_ratio=0.0,
        )
        self.assertEqual(zero, 0.0)

    def test_calculate_all_metrics(self):
        """Verify aggregated telemetry dictionary generation."""
        meta = {
            "passes_executed": 2,
            "converged": True,
            "symbols_resolved_count": 3,
            "elapsed_ms": 1.5,
        }
        res = calculate_all_metrics(
            raw_text="c^m^d /c whoami",
            clean_text="cmd /c whoami",
            meta=meta,
            expected_tokens=["whoami"],
        )
        self.assertIn("entropy_before", res)
        self.assertIn("entropy_after", res)
        self.assertIn("entropy_delta", res)
        self.assertIn("compression_ratio", res)
        self.assertIn("caret_stripping_ratio", res)
        self.assertIn("symbol_density", res)
        self.assertIn("convergence_speed", res)
        self.assertIn("clarity_index", res)
        self.assertIn("composite_score", res)
        self.assertEqual(res["tokens_found"], ["whoami"])
        self.assertEqual(len(res["tokens_missing"]), 0)


class TestBenchmarkRunnerSuite(unittest.TestCase):
    """Test suite for benchmarks/eval_corpus_runner.py programmatic runner."""

    def setUp(self):
        self.runner = CorpusBenchmarkRunner()

    def test_evaluate_single_corpus(self):
        """Verify single corpus evaluation produces valid BenchmarkResult."""
        c = get_corpus_by_id(1)
        res = self.runner.evaluate_single(c)
        self.assertIsInstance(res, BenchmarkResult)
        self.assertEqual(res.status, "PASS")
        self.assertGreaterEqual(res.score, 85.0)
        self.assertTrue(res.meta["converged"])
        d = res.to_dict()
        self.assertEqual(d["id"], 1)
        self.assertEqual(d["name"], "BatCloak")

    def test_full_28_corpus_suite_execution(self):
        """Verify 100% pass rate across all 28 corpora with superior grade."""
        summary = self.runner.run_suite(min_score=80.0)
        self.assertEqual(summary["total_corpora"], 28)
        self.assertEqual(summary["passed"], 28)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["pass_rate_pct"], 100.0)
        self.assertGreaterEqual(summary["mean_score"], 90.0)
        self.assertTrue(summary["verdict_passed"])
        self.assertIn(summary["grade"], ["A+ (Excellent)", "A (Superior)"])

    def test_corpus_filtering_by_id_and_name(self):
        """Verify filtering by ID and name."""
        # By ID
        res_id = self.runner.run_suite(corpus_filter="5")
        self.assertEqual(res_id["total_corpora"], 1)
        self.assertEqual(res_id["results"][0]["id"], 5)
        self.assertEqual(res_id["results"][0]["name"], "Invoke-DOSfuscation")

        # By Name
        res_name = self.runner.run_suite(corpus_filter="Somalifuscator")
        self.assertEqual(res_name["total_corpora"], 1)
        self.assertEqual(res_name["results"][0]["name"], "Somalifuscator")

        # Invalid filter raises ValueError
        with self.assertRaises(ValueError):
            self.runner.run_suite(corpus_filter="invalid_nonexistent_xyz")

    def test_external_directory_loading(self):
        """Verify loading additional corpora from an external directory."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            bat_file = tmp_path / "custom_test.bat"
            bat_file.write_text("c^m^d /c whoami", encoding="utf-8")

            summary = self.runner.run_suite(corpus_dir=tmp_dir)
            self.assertEqual(summary["total_corpora"], 29)
            custom_res = [r for r in summary["results"] if r["name"] == "custom_test"]
            self.assertEqual(len(custom_res), 1)

    def test_report_formatters(self):
        """Verify ASCII and Markdown summary formatting."""
        summary = self.runner.run_suite(corpus_filter="1")
        text_out = format_text_table(summary)
        self.assertIn("BATCH DEOBFUSCATOR 28-CORPUS BENCHMARK EVALUATION HARNESS", text_out)
        self.assertIn("BatCloak", text_out)

        md_out = format_markdown_table(summary)
        self.assertIn("# Batch Deobfuscator 28-Corpus Benchmark Evaluation Report", md_out)
        self.assertIn("| ID | Corpus Name | Archetype |", md_out)
        self.assertIn("BatCloak", md_out)


class TestBenchmarkCLI(unittest.TestCase):
    """Test suite for CLI invocation of eval_corpus_runner.py."""

    def test_cli_format_json(self):
        """Verify CLI --format json produces valid parseable JSON."""
        cmd = [sys.executable, str(REPO_ROOT / "benchmarks" / "eval_corpus_runner.py"), "--format", "json", "--corpus", "1"]
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["total_corpora"], 1)
        self.assertEqual(data["passed"], 1)
        self.assertEqual(data["results"][0]["id"], 1)

    def test_cli_format_markdown(self):
        """Verify CLI --format markdown produces markdown output."""
        cmd = [sys.executable, str(REPO_ROOT / "benchmarks" / "eval_corpus_runner.py"), "--format", "markdown", "--corpus", "1"]
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("# Batch Deobfuscator 28-Corpus Benchmark Evaluation Report", proc.stdout)

    def test_cli_output_file(self):
        """Verify CLI --output writes report to disk."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "out_report.txt"
            cmd = [
                sys.executable,
                str(REPO_ROOT / "benchmarks" / "eval_corpus_runner.py"),
                "--corpus", "1",
                "--output", str(out_file),
            ]
            proc = subprocess.run(cmd, cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
            self.assertEqual(proc.returncode, 0)
            self.assertTrue(out_file.exists())
            content = out_file.read_text(encoding="utf-8")
            self.assertIn("BatCloak", content)

    def test_cli_min_score_regression_trigger(self):
        """Verify CLI exits with code 1 when regression threshold fails."""
        cmd = [
            sys.executable,
            str(REPO_ROOT / "benchmarks" / "eval_corpus_runner.py"),
            "--min-score", "99.9",
        ]
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("REGRESSION DETECTED", proc.stdout)

    def test_cli_verbose_flag(self):
        """Verify CLI --verbose prints snippet info."""
        cmd = [
            sys.executable,
            str(REPO_ROOT / "benchmarks" / "eval_corpus_runner.py"),
            "--corpus", "1",
            "--verbose",
        ]
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("BatCloak -> Found:", proc.stdout)


class TestNormalizerRefinements(unittest.TestCase):
    """Test suite for refined normalizers handling negative slicing, carets, empty quotes."""

    def test_negative_slicing_comspec(self):
        """Verify negative slicing with comspec variable."""
        env = {"comspec": r"C:\Windows\system32\cmd.exe"}
        res = resolve_slicing("%COMSPEC:~-7,3%", env)
        self.assertEqual(res, "cmd")

    def test_negative_slicing_bounds(self):
        """Verify exact cmd.exe semantics for negative offset and negative length."""
        env = {"alphabet": "0123456789"}
        # ~2,-2 extracts from offset 2 up to 2 characters before end -> "234567"
        self.assertEqual(resolve_slicing("%alphabet:~2,-2%", env), "234567")
        # ~-3,3 extracts 3 characters from 3rd char before end -> "789"
        self.assertEqual(resolve_slicing("%alphabet:~-3,3%", env), "789")
        # ~-4,-1 extracts from 4th char before end to 1st char before end -> "678"
        self.assertEqual(resolve_slicing("%alphabet:~-4,-1%", env), "678")

    def test_empty_quote_normalization(self):
        """Verify empty quote pairs normalization."""
        self.assertEqual(strip_empty_quotes('w""h""o""a""m""i'), 'whoami')
        self.assertEqual(strip_empty_quotes('""c""""m""""d""'), 'cmd')
        self.assertEqual(strip_empty_quotes('c""m""d"".e""x""e'), 'cmd.exe')
        # Preserves empty string comparisons
        self.assertEqual(strip_empty_quotes('if "%1"==""'), 'if "%1"==""')

    def test_caret_escape_outside_and_inside_quotes(self):
        """Verify carets stripped outside quotes and preserved inside quotes."""
        self.assertEqual(strip_carets('c^m^d /c whoami'), 'cmd /c whoami')
        self.assertEqual(strip_carets('echo "^"'), 'echo "^"')
        self.assertEqual(strip_carets('^^'), '^')

    def test_split_chained_commands(self):
        """Verify split_chained_commands preserves redirection and caret ampersands."""
        res = split_chained_commands('cmd1 & cmd2 & cmd3')
        self.assertEqual(res.splitlines(), ['cmd1', 'cmd2', 'cmd3'])

        # Redirection 2>&1 preserved
        res_red = split_chained_commands('cmd.exe /c whoami 2>&1 & calc.exe')
        self.assertEqual(res_red.splitlines(), ['cmd.exe /c whoami 2>&1', 'calc.exe'])

        # Quotes preserved
        res_q = split_chained_commands('echo "hello & world" & dir')
        self.assertEqual(res_q.splitlines(), ['echo "hello & world"', 'dir'])

    def test_split_chained_commands_parentheses_and_caret_quotes(self):
        """Adversarial testing: verify parentheses blocks, caret quotes, and redirection boundaries."""
        # 1. Caret immediately preceding closing quote
        res_caret = split_chained_commands('echo "test^" & echo foo')
        self.assertEqual(res_caret.splitlines(), ['echo "test^"', 'echo foo'])

        # 2. Compound if-else with parentheses must not be broken across lines
        if_else = 'if exist foo (del foo & echo deleted) else (echo not found & exit /b)'
        self.assertEqual(split_chained_commands(if_else), if_else)

        # 3. Parenthesized block followed by chained command
        paren_chained = '(set y=2 & set z=3) & echo %y% %z%'
        self.assertEqual(split_chained_commands(paren_chained).splitlines(), ['(set y=2 & set z=3)', 'echo %y% %z%'])

        # 4. For-in construct with ampersand in command string
        for_loop = 'for /f "tokens=*" %a in (\'whoami & id\') do (echo %a & echo %a)'
        self.assertEqual(split_chained_commands(for_loop), for_loop)

        # 5. Adjacent and unusual redirection tokens
        red1 = split_chained_commands('cmd.exe 1>&2 2>&1 & calc.exe')
        self.assertEqual(red1.splitlines(), ['cmd.exe 1>&2 2>&1', 'calc.exe'])

        red2 = split_chained_commands('cmd.exe 2>&1&calc.exe')
        self.assertEqual(red2.splitlines(), ['cmd.exe 2>&1', 'calc.exe'])

        red3 = split_chained_commands('dir /b > output.txt 2>&1 & type output.txt')
        self.assertEqual(red3.splitlines(), ['dir /b > output.txt 2>&1', 'type output.txt'])

    def test_dynamic_windows_pseudo_variables_preserved(self):
        """Verify standard Windows dynamic variables are preserved and not stripped as noise."""
        script = 'if %errorlevel% neq 0 exit /b & echo %cd% & echo %random%'
        engine = BatchDeobfuscator(strip_undefined=True)
        clean, _ = engine.deobfuscate(script)
        self.assertIn('%errorlevel%', clean)
        self.assertIn('%cd%', clean)
        self.assertIn('%random%', clean)

        # strip_undefined_vars directly
        env = {"user": "admin"}
        res = strip_undefined_vars('echo %errorlevel% %NOT_SET% %user%', env)
        self.assertEqual(res, 'echo %errorlevel% %user%')

    def test_symmetric_percent_quote_stripping(self):
        """Verify symmetric double quotes around percent variables and parameters."""
        self.assertEqual(strip_empty_quotes('if ""%1""==""'), 'if %1==""')
        self.assertEqual(strip_empty_quotes('echo ""%var%""'), 'echo %var%')
        self.assertEqual(strip_empty_quotes('if "%1"==""'), 'if "%1"==""')
        self.assertEqual(strip_empty_quotes('w""h""o""%dummy%""a""m""i'), 'who%dummy%ami')

    def test_parenthesized_set_extraction(self):
        """Verify BatchDeobfuscator extracts multiple set statements inside parenthesized blocks."""
        script = '(set y=2 & set z=3) & echo %y% %z%'
        engine = BatchDeobfuscator()
        clean, meta = engine.deobfuscate(script)
        self.assertIn('echo 2 3', clean)
        self.assertEqual(meta['symbol_table'].get('y'), '2')
        self.assertEqual(meta['symbol_table'].get('z'), '3')

    def test_cli_json_alias_flag(self):
        """Verify --json CLI flag executes successfully as documented in README/CHANGELOG."""
        import io
        import contextlib
        import benchmarks.eval_corpus_runner as runner
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ret = runner.main(['--json', '--corpus', '1'])
        self.assertEqual(ret, 0)
        self.assertIn('"verdict_passed": true', buf.getvalue())

    def test_split_chained_commands_preserves_comments_and_labels(self):
        """Verify cmd.exe comment lines (rem, ::) and labels are preserved and not split at ampersands."""
        # In cmd.exe, REM/:: comments treat the rest of the line as comment text; ampersands must not be split
        self.assertEqual(split_chained_commands('rem this is a test & whoami'), 'rem this is a test & whoami')
        self.assertEqual(split_chained_commands('@rem comment line & echo payload'), '@rem comment line & echo payload')
        self.assertEqual(split_chained_commands(':: label comment & calc.exe'), ':: label comment & calc.exe')
        self.assertEqual(split_chained_commands(':my_label & dir'), ':my_label & dir')

    def test_value_quoted_and_caret_ampersand_set_extraction(self):
        """Verify variable extraction handles value-quoted strings, caret-escaped ampersands, and switches."""
        # 1. Value-quoted syntax: set var="hello"
        script1 = 'set var="hello"\necho %var%'
        engine1 = BatchDeobfuscator()
        clean1, meta1 = engine1.deobfuscate(script1)
        self.assertEqual(meta1['symbol_table'].get('var'), '"hello"')
        self.assertIn('echo "hello"', clean1)

        # 2. Caret-escaped ampersand in set value: set x=foo^&bar & set y=1
        script2 = 'set x=foo^&bar & set y=1\necho %x% %y%'
        engine2 = BatchDeobfuscator()
        clean2, meta2 = engine2.deobfuscate(script2)
        self.assertIn('echo foo&bar 1', clean2)
        self.assertEqual(meta2['symbol_table'].get('y'), '1')

        # 3. Compact set switch: set/a count=10
        script3 = '@set/a count=10 & echo %count%'
        engine3 = BatchDeobfuscator()
        clean3, meta3 = engine3.deobfuscate(script3)
        self.assertEqual(meta3['symbol_table'].get('count'), '10')

    def test_quote_aware_space_collapsing(self):
        """Verify whitespace inside double quotes is strictly preserved while undefined noise spaces are collapsed."""
        script = 'echo "hello    world" & %UNDEFINED% %DUMMY% calc.exe'
        engine = BatchDeobfuscator(strip_undefined=True)
        clean, _ = engine.deobfuscate(script)
        lines = clean.splitlines()
        self.assertEqual(lines[0], 'echo "hello    world"')
        self.assertEqual(lines[1], 'calc.exe')

    def test_internal_dynamic_variables_appdir_and_cd(self):
        """Verify Windows internal dynamic pseudo-variables __appdir__ and __cd__ are preserved and resolved."""
        # 1. Expanded via DEFAULT_ENV
        script = 'set mydir=%__appdir__% & echo %__cd__%'
        engine = BatchDeobfuscator(strip_undefined=True)
        clean, meta = engine.deobfuscate(script)
        self.assertIn('C:\\Windows\\system32\\', clean)

        # 2. Preserved against undefined stripping when env does not define them
        res = strip_undefined_vars('echo %__cd__% %NOT_A_VAR% %__appdir__%', {})
        self.assertEqual(res, 'echo %__cd__% %__appdir__%')

    def test_src_standalone_engine_parity(self):
        """Verify src/deobfuscator_engine.py is fully synchronized with deobfuscator core."""
        from src.deobfuscator_engine import BatchDeobfuscator as StandaloneEngine
        se = StandaloneEngine()

        # Substitution resolution
        sub_res = se.deobfuscate('set v=powershell\n%v:powershell=cmd% /c whoami')
        self.assertIn('cmd /c whoami', sub_res)

        # Value-quoted set
        vq_res = se.deobfuscate('set var="hello"\necho %var%')
        self.assertIn('echo "hello"', vq_res)

        # Comment preservation
        rem_res = se.deobfuscate('rem test comment & calc.exe')
        self.assertEqual(rem_res, 'rem test comment & calc.exe')

    def test_chained_rem_and_label_comment_preservation(self):
        """Verify comments and labels following ampersands (&) consume the rest of the line without splitting further."""
        # In cmd.exe, once REM, ::, or :label is reached, all subsequent ampersands are part of the comment/label
        s1 = '@echo off & rem comment with & whoami & calc.exe'
        res1 = split_chained_commands(s1)
        self.assertEqual(res1.splitlines(), ['@echo off', 'rem comment with & whoami & calc.exe'])

        s2 = 'echo 1 & :: my note & calc.exe'
        res2 = split_chained_commands(s2)
        self.assertEqual(res2.splitlines(), ['echo 1', ':: my note & calc.exe'])

        s3 = 'dir & :my_label & whoami'
        res3 = split_chained_commands(s3)
        self.assertEqual(res3.splitlines(), ['dir', ':my_label & whoami'])

    def test_unquoted_ampersand_set_extraction_terminates_at_ampersand(self):
        """Verify unquoted unescaped ampersand terminates variable value assignment rather than capturing commands."""
        # 1. set x=1 & echo %x% must set x to 1, not '1 & echo %x%'
        b = BatchDeobfuscator(split_chains=False)
        b.extract_and_set_vars('set x=1 & echo %x%')
        self.assertEqual(b.env_vars.get('x'), '1')

        # 2. Caret-escaped ampersand still preserves escaped ampersand
        b2 = BatchDeobfuscator(split_chains=False)
        b2.extract_and_set_vars('set x=foo^&bar & dir')
        self.assertEqual(b2.env_vars.get('x'), 'foo&bar')

    def test_substitution_with_windows_path_backslashes(self):
        """Verify variable substitution handles replacement strings containing Windows paths with backslashes."""
        from src.deobfuscator_engine import BatchDeobfuscator as StandaloneEngine
        env = {"v": "replace_me"}
        # Both normalizers and standalone engine must safely handle backslashes without re.PatternError
        r1 = resolve_substitution(r"%v:replace_me=C:\Windows\system32%", env)
        self.assertEqual(r1, r"C:\Windows\system32")

        se = StandaloneEngine()
        se.env_vars["v"] = "replace_me"
        r2 = se.resolve_substitution(r"%v:replace_me=C:\Windows\system32%")
        self.assertEqual(r2, r"C:\Windows\system32")

    def test_wildcard_substitution_parity(self):
        """Verify wildcard string replacement %VAR:*old=new% functions identically in core and standalone engine."""
        from src.deobfuscator_engine import BatchDeobfuscator as StandaloneEngine
        env = {"mypath": r"C:\Windows\system32;C:\Users\test"}
        # Replaces everything up to and including 'system32' with 'D:\bin'
        r1 = resolve_substitution(r"%mypath:*system32=D:\bin%", env)
        self.assertEqual(r1, r"D:\bin;C:\Users\test")

        se = StandaloneEngine()
        se.env_vars["mypath"] = r"C:\Windows\system32;C:\Users\test"
        r2 = se.resolve_substitution(r"%mypath:*system32=D:\bin%")
        self.assertEqual(r2, r"D:\bin;C:\Users\test")


if __name__ == "__main__":
    unittest.main()
