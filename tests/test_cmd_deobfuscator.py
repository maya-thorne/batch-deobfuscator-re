"""
Unit and Integration Tests for CMD-DeObfuscator Module.
Covers chained variable dependency graphs, topological solver, cycle guards,
delayed expansion, quote widening, nested cmd flattening, delimiter normalization,
signature detection, memory zeroization, and full deobfuscator pipeline integration.
"""

import unittest
from deobfuscator.cmd_deobfuscator import (
    strip_empty_quote_pairs,
    widen_token_quotes,
    flatten_nested_cmd,
    normalize_delimiters_outside_quotes,
    eval_batch_slice,
    eval_batch_subst,
    eval_delayed_expansion,
    build_variable_dependency_graph,
    resolve_chained_environment_variables,
    detect_cmd_deobfuscator_signatures,
    CMDDeobfuscatorNormalizer,
    normalize_cmd_deobfuscator,
    zeroize_dict,
    zeroize_bytes,
)
from deobfuscator.core import BatchDeobfuscator, deobfuscate_script, deobfuscate_bytes


class TestCMDDeobfuscator(unittest.TestCase):
    """Test suite for CMD-DeObfuscator engine."""

    def test_strip_empty_quote_pairs(self):
        # Word-internal empty quote pairs
        res, count = strip_empty_quote_pairs('pow""ersh""ell')
        self.assertEqual(res, "powershell")
        self.assertEqual(count, 2)

        res2, count2 = strip_empty_quote_pairs('c""m""d.exe /c c""al""c')
        self.assertEqual(res2, "cmd.exe /c calc")
        self.assertEqual(count2, 4)

        # Standalone empty quotes preserved
        res3, count3 = strip_empty_quote_pairs('cmd /c ""')
        self.assertEqual(res3, 'cmd /c ""')
        self.assertEqual(count3, 0)

    def test_widen_token_quotes(self):
        # Fragmented internal quotes widened to clean wrapping quotes
        res, c = widen_token_quotes('w"s"c"r"i"p"t')
        self.assertEqual(res, '"wscript"')
        self.assertEqual(c, 1)

        res, c = widen_token_quotes('h"t"t"p"')
        self.assertEqual(res, '"http"')
        self.assertEqual(c, 1)

        res, c = widen_token_quotes('c"al"c.exe')
        self.assertEqual(res, '"calc.exe"')
        self.assertEqual(c, 1)

        # Existing cleanly quoted strings remain intact
        clean_line = 'echo "hello world" "C:\\Program Files\\App"'
        res, c = widen_token_quotes(clean_line)
        self.assertEqual(res, clean_line)
        self.assertEqual(c, 0)

        # Line with mixed tokens
        line = 'cmd.exe /c "w"s"c"r"i"p"t //nologo'
        res, c = widen_token_quotes(line)
        self.assertEqual(res, 'cmd.exe /c "wscript" //nologo')
        self.assertEqual(c, 1)

    def test_flatten_nested_cmd(self):
        # Redundant nested cmd.exe shells unwrapped
        res, c = flatten_nested_cmd('cmd /c cmd /c "whoami"')
        self.assertEqual(res, "whoami")
        self.assertEqual(c, 2)

        res, c = flatten_nested_cmd('cmd cmd cmd calc.exe')
        self.assertEqual(res, "calc.exe")
        self.assertEqual(c, 3)

        res, c = flatten_nested_cmd('cmd.exe /c "cmd /c calc"')
        self.assertEqual(res, "calc")
        self.assertEqual(c, 2)

        res, c = flatten_nested_cmd('@%comspec% /c cmd.exe /c "ipconfig /all"')
        self.assertEqual(res, "@ipconfig /all")
        self.assertEqual(c, 2)

        # Single non-nested cmd invocation remains intact (min_depth=2)
        res, c = flatten_nested_cmd('cmd /c whoami')
        self.assertEqual(res, 'cmd /c whoami')
        self.assertEqual(c, 0)

    def test_normalize_delimiters_outside_quotes(self):
        # Delimiters and commas outside quotes
        res, c = normalize_delimiters_outside_quotes('cmd , , ,')
        self.assertEqual(res, 'cmd')
        self.assertGreater(c, 0)

        res, c = normalize_delimiters_outside_quotes('cmd , , , /c , , whoami')
        self.assertEqual(res, 'cmd /c whoami')
        self.assertGreater(c, 0)

        res, c = normalize_delimiters_outside_quotes('calc.exe , , ,')
        self.assertEqual(res, 'calc.exe')
        self.assertGreater(c, 0)

        # Commas inside quotes preserved
        res, c = normalize_delimiters_outside_quotes('echo "one, two, three" , ,')
        self.assertEqual(res, 'echo "one, two, three"')

    def test_eval_batch_slice_and_subst(self):
        val = "abcdefghij"
        self.assertEqual(eval_batch_slice(val, "0", "4"), "abcd")
        self.assertEqual(eval_batch_slice(val, "-4"), "ghij")
        self.assertEqual(eval_batch_slice(val, "2", "-2"), "cdefgh")

        self.assertEqual(eval_batch_subst("powershell", "", "power", "batch"), "batchshell")
        self.assertEqual(eval_batch_subst("abc_target_xyz", "*", "target", "new"), "new_xyz")

    def test_eval_delayed_expansion(self):
        env = {"cmd_name": "calc.exe", "tool": "powershell", "msg": "hello_world"}

        res, c = eval_delayed_expansion("start !cmd_name!", env)
        self.assertEqual(res, "start calc.exe")
        self.assertEqual(c, 1)

        res, c = eval_delayed_expansion("!tool:~0,5!", env)
        self.assertEqual(res, "power")
        self.assertEqual(c, 1)

        res, c = eval_delayed_expansion("!msg:hello=bye!", env)
        self.assertEqual(res, "bye_world")
        self.assertEqual(c, 1)

    def test_chained_environment_variables_resolution(self):
        script = (
            'set "a=c"\n'
            'set "b=%a%m"\n'
            'set "c=%b%d"\n'
            'set "d=!c!.exe"\n'
            'set "cmdline=%d% /c whoami"\n'
            '%cmdline%\n'
        )
        resolved_script, symbols, chains, cycles = resolve_chained_environment_variables(script)
        self.assertEqual(symbols.get("d"), "cmd.exe")
        self.assertIn("cmd.exe /c whoami", resolved_script)
        self.assertGreaterEqual(chains, 3)
        self.assertEqual(cycles, 0)

    def test_cycle_detection_and_loop_guard(self):
        # Mutual cyclic references
        cyclic_script = (
            'set "x=%y%"\n'
            'set "y=%x%"\n'
            'set "safe=clean_command"\n'
            '%safe%\n'
        )
        resolved, symbols, chains, cycles = resolve_chained_environment_variables(cyclic_script)
        self.assertGreater(cycles, 0)
        self.assertEqual(symbols.get("safe"), "clean_command")
        self.assertIn("clean_command", resolved)

        # Self-referential variable
        self_ref_script = (
            'set count=0\n'
            'set count=%count%+1\n'
            'echo %count%\n'
        )
        defs, graph, found_cycles = build_variable_dependency_graph(self_ref_script)
        self.assertIn("count", defs)

    def test_signature_detection(self):
        clean = "@echo off\necho Normal execution\npause\n"
        sig_clean = detect_cmd_deobfuscator_signatures(clean)
        self.assertFalse(sig_clean["is_cmd_deobfuscator"])
        self.assertLess(sig_clean["confidence"], 0.25)

        obfuscated = (
            'set a=c\n'
            'set b=%a%m\n'
            'set c=%b%d\n'
            '!c! /c "w"s"c"r"i"p"t , , , pow""ersh""ell\n'
            'cmd /c cmd /c "whoami"\n'
        )
        sig_obf = detect_cmd_deobfuscator_signatures(obfuscated)
        self.assertTrue(sig_obf["is_cmd_deobfuscator"])
        self.assertGreaterEqual(sig_obf["confidence"], 0.40)
        self.assertGreaterEqual(len(sig_obf["indicators"]), 3)

    def test_zeroize_memory(self):
        secret_dict = {"token": "secret_key_12345", "nested": {"sub": "data"}}
        zeroize_dict(secret_dict)
        self.assertEqual(len(secret_dict), 0)

        raw_buf = bytearray(b"sensitive_buffer_content")
        zeroize_bytes(raw_buf)
        self.assertTrue(all(b == 0 for b in raw_buf))

        norm = CMDDeobfuscatorNormalizer(custom_env={"secret_var": "sensitive_val"})
        norm.zeroize()
        self.assertEqual(len(norm.custom_env), 0)

        with CMDDeobfuscatorNormalizer(custom_env={"temp_sec": "val"}) as ctx_norm:
            self.assertEqual(len(ctx_norm.custom_env), 1)
        self.assertEqual(len(ctx_norm.custom_env), 0)

    def test_normalizer_and_functional_wrapper(self):
        script = (
            'set "v1=cal"\n'
            'set "v2=%v1%c.exe"\n'
            'cmd /c cmd /c "w"s"c"r"i"p"t , , , %v2%\n'
        )
        clean_text, meta = normalize_cmd_deobfuscator(script)
        self.assertIn("calc.exe", clean_text)
        self.assertIn('"wscript"', clean_text)
        self.assertGreater(meta["quotes_widened_count"], 0)
        self.assertGreater(meta["delimiters_normalized_count"], 0)
        self.assertGreater(meta["nested_cmds_flattened_count"], 0)

    def test_e2e_batch_deobfuscator_integration(self):
        script = (
            '@echo off\n'
            'set a=c\n'
            'set b=%a%m\n'
            'set c=%b%d\n'
            'set target=%c%.exe\n'
            'cmd /c cmd /c "%target% , , , /c w"s"c"r"i"p"t pow""ersh""ell"\n'
        )
        engine = BatchDeobfuscator(enable_cmd_deobfuscator=True)
        clean, meta = engine.deobfuscate(script)
        self.assertIn("cmd_deobfuscator_telemetry", meta)
        cdt = meta["cmd_deobfuscator_telemetry"]
        self.assertTrue(cdt.get("is_cmd_deobfuscator"))
        self.assertIn("powershell", clean)

    def test_convenience_helpers(self):
        script = 'set x=calc\nset y=%x%.exe\ncmd cmd cmd %y%\n'
        res_str = deobfuscate_script(script, enable_cmd_deobfuscator=True)
        self.assertIn("calc.exe", res_str)

        raw_bytes = script.encode("utf-8")
        clean_text, meta = deobfuscate_bytes(raw_bytes, enable_cmd_deobfuscator=True)
        self.assertIn("calc.exe", clean_text)


if __name__ == "__main__":
    unittest.main()
