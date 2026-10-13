"""
Unit and Integration Tests for BatchShield Virtual Symbol Table & Compound Env Deobfuscator.
Covers signature detection, static OS indexing, virtual symbol tables, compound chains,
noise pruning, memory wiping, and full pipeline integration.
"""

import unittest
from deobfuscator.batchshield import (
    detect_batchshield_signatures,
    eval_batch_slice,
    eval_batch_subst,
    calculate_shannon_entropy,
    harvest_batchshield_symbols,
    resolve_batchshield_env_chains,
    strip_batchshield_dummy_noise,
    eliminate_batchshield_chaff,
    normalize_batchshield,
    BatchShieldNormalizer,
    zeroize_dict,
    zeroize_bytes,
    DEFAULT_OS_ENV,
)
from deobfuscator.core import BatchDeobfuscator


class TestBatchShieldDeobfuscator(unittest.TestCase):
    """Test suite for BatchShield deobfuscation and compound env resolution."""

    def test_calculate_shannon_entropy(self):
        self.assertEqual(calculate_shannon_entropy(""), 0.0)
        self.assertEqual(calculate_shannon_entropy("aaaa"), 0.0)
        entropy_high = calculate_shannon_entropy("a8f9c2x01b")
        self.assertGreater(entropy_high, 2.5)

    def test_detect_batchshield_signatures_clean(self):
        clean_script = "@echo off\necho Hello World\npause\n"
        sig = detect_batchshield_signatures(clean_script)
        self.assertFalse(sig["is_batchshield"])
        self.assertLess(sig["confidence"], 0.3)
        self.assertEqual(len(sig["indicators"]), 0)

    def test_detect_batchshield_signatures_detected(self):
        obf_script = (
            'set a8f9c2=%COMSPEC:~-7,3%\n'
            'set b01x8a=%PATH:~0,1%\n'
            'set k99z=%a8f9c2%%b01x8a%\n'
            'e%junk99%c%trash44%h%noise11%o %k99z%\n'
        )
        sig = detect_batchshield_signatures(obf_script)
        self.assertTrue(sig["is_batchshield"])
        self.assertGreaterEqual(sig["confidence"], 0.4)
        self.assertGreaterEqual(len(sig["indicators"]), 2)
        self.assertGreaterEqual(sig["os_index_count"], 1)

    def test_eval_batch_slice_semantics(self):
        text = r"C:\Windows\system32\cmd.exe"
        # Positive start, positive length
        self.assertEqual(eval_batch_slice(text, "0", "1"), "C")
        self.assertEqual(eval_batch_slice(text, "3", "7"), "Windows")
        # Negative start, positive length
        self.assertEqual(eval_batch_slice(text, "-7", "3"), "cmd")
        self.assertEqual(eval_batch_slice(text, "-7", "7"), "cmd.exe")
        # Negative start, negative length
        self.assertEqual(eval_batch_slice("abcdefgh", "2", "-2"), "cdef")
        # Explicit plus signs and whitespace
        self.assertEqual(eval_batch_slice(text, " +0 ", " +1 "), "C")
        self.assertEqual(eval_batch_slice(text, " -7 ", " +3 "), "cmd")

    def test_eval_batch_subst_semantics(self):
        val = "powershell.exe -ExecutionPolicy Bypass"
        # Standard replacement
        res = eval_batch_subst(val, "powershell", "cmd")
        self.assertEqual(res, "cmd.exe -ExecutionPolicy Bypass")
        # Wildcard prefix *old=new
        res_wildcard = eval_batch_subst("C:\\Path\\To\\Target\\run.bat", "*Target\\", "C:\\Output\\")
        self.assertEqual(res_wildcard, "C:\\Output\\run.bat")

    def test_harvest_and_resolve_compound_chains(self):
        script = (
            'set a=%COMSPEC:~-7,3%\n'
            'set b=/c\n'
            'set c=whoami\n'
            'set cmd_chain=%a% %b% %c%\n'
            '%cmd_chain%\n'
        )
        symbols, def_lines = harvest_batchshield_symbols(script)
        self.assertEqual(symbols.get("a"), "cmd")
        self.assertEqual(symbols.get("b"), "/c")
        self.assertEqual(symbols.get("c"), "whoami")
        self.assertEqual(symbols.get("cmd_chain"), "cmd /c whoami")
        self.assertEqual(len(def_lines), 4)

    def test_circular_dependency_protection(self):
        circular_script = (
            'set loop1=%loop2%\n'
            'set loop2=%loop1%\n'
            'echo %loop1%\n'
        )
        symbols, _ = harvest_batchshield_symbols(circular_script)
        # Should terminate cleanly without hanging or crashing
        self.assertIn("loop1", symbols)
        self.assertIn("loop2", symbols)

    def test_strip_batchshield_dummy_noise_selective(self):
        script = (
            'set legit_var=safe_value\n'
            'e%junk_chaff_1%c%noise_token_2%h%random_trash%o %legit_var% %random% %errorlevel% %1 %~dp0\n'
        )
        known = {"legit_var"}
        cleaned, stripped_count = strip_batchshield_dummy_noise(script, known)
        self.assertEqual(stripped_count, 3)
        self.assertIn("echo %legit_var% %random% %errorlevel% %1 %~dp0", cleaned)

    def test_eliminate_batchshield_chaff(self):
        script = (
            'set a=1\n'
            'set b=2\n'
            'echo Result: %a% %b%\n'
        )
        symbols = {"a": "1", "b": "2"}
        cleaned, eliminated = eliminate_batchshield_chaff(script, symbols)
        self.assertEqual(len(eliminated), 2)
        self.assertEqual(cleaned.strip(), "echo Result: %a% %b%")

    def test_zeroize_dict_and_bytes(self):
        secret_dict = {"token": "secret_key_123", "nested": {"k": "v"}}
        zeroize_dict(secret_dict)
        self.assertEqual(len(secret_dict), 0)

        raw_buf = bytearray(b"sensitive_buffer_data")
        zeroize_bytes(raw_buf)
        self.assertEqual(raw_buf, bytearray(len(raw_buf)))

    def test_batchshield_normalizer_class_interface(self):
        normalizer = BatchShieldNormalizer(strip_noise=True, eliminate_chaff=True)
        script = 'set p=%COMSPEC:~-7,3%\n%p% /c echo OK\n'
        clean, telemetry = normalizer.normalize(script)
        self.assertIn("cmd /c echo OK", clean)
        self.assertTrue(telemetry["is_batchshield"])
        self.assertGreaterEqual(telemetry["symbols_resolved_count"], 1)

    def test_normalize_batchshield_convenience_function(self):
        script = (
            'set v1=%COMSPEC:~-7,3%\n'
            'set v2=%v1% /c\n'
            '%v2% e%noise%c%noise%h%noise%o PAYLOAD\n'
        )
        clean, meta = normalize_batchshield(script)
        self.assertIn("cmd /c echo PAYLOAD", clean)
        self.assertGreaterEqual(meta["chains_resolved_count"], 1)
        self.assertGreaterEqual(meta["noise_stripped_count"], 3)

    def test_corpus_8_parity(self):
        # Direct parity check against Corpus 8 in BenchmarkCorpus
        script = 'set p=%COMSPEC:~-7,3% & %p% /c echo PAYLOAD_RECOVERED'
        engine = BatchDeobfuscator()
        clean, meta = engine.deobfuscate(script)
        self.assertIn("cmd /c echo PAYLOAD_RECOVERED", clean)


if __name__ == "__main__":
    unittest.main()
