"""
Unit test suite for 0xidiz3r zero-literal bootstrap & reversible alphabet substitution deobfuscator.
Covers:
  - Canonical 0xidiz3r scripts with watermarks
  - Watermark-stripped variants (malware evasion pattern)
  - Chained single-line & multi-command executions
  - Caret-escaped & quoted bootstrap keywords
  - Special character variable identifiers
  - Percent literal (%% -> %) escape resolutions
  - Dead store & preamble elimination
  - Cryptographic zeroize verification
  - Integration with BatchDeobfuscator multi-pass pipeline

Engineered by Maya Thorne.
"""

import unittest
from deobfuscator.oxidizer import (
    extract_bootstrap_primitives,
    harvest_oxidizer_alphabet,
    detect_oxidizer_signatures,
    normalize_oxidizer,
    zeroize_dict,
)
from deobfuscator.core import BatchDeobfuscator, deobfuscate_script


class TestOxidizerDeobfuscator(unittest.TestCase):
    """Test suite for 0xidiz3r deobfuscation and signature extraction."""

    def test_canonical_oxidizer_sample(self):
        """Verify full deobfuscation of a canonical 0xidiz3r script with watermarks."""
        script = (
            ":: VGhpcyBmaWxlIHdhcyBvYmZ1c2NhdGVkIHZpYSBodHRwczovL2dpdGh1Yi5jb20vMHhUYXMvMHhpZGl6M3I=\n"
            ":: VGhpcyBmaWxlIGNhbiBiZSBwcm9ncmFtYXRpY2FsbHkgZGVvYmZ1c2NhdGVkIHZpYSBodHRwczovL2dpdGh1Yi5jb20vMHhUYXMvMHhpZGl6M3I=\n"
            "@echo off\n"
            "set HQTW=set\n"
            "%HQTW% HswBh= \n"
            "%HQTW%%HswBh%xtYRu==\n"
            "%HQTW%%HswBh%ubBBS%xtYRu%c\n"
            "%HQTW%%HswBh%XRVHZ%xtYRu%e\n"
            "%HQTW%%HswBh%qWvHi%xtYRu%h\n"
            "%HQTW%%HswBh%XyVFS%xtYRu%o\n"
            "%HQTW%%HswBh%BslH%xtYRu%C\n"
            "%HQTW%%HswBh%AsBi%xtYRu%P\n"
            "%HQTW%%HswBh%biQK%xtYRu% \n"
            "%XRVHZ%%ubBBS%%qWvHi%%XyVFS%%biQK%%AsBi%%XyVFS%%BslH%\n"
            ":: VGhpcyBmaWxlIHdhcyBvYmZ1c2NhdGVkIHZpYSBodHRwczovL2dpdGh1Yi5jb20vMHhUYXMvMHhpZGl6M3I=\n"
            ":: VGhpcyBmaWxlIGNhbiBiZSBwcm9ncmFtYXRpY2FsbHkgZGVvYmZ1c2NhdGVkIHZpYSBodHRwczovL2dpdGh1Yi5jb20vMHhUYXMvMHhpZGl6M3I=\n"
        )
        clean, meta = normalize_oxidizer(script)
        self.assertTrue(meta["is_oxidizer"])
        self.assertEqual(meta["bootstrap_vars"]["set_var"], "HQTW")
        self.assertEqual(meta["bootstrap_vars"]["space_var"], "HswBh")
        self.assertEqual(meta["bootstrap_vars"]["eq_var"], "xtYRu")
        self.assertIn("echo PoC", clean)
        self.assertNotIn("HQTW", clean)
        self.assertNotIn("VGhpcyBmaWxl", clean)

    def test_watermark_stripped_malware_variant(self):
        """Verify robust detection and deobfuscation when base64 watermarks are removed."""
        script = (
            "set S1=set\n"
            "%S1% SP1= \n"
            "%S1%%SP1%EQ1===\n"
            "%S1%%SP1%c1%EQ1%c\n"
            "%S1%%SP1%a1%EQ1%a\n"
            "%S1%%SP1%l1%EQ1%l\n"
            "%S1%%SP1%x1%EQ1%x\n"
            "%S1%%SP1%e1%EQ1%e\n"
            "%c1%%a1%%l1%%c1%.%e1%%x1%%e1%\n"
        )
        clean, meta = normalize_oxidizer(script)
        self.assertTrue(meta["is_oxidizer"])
        self.assertEqual(meta["bootstrap_vars"]["set_var"], "S1")
        self.assertEqual(clean.strip(), "calc.exe")

    def test_chained_single_line_bootstrap(self):
        """Verify single-line chained bootstrap declarations using ampersand."""
        script = (
            "set s=set & %s% sp= & %s%%sp%eq=== & %s%%sp%c%eq%c & %s%%sp%m%eq%m & %s%%sp%d%eq%d\n"
            "%c%%m%%d% /c whoami\n"
        )
        # Pass through multi-pass deobfuscator
        clean = deobfuscate_script(script)
        self.assertIn("cmd /c whoami", clean)

    def test_caret_escaped_and_quoted_bootstrap(self):
        """Verify handling of carets (s^e^t) and quotes in bootstrap seeds."""
        script = (
            "s^e^t \"SETVAR=set\"\n"
            "%SETVAR% \"SPACEVAR= \"\n"
            "%SETVAR%%SPACEVAR%EQVAR===\n"
            "%SETVAR%%SPACEVAR%d%EQVAR%dir\n"
            "%d%\n"
        )
        clean, meta = normalize_oxidizer(script)
        self.assertEqual(meta["bootstrap_vars"]["set_var"], "SETVAR")
        self.assertIn("dir", clean)

    def test_special_characters_in_identifiers(self):
        """Verify variable identifiers using GoodChars symbols (!, #, $, @, ~, _)."""
        script = (
            "set v#1=set\n"
            "%v#1% sp@2= \n"
            "%v#1%%sp@2%eq_3===\n"
            "%v#1%%sp@2%cmd$4%eq_3%cmd.exe\n"
            "%cmd$4% /c echo OK\n"
        )
        clean, meta = normalize_oxidizer(script)
        self.assertTrue(meta["is_oxidizer"])
        self.assertIn("cmd.exe /c echo OK", clean)

    def test_double_percent_escape(self):
        """Verify resolution of %% percent literal tokens."""
        script = (
            "set s=set\n"
            "%s% sp= \n"
            "%s%%sp%eq===\n"
            "%s%%sp%perc%eq%%%%\n"
            "%s%%sp%w%eq%whoami\n"
            "%perc%COMSPEC%perc% /c %w%\n"
        )
        clean, meta = normalize_oxidizer(script)
        self.assertIn("%COMSPEC% /c whoami", clean)

    def test_mixed_commands_and_cleartext(self):
        """Verify that unaffected cleartext lines remain untouched."""
        script = (
            "set s=set\n"
            "%s% sp= \n"
            "%s%%sp%eq===\n"
            "%s%%sp%c%eq%calc.exe\n"
            "start %c%\n"
            "ping 127.0.0.1 -n 2\n"
        )
        clean, meta = normalize_oxidizer(script)
        lines = [l.strip() for l in clean.splitlines() if l.strip()]
        self.assertIn("start calc.exe", lines)
        self.assertIn("ping 127.0.0.1 -n 2", lines)

    def test_signature_detection_scoring(self):
        """Test heuristic signature detection metrics."""
        script_wm = ":: VGhpcyBmaWxlIHdhcyBvYmZ1c2NhdGVkIHZpYSBodHRwczovL2dpdGh1Yi5jb20vMHhUYXMvMHhpZGl6M3I=\necho hello"
        sig_wm = detect_oxidizer_signatures(script_wm)
        self.assertIn("base64_watermark", sig_wm["indicators"])
        self.assertGreaterEqual(sig_wm["confidence"], 0.5)

        script_clean = "echo standard script & dir"
        sig_clean = detect_oxidizer_signatures(script_clean)
        self.assertFalse(sig_clean["is_oxidizer"])
        self.assertEqual(sig_clean["confidence"], 0.0)

    def test_zeroize_dict_memory_wiping(self):
        """Verify that zeroize_dict properly wipes dictionary data in memory."""
        test_dict = {"key1": "secret_token", "key2": bytearray(b"sensitive_buffer")}
        zeroize_dict(test_dict)
        self.assertEqual(len(test_dict), 0)

    def test_batch_deobfuscator_core_integration(self):
        """Verify seamless end-to-end integration with BatchDeobfuscator."""
        script = (
            ":: VGhpcyBmaWxlIHdhcyBvYmZ1c2NhdGVkIHZpYSBodHRwczovL2dpdGh1Yi5jb20vMHhUYXMvMHhpZGl6M3I=\n"
            "set HQTW=set\n"
            "%HQTW% HswBh= \n"
            "%HQTW%%HswBh%xtYRu==\n"
            "%HQTW%%HswBh%u1%xtYRu%who\n"
            "%HQTW%%HswBh%u2%xtYRu%ami\n"
            "%u1%%u2%\n"
        )
        engine = BatchDeobfuscator(enable_oxidizer=True)
        clean, meta = engine.deobfuscate(script)
        self.assertIn("whoami", clean)
        self.assertTrue(meta["oxidizer_telemetry"]["is_oxidizer"])
        self.assertGreater(meta["oxidizer_telemetry"]["alphabet_size"], 0)


if __name__ == "__main__":
    unittest.main()
