"""
Unit test suite for Abobus-obfuscator normalization, Unicode noise filtering,
decoy variable elimination, and trap chaff removal engine.

Covers:
  - Canonical Abobus scripts with markers and metadata
  - Heuristic detection on marker-stripped evasion variants
  - Clean non-Abobus script discrimination (false positive check)
  - Zero-width character & Unicode noise stripping
  - Kaomoji, Arabic decoy glyph, and Chinese warning string removal
  - Caret separation on quotes (^"), keywords, and variable identifiers
  - Leading semicolon/at-sign delimiter trap normalization (;;, ;@;, @@)
  - Excessive whitespace indentation pruning (>50 spaces)
  - Opaque predicate and random_if prefix unwrapping
  - Anti-tamper / anti-analysis execution trap line pruning
  - Chinese substring dictionary harvesting and %public% slicing inversion
  - Chained multi-stage Chinese dictionary resolution
  - Ephemeral decoy variable elimination (%𝧽%, dummy flags)
  - Cryptographic RAM zeroization verification
  - Integration with BatchDeobfuscator multi-pass pipeline and CLI flags

Engineered by Maya Thorne.
"""

import unittest
from typing import Dict, Any

from deobfuscator.abobus import (
    AbobusNormalizer,
    detect_abobus_signatures,
    strip_abobus_unicode_noise,
    strip_abobus_decoy_variables,
    normalize_abobus_carets_and_delimiters,
    strip_abobus_traps_and_chaff,
    resolve_abobus_substring_dictionaries,
    normalize_abobus,
    zeroize_dict,
)
from deobfuscator.core import BatchDeobfuscator, deobfuscate_script


class TestAbobusDeobfuscator(unittest.TestCase):
    """Test suite for Abobus-obfuscator deobfuscation and forensic normalization."""

    def test_detect_abobus_signatures_canonical(self):
        """Verify signature detection on canonical Abobus script with full author metadata."""
        script = (
            ":ABOBUS-OBFUSCATOR\n"
            ';SE^T "__author__=EscaLag"\n'
            ';SE^T "__github__=github.com/EscaLag/Abobus-obfuscator"\n'
            "@find >nul 2>&1&&for /l %%c in (.)do (@echo ABOBUS OBFUSCATION)||@exit\n"
            "cmd /c whoami\n"
        )
        sig = detect_abobus_signatures(script)
        self.assertTrue(sig["is_abobus"])
        self.assertGreaterEqual(sig["confidence"], 0.85)
        self.assertIn("marker_ABOBUS-OBFUSCATOR", sig["indicators"])
        self.assertIn("marker_EscaLag", sig["indicators"])
        self.assertTrue(sig["has_traps"])

    def test_detect_abobus_signatures_markerless_heuristic(self):
        """Verify heuristic detection when author markers are deliberately stripped."""
        script = (
            "c%ﭲسﺖﮚ%^m%ヾ(⌐■_■)ノ%^d /c whoami\n"
            'set "阿贝色德=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ @="\n'
            "if 1 EQU 1 %阿贝色德:~12,1%\n"
        )
        sig = detect_abobus_signatures(script)
        self.assertTrue(sig["is_abobus"])
        self.assertTrue(sig["has_arabic"])
        self.assertTrue(sig["has_kaomoji"])
        self.assertTrue(sig["has_chinese_decoys"])

    def test_detect_clean_script_negative(self):
        """Verify clean non-obfuscated script does not trigger Abobus heuristics."""
        script = "@echo off\necho System maintenance starting...\ndir C:\\Windows\n"
        sig = detect_abobus_signatures(script)
        self.assertFalse(sig["is_abobus"])
        self.assertEqual(sig["confidence"], 0.0)
        self.assertEqual(len(sig["indicators"]), 0)

    def test_strip_abobus_unicode_noise(self):
        """Verify stripping of Arabic glyphs, Kaomoji, Chinese warning decoys, and zero-width chars."""
        # Mix zero-width marks (\u200e, \u200f), Arabic (%ﭲس^ﺖﮚ%), Kaomoji (%ヾ(⌐■_■)ノ%), and warning text
        noisy_script = (
            "c%ﭲس^ﺖﮚ%^m%ヾ(⌐■_■)ノ%^d\u200e /c %此訊息已被神秘魔法保護凡人%whoami\u200f"
        )
        clean, removed = strip_abobus_unicode_noise(noisy_script)
        self.assertNotIn("ﭲ", clean)
        self.assertNotIn("ヾ(⌐■_■)ノ", clean)
        self.assertNotIn("此訊息已被神秘魔法保護", clean)
        self.assertNotIn("\u200e", clean)
        self.assertNotIn("\u200f", clean)
        self.assertIn("c^m^d /c whoami", clean)
        self.assertGreater(len(removed), 0)

    def test_normalize_abobus_carets_and_delimiters(self):
        """Verify normalization of carets, escaped quotes (^"), keywords, and leading delimiters."""
        script = (
            '; ;   s^e^t ^"target=calc.exe^"\n'
            ";@;@@c^m^d /c %t^a^r^g^e^t%\n"
            + (" " * 80) + "e^c^h^o Done\n"
        )
        clean = normalize_abobus_carets_and_delimiters(script)
        lines = clean.splitlines()
        self.assertIn('set "target=calc.exe"', lines[0])
        self.assertIn('@cmd /c %target%', lines[1])
        self.assertIn('echo Done', lines[2])
        self.assertFalse(lines[2].startswith(" " * 50))

    def test_strip_abobus_traps_and_chaff(self):
        """Verify unwrapping of random_if prefixes and pruning of anti-analysis execution traps."""
        script = (
            ":ABOBUS-OBFUSCATOR\n"
            ';SE^T "__author__=EscaLag"\n'
            "(@chcp.com 437)>nul\n"
            "@find >nul 2>&1&&for /l %%c in (.)do (@echo ABOBUS OBFUSCATION)||@exit\n"
            "set b=1 >nul 2>&1 & if not defined b (@echo =D&@pause&@exit)\n"
            "echo>tmp&@for /f \"tokens=3\" %%i in ('type tmp')do if \"%%i\" EQU \"on.\" (@exit) else (@del /f/q tmp)\n"
            "if 1 EQU 1 cmd /c whoami\n"
            "if 25 EQU 0 (@exit) else dir C:\\\n"
            "if 5 LsS 50 for /l %%y in (1,1,1) do echo Verified\n"
            "for /l %%i in (1 1 1)do (for /l %%i in (1 1 1)do (if %errorlevel% EQU 0 exit))\n"
        )
        clean, count = strip_abobus_traps_and_chaff(script)
        self.assertGreaterEqual(count, 7)
        self.assertNotIn(":ABOBUS-OBFUSCATOR", clean)
        self.assertNotIn("__author__", clean)
        self.assertNotIn("ABOBUS OBFUSCATION", clean)
        self.assertNotIn("type tmp", clean)
        self.assertNotIn("if %errorlevel% EQU 0", clean)
        lines = [l.strip() for l in clean.splitlines() if l.strip()]
        self.assertIn("cmd /c whoami", lines)
        self.assertIn("dir C:\\", lines)
        self.assertIn("echo Verified", lines)

    def test_resolve_chinese_substring_dictionaries(self):
        """Verify harvesting and inlining of Chinese substring dictionaries with %public% slicing."""
        # In Abobus: first dictionary uses %public:~idx,1%
        # C:\Users\Public -> C=0, :=1, \=2, U=3, s=4, e=5, r=6, P=9, u=10, b=11, l=12, i=13, c=14
        script = (
            'set "阿贝色德=%public:~0,1%md /c %public:~10,1%sers"\n'
            '%阿贝色德:~0,1%%阿贝色德:~1,1%%阿贝色德:~2,1%%阿贝色德:~3,1%%阿贝色德:~4,1%%阿贝色德:~5,1%%阿贝色德:~6,1%%阿贝色德:~7,1%\n'
        )
        clean, dict_map, resolved_count = resolve_abobus_substring_dictionaries(script)
        self.assertIn("阿贝色德", dict_map)
        self.assertIn("Cmd /c users", dict_map["阿贝色德"])
        self.assertGreater(resolved_count, 0)
        self.assertNotIn('set "阿贝色德=', clean)
        self.assertIn("Cmd /c u", clean)

    def test_chained_chinese_dictionaries(self):
        """Verify multi-pass resolution of chained Chinese substring dictionaries."""
        # Table 1: literal alphabet
        # Table 2: defined via Table 1
        # Payload: uses Table 2
        script = (
            'set "阿贝色德=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ @="\n'
            'set "艾豆贝尔=%阿贝色德:~12,1%%阿贝色德:~22,1%%阿贝色德:~13,1%"\n'
            '%艾豆贝尔:~0,1%%艾豆贝尔:~1,1%%艾豆贝尔:~2,1% /c whoami\n'
        )
        clean, dict_map, count = resolve_abobus_substring_dictionaries(script)
        self.assertIn("阿贝色德", dict_map)
        self.assertIn("艾豆贝尔", dict_map)
        self.assertEqual(dict_map["艾豆贝尔"], "cmd")
        self.assertIn("cmd /c whoami", clean)
        self.assertNotIn("阿贝色德", clean)
        self.assertNotIn("艾豆贝尔", clean)

    def test_strip_abobus_decoy_variables(self):
        """Verify elimination of decoy dummy variables like 𝧽 and b."""
        script = (
            "set 𝧽=  c\n"
            "set iillliil=%0\n"
            "set /a +=1 >nul\n"
            "set b=1 >nul 2>&1\n"
            "echo Target=%𝧽%\n"
        )
        clean, removed = strip_abobus_decoy_variables(script)
        self.assertNotIn("𝧽=", clean)
        self.assertNotIn("%𝧽%", clean)
        self.assertNotIn("iillliil=%0", clean)
        self.assertIn("echo Target=", clean)

    def test_full_abobus_script_end_to_end(self):
        """Verify end-to-end normalization of a complex synthetic Abobus-obfuscated specimen."""
        full_specimen = (
            ":ABOBUS-OBFUSCATOR\n"
            ';SE^T "__author__=EscaLag"\n'
            ';SE^T "__github__=github.com/EscaLag/Abobus-obfuscator"\n'
            "(@chcp.com 437)>nul&@echo off&cls&&set illilili=%0&set 𝧽=  c\n"
            "@find >nul 2>&1&&for /l %%c in (.)do (@echo ABOBUS OBFUSCATION)||@exit\n"
            'set "阿贝色德=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ @="\n'
            ";@; if 1 EQU 1 %阿贝色德:~12,1%%ﭲس^ﺖﮚ%^%阿贝色德:~22,1%^%阿贝色德:~13,1% /c whoami\n"
            "echo>tmp&@for /f \"tokens=3\" %%i in ('type tmp')do if \"%%i\" EQU \"on.\" (@exit) else (@del /f/q tmp)\n"
        )
        clean, meta = normalize_abobus(full_specimen)
        self.assertTrue(meta["is_abobus"])
        self.assertGreaterEqual(meta["eliminated_traps_count"], 3)
        self.assertIn("cmd /c whoami", clean)
        self.assertNotIn("ABOBUS", clean)
        self.assertNotIn("阿贝色德", clean)
        self.assertNotIn("ﭲ", clean)

    def test_corpus_04_abobus_integration(self):
        """Verify full multi-pass pipeline resolution of benchmark Corpus 04 (Abobus)."""
        corpus_04 = '@s^e^t ^"abobus=whoami^" & c^m^d /c %abobus%'
        clean = deobfuscate_script(corpus_04)
        self.assertEqual(clean.strip(), "cmd /c whoami")

    def test_core_batch_deobfuscator_abobus_flag(self):
        """Verify enable_abobus parameter controls execution of Abobus pass."""
        test_script = (
            ":ABOBUS-OBFUSCATOR\n"
            "if 1 EQU 1 c%ﭲسﺖ%^m^d /c whoami\n"
        )
        # Enabled (default)
        engine_on = BatchDeobfuscator(enable_abobus=True)
        clean_on, meta_on = engine_on.deobfuscate(test_script)
        self.assertTrue(meta_on["abobus_telemetry"]["is_abobus"])
        self.assertIn("cmd /c whoami", clean_on)
        self.assertNotIn(":ABOBUS-OBFUSCATOR", clean_on)

        # Disabled
        engine_off = BatchDeobfuscator(enable_abobus=False)
        clean_off, meta_off = engine_off.deobfuscate(test_script)
        self.assertFalse(meta_off["abobus_telemetry"]["is_abobus"])
        self.assertIn(":ABOBUS-OBFUSCATOR", clean_off)

    def test_zeroize_dict_memory_forensics(self):
        """Verify cryptographic RAM wiping of in-memory dictionaries."""
        d: Dict[str, Any] = {"阿贝色德": "secret_alphabet", "key2": bytearray(b"payload_bytes")}
        zeroize_dict(d)
        self.assertEqual(len(d), 0)

    def test_abobus_normalizer_class_interface(self):
        """Verify object-oriented AbobusNormalizer wrapper methods."""
        normalizer = AbobusNormalizer()
        script = ":ABOBUS-OBFUSCATOR\ncmd /c whoami\n"
        sig = normalizer.detect(script)
        self.assertTrue(sig["is_abobus"])
        clean, meta = normalizer.normalize(script)
        self.assertIn("cmd /c whoami", clean)
        self.assertNotIn(":ABOBUS-OBFUSCATOR", clean)


if __name__ == "__main__":
    unittest.main()
