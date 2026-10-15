"""
Comprehensive Test Suite for batobfuscate-machine1337 Deobfuscation Engine.
Validates multi-BOM header stripping, CJK transcode recovery, caret & preamble normalization,
heuristic signature detection, memory zeroization, and end-to-end integration.

Engineered by Maya Thorne.
"""

import unittest
from deobfuscator.machine1337 import (
    is_machine1337_header,
    neutralize_machine1337_headers,
    recover_cjk_transcoded_batch,
    normalize_machine1337_carets_and_preamble,
    detect_machine1337_signatures,
    normalize_machine1337,
    Machine1337Normalizer,
    zeroize_bytes,
    zeroize_dict,
    MACHINE1337_HEADER_V1,
    MACHINE1337_HEADER_V2,
    MACHINE1337_HEADER_LF1,
    MACHINE1337_HEADER_LF2,
    MACHINE1337_BE_HEADER,
    MACHINE1337_UTF8_CORRUPTED_V1,
    MACHINE1337_UTF8_CORRUPTED_V2,
)
from deobfuscator.core import BatchDeobfuscator, deobfuscate_bytes, deobfuscate_script


class TestMachine1337Deobfuscator(unittest.TestCase):
    """Unit and integration tests for machine1337 deobfuscation capabilities."""

    def test_header_detection_variants(self):
        """Test identification of various machine1337 header formats."""
        # V1 exact
        matched, variant, count = is_machine1337_header(MACHINE1337_HEADER_V1 + b"@echo off\r\n")
        self.assertTrue(matched)
        self.assertEqual(variant, "machine1337-v1-exact")
        self.assertEqual(count, 12)

        # V2 CRLF
        matched, variant, count = is_machine1337_header(MACHINE1337_HEADER_V2 + b"echo test")
        self.assertTrue(matched)
        self.assertEqual(variant, "machine1337-v2-crlf")
        self.assertEqual(count, 12)

        # Unix LF variants
        matched, variant, count = is_machine1337_header(MACHINE1337_HEADER_LF1 + b"echo test")
        self.assertTrue(matched)
        self.assertEqual(variant, "machine1337-lf1")

        matched, variant, count = is_machine1337_header(MACHINE1337_HEADER_LF2 + b"echo test")
        self.assertTrue(matched)
        self.assertEqual(variant, "machine1337-lf2")

        # Big-Endian
        matched, variant, count = is_machine1337_header(MACHINE1337_BE_HEADER + b"echo test")
        self.assertTrue(matched)
        self.assertEqual(variant, "machine1337-be")

        # UTF-8 corrupted replacement characters (as in TEUEI.bat)
        matched, variant, count = is_machine1337_header(MACHINE1337_UTF8_CORRUPTED_V1 + b"@echo off\n")
        self.assertTrue(matched)
        self.assertEqual(variant, "machine1337-utf8-corrupted-v1")

        # Non-matching
        matched, variant, count = is_machine1337_header(b"@echo off\r\nwhoami")
        self.assertFalse(matched)
        self.assertEqual(variant, "none")
        self.assertEqual(count, 0)

    def test_neutralize_machine1337_headers(self):
        """Test binary header stripping and payload decoding."""
        payload = b"@echo off\r\necho Hello machine1337 payload!\r\npause\r\n"
        obfuscated = MACHINE1337_HEADER_V1 + payload

        clean_text, meta = neutralize_machine1337_headers(obfuscated)
        self.assertTrue(meta["header_stripped"])
        self.assertEqual(meta["header_variant"], "machine1337-v1-exact")
        self.assertEqual(meta["stripped_bytes"], 12)
        self.assertIn("echo Hello machine1337 payload!", clean_text)

    def test_neutralize_nested_headers(self):
        """Test multi-layer header stripping when obfuscator was executed repeatedly."""
        payload = b"@echo off\r\ncalc.exe\r\n"
        double_obfuscated = MACHINE1337_HEADER_V1 + MACHINE1337_HEADER_V2 + payload

        clean_text, meta = neutralize_machine1337_headers(double_obfuscated)
        self.assertTrue(meta["header_stripped"])
        self.assertEqual(meta["layers_stripped"], 2)
        self.assertEqual(meta["stripped_bytes"], 24)
        self.assertIn("calc.exe", clean_text)

    def test_neutralize_utf8_corrupted_header(self):
        """Test recovery from UTF-8 corrupted header file (TEUEI.bat pattern)."""
        payload = b"@echo off\necho Hello world !\ntimeout /t 5 /NOBREAK\npause"
        corrupted = MACHINE1337_UTF8_CORRUPTED_V1 + payload

        clean_text, meta = neutralize_machine1337_headers(corrupted)
        self.assertTrue(meta["header_stripped"])
        self.assertIn("machine1337-utf8", meta["header_variant"])
        self.assertIn("echo Hello world !", clean_text)

    def test_cjk_transcode_recovery_synthetic(self):
        """Test recovery of batch code that was mistakenly saved or viewed as UTF-16LE Chinese text."""
        # Create genuine raw bytes of machine1337 obfuscated batch
        original_script = "@echo off\r\necho TARGET_PAYLOAD_RECOVERED\r\npause"
        raw_obfuscated = MACHINE1337_HEADER_V1 + original_script.encode("ascii")

        # Decode as UTF-16LE (mimicking VS Code or text editor opening the file with UTF-16LE)
        cjk_pseudo_text = raw_obfuscated.decode("utf-16le", errors="replace")
        self.assertTrue(cjk_pseudo_text.startswith("\ufeff\u6326\u736c") or cjk_pseudo_text.startswith("\u6326\u736c"))

        # Recover using CJK transcode engine
        recovered_text, was_recovered = recover_cjk_transcoded_batch(cjk_pseudo_text)
        self.assertTrue(was_recovered)
        self.assertIn("@echo off", recovered_text)
        self.assertIn("TARGET_PAYLOAD_RECOVERED", recovered_text)

    def test_cjk_transcode_recovery_readme_specimen(self):
        """Test recovery using the actual Chinese text specimen documented in batobfuscate README.md."""
        # Extract of README specimen:
        # 挦獬਍﻿ഊ敀档⁯䙏െഊ㨊䔺䥘呓挠浯慭摮椠⁳獵摥琠⁯档捥⁫潦⁲硥獩整据൥䤊⁆塅卉⁔㩄慜换琮瑸䔠䡃⁏扡⹣硴⁴潦湵൤䤊⁆塅卉⁔㩄硜穹琮瑸⠠䍅佈砠穹琮瑸映畯摮
        specimen = (
            "\u6326\u736c\u0a0d\ufeff\u0d0a\u6540\u6863\u206f\u464f\u0d46\u0d0a\u3a0a"
            "\u3a3a\u4558\u4953\u5420\u636f\u6d6d\u616e\u6420\u6973\u2075\u7365\u6420"
            "\u746f\u2063\u6865\u636b\u2066\u6f72\u2065\u7869\u7374\u656e\u6365\u0d0a"
            "\u4946\u2045\u5849\u5354\u2044\u3a5c\u6162\u632e\u7478\u7420\u4543\u484f"
            "\u2061\u6263\u2e74\u7874\u2066\u6f75\u6e64\u0d0a"
        )
        recovered, ok = recover_cjk_transcoded_batch(specimen)
        self.assertTrue(ok)
        self.assertIn("echo", recovered.lower())

    def test_cjk_no_false_positive_on_english_or_hangul(self):
        """Ensure standard English and Korean texts are never falsely identified as CJK pseudo-text."""
        normal_en = "@echo off\r\nset var=test\r\necho %var%\r\npause\r\n"
        rec_en, ok_en = recover_cjk_transcoded_batch(normal_en)
        self.assertFalse(ok_en)
        self.assertEqual(rec_en, normal_en)

        normal_ko = "@echo off\r\necho 한글 배치 스크립트 테스트\r\npause\r\n"
        rec_ko, ok_ko = recover_cjk_transcoded_batch(normal_ko)
        self.assertFalse(ok_ko)
        self.assertEqual(rec_ko, normal_ko)

    def test_normalize_carets_and_preamble(self):
        """Test inline caret unescaping and &cls preamble removal."""
        raw_text = "&cls & c^m^d /c p^o^w^e^r^s^h^e^l^l -Command Get-Process"
        clean, meta = normalize_machine1337_carets_and_preamble(raw_text)
        self.assertTrue(meta["cls_preamble_stripped"])
        self.assertGreater(meta["carets_normalized"], 0)
        self.assertEqual(clean.strip(), "cmd /c powershell -Command Get-Process")

    def test_carets_inside_quotes_preserved(self):
        """Verify that carets inside double-quoted literals are safely preserved."""
        raw_text = 'c^m^d /c echo "Keep ^caret inside quotes" & p^a^u^s^e'
        clean, meta = normalize_machine1337_carets_and_preamble(raw_text)
        self.assertIn('echo "Keep ^caret inside quotes"', clean)
        self.assertIn("pause", clean)

    def test_signature_detection_comprehensive(self):
        """Test heuristic detection across raw bytes, CJK strings, and carets."""
        # 1. Raw binary
        sig_bytes = detect_machine1337_signatures(MACHINE1337_HEADER_V1 + b"dir")
        self.assertTrue(sig_bytes["is_machine1337"])
        self.assertTrue(sig_bytes["has_raw_header"])
        self.assertGreaterEqual(sig_bytes["confidence"], 0.8)

        # 2. CJK pseudo-text
        sig_cjk = detect_machine1337_signatures("\u6326\u736c\u0a0d\ufeff\u0d0a\u6540\u6863")
        self.assertTrue(sig_cjk["is_machine1337"])
        self.assertTrue(sig_cjk["has_cjk_transcode"])

        # 3. Caret + cls preamble
        sig_caret = detect_machine1337_signatures("&cls & c^m^d /c w^h^o^a^m^i")
        self.assertTrue(sig_caret["is_machine1337"])
        self.assertTrue(sig_caret["has_cls_preamble"])
        self.assertTrue(sig_caret["has_caret_scramble"])

        # 4. Clean script
        sig_clean = detect_machine1337_signatures("@echo off\r\necho Normal Script")
        self.assertFalse(sig_clean["is_machine1337"])
        self.assertEqual(sig_clean["confidence"], 0.0)

    def test_normalize_machine1337_full_pipeline(self):
        """Test high-level normalize_machine1337 on both bytes and string inputs."""
        # Bytes input
        payload_bytes = MACHINE1337_HEADER_V1 + b"&cls & c^m^d /c whoami"
        text_out, meta = normalize_machine1337(payload_bytes)
        self.assertTrue(meta["header_stripped"])
        self.assertTrue(meta["cls_preamble_stripped"])
        self.assertEqual(text_out.strip(), "cmd /c whoami")

        # String input
        script_str = "&cls\r\nc^u^r^l -s http://127.0.0.1/test"
        text_out2, meta2 = normalize_machine1337(script_str)
        self.assertTrue(meta2["cls_preamble_stripped"])
        self.assertIn("curl -s http://127.0.0.1/test", text_out2)

    def test_class_wrapper_and_zeroize(self):
        """Test Machine1337Normalizer stateful wrapper and memory zeroization."""
        buf = bytearray(b"sensitive_machine1337_key_12345")
        zeroize_bytes(buf)
        self.assertEqual(set(buf), {0})

        meta_dict = {"secret": "val", "list": [1, 2, 3], "nested": {"k": "v"}}
        zeroize_dict(meta_dict)
        self.assertEqual(len(meta_dict), 0)

        with Machine1337Normalizer() as norm:
            out, meta = norm.normalize("&cls & c^m^d /c echo TEST")
            self.assertEqual(out.strip(), "cmd /c echo TEST")
            self.assertIn("signatures", meta)

    def test_e2e_integration_with_batch_deobfuscator(self):
        """Test full integration within BatchDeobfuscator convergence loop."""
        obfuscated_bytes = MACHINE1337_HEADER_V1 + b"&cls & set target=whoami & c^m^d /c %target%"
        clean_text, meta = deobfuscate_bytes(obfuscated_bytes)
        self.assertIn("cmd /c whoami", clean_text)
        self.assertTrue(meta["machine1337_telemetry"]["header_stripped"])

    def test_corpus_12_regression(self):
        """Test Corpus 12 (batobfuscate-machine1337) regression from benchmark suite."""
        corpus_12_script = '&cls & c^m^d /c p^o^w^e^r^s^h^e^l^l -Command Get-Process'
        clean = deobfuscate_script(corpus_12_script)
        self.assertEqual(clean.strip(), "cmd /c powershell -Command Get-Process")


if __name__ == "__main__":
    unittest.main()
