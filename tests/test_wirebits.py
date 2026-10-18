"""
Comprehensive Unit & Integration Test Suite for BatchObfuscator-wirebits Engine.
Verifies signature heuristics, header neutralization, hex/octal escape decoding,
PowerShell character casting & join resolution, radix arithmetic normalization,
sequential character fragment splicing, memory zeroization, and Corpus 19 parity.

Engineered by Maya Thorne.
"""

import unittest
from typing import Dict, Any

from deobfuscator.wirebits import (
    detect_wirebits_signatures,
    neutralize_wirebits_headers,
    decode_hex_escapes,
    decode_octal_escapes,
    resolve_char_casting_and_arrays,
    normalize_radix_arithmetic,
    resolve_wirebits_char_splicing,
    normalize_wirebits,
    WireBitsNormalizer,
    zeroize_dict,
    zeroize_bytes,
)
from deobfuscator.core import BatchDeobfuscator, deobfuscate_script, deobfuscate_bytes


class TestWireBitsEngine(unittest.TestCase):
    """Test suite covering all WireBits deobfuscation components and edge cases."""

    def test_detect_wirebits_signatures_header_base64(self):
        sample = "//4mY2xzDQo=@echo off\ncmd.exe /c calc.exe"
        sig = detect_wirebits_signatures(sample)
        self.assertTrue(sig["is_wirebits"])
        self.assertTrue(sig["has_header"])
        self.assertGreaterEqual(sig["confidence"], 0.40)
        self.assertIn("wirebits-header-bom-cls", sig["indicators"])

    def test_detect_wirebits_signatures_raw_bom_bytes(self):
        data = b"\xff\xfe&cls\r\n@echo off\r\npowershell whoami"
        sig = detect_wirebits_signatures(data)
        self.assertTrue(sig["is_wirebits"])
        self.assertTrue(sig["has_header"])
        self.assertIn("wirebits-header-bom-cls", sig["indicators"])

    def test_detect_wirebits_signatures_banner(self):
        sample = (
            "+──────────────────────────────────────────────+\n"
            "| Batch File Obfuscation Tool |\n"
            "| Author : WireBits |\n"
            "+──────────────────────────────────────────────+\n"
            "echo Hello"
        )
        sig = detect_wirebits_signatures(sample)
        self.assertTrue(sig["is_wirebits"])
        self.assertTrue(sig["has_banner"])
        self.assertGreaterEqual(sig["confidence"], 0.40)

    def test_detect_wirebits_signatures_box_drawing_glyphs(self):
        sample = ":: ╔╗ ╔═╗ ╠╩╗ ╚═╝\n╰┈➤ Obfuscate a .bat/.cmd file\nwhoami"
        sig = detect_wirebits_signatures(sample)
        self.assertTrue(sig["is_wirebits"])
        self.assertTrue(sig["has_banner"])

    def test_detect_wirebits_signatures_char_splicing(self):
        sample = "set _1=p&set _2=o&set _3=w&%_1%%_2%%_3%ershell"
        sig = detect_wirebits_signatures(sample)
        self.assertTrue(sig["is_wirebits"])
        self.assertTrue(sig["has_char_splicing"])

    def test_detect_wirebits_signatures_hex_escapes(self):
        sample = r"cmd /c \x70\x6f\x77\x65\x72\x73\x68\x65\x6c\x6c -c whoami"
        sig = detect_wirebits_signatures(sample)
        self.assertTrue(sig["is_wirebits"])
        self.assertTrue(sig["has_hex_escapes"])

    def test_detect_wirebits_signatures_octal_escapes(self):
        sample = r"echo \143\141\154\143\056\145\170\145"
        sig = detect_wirebits_signatures(sample)
        self.assertTrue(sig["is_wirebits"])
        self.assertTrue(sig["has_octal_escapes"])

    def test_detect_wirebits_signatures_powershell_arrays(self):
        sample = 'powershell -c "$x=[char]0x70+[char]0x6f+[char]0x77; iex $x"'
        sig = detect_wirebits_signatures(sample)
        self.assertTrue(sig["is_wirebits"])
        self.assertTrue(sig["has_powershell_arrays"])

    def test_detect_wirebits_signatures_radix_arithmetic(self):
        sample = "set /a var=0x10 + 040 + 2#1010\necho %var%"
        sig = detect_wirebits_signatures(sample)
        self.assertTrue(sig["is_wirebits"])
        self.assertTrue(sig["has_radix_arithmetic"])

    def test_detect_wirebits_signatures_clean_negative(self):
        sample = "@echo off\nset target=calc.exe\nstart %target%"
        sig = detect_wirebits_signatures(sample)
        self.assertFalse(sig["is_wirebits"])
        self.assertEqual(sig["confidence"], 0.0)
        self.assertEqual(len(sig["indicators"]), 0)

    def test_neutralize_headers_base64_embedded(self):
        sample = "//4mY2xzDQo=@echo off\necho Clean Code"
        clean, meta = neutralize_wirebits_headers(sample)
        self.assertTrue(meta["header_stripped"])
        self.assertEqual(clean, "@echo off\necho Clean Code")

    def test_neutralize_headers_raw_bytes(self):
        data = b"\xff\xfe&cls\r\n@echo off\r\nwhoami"
        clean, meta = neutralize_wirebits_headers(data)
        self.assertTrue(meta["header_stripped"])
        self.assertIn("whoami", clean)
        self.assertNotIn("&cls", clean)

    def test_neutralize_headers_tui_box_banner(self):
        sample = (
            "+──────────────────────────────────────────────+\n"
            "|╔╗ ╔═╗╔╦╗╔═╗╦ ╦ ╔═╗╔╗ ╔═╗╦ ╦╔═╗╔═╗╔═╗╔╦╗╔═╗╦═╗|\n"
            "|╠╩╗╠═╣ ║ ║  ╠═╣ ║ ║╠╩╗╠╣ ║ ║╚═╗║  ╠═╣ ║ ║ ║╠╦╝|\n"
            "|╚═╝╩ ╩ ╩ ╚═╝╩ ╩ ╚═╝╚═╝╚  ╚═╝╚═╝╚═╝╩ ╩ ╩ ╚═╝╩╚═|\n"
            "+──────────────────────────────────────────────+\n"
            "|         Batch File Obfuscation Tool          |\n"
            "+──────────────────────────────────────────────+\n"
            "|              Author : WireBits               |\n"
            "+──────────────────────────────────────────────+\n"
            "@echo off\n"
            "calc.exe"
        )
        clean, meta = neutralize_wirebits_headers(sample)
        self.assertTrue(meta["banner_stripped"])
        self.assertGreater(meta["stripped_lines"], 5)
        self.assertNotIn("WireBits", clean)
        self.assertIn("calc.exe", clean)

    def test_decode_hex_escapes_standard(self):
        sample = r"cmd.exe /c \x63\x61\x6c\x63\x2e\x65\x78\x65"
        decoded, count = decode_hex_escapes(sample)
        self.assertEqual(decoded, "cmd.exe /c calc.exe")
        self.assertEqual(count, 8)

    def test_decode_hex_escapes_unicode(self):
        sample = r"\u0070\u006f\u0077\u0065\u0072\u0073\u0068\u0065\u006c\u006c"
        decoded, count = decode_hex_escapes(sample)
        self.assertEqual(decoded, "powershell")
        self.assertEqual(count, 10)

    def test_decode_octal_escapes_standard(self):
        sample = r"start \143\141\154\143\056\145\170\145"
        decoded, count = decode_octal_escapes(sample)
        self.assertEqual(decoded, "start calc.exe")
        self.assertEqual(count, 8)

    def test_decode_octal_escapes_with_whitespace(self):
        sample = r"echo\040\110\145\154\154\157"
        decoded, count = decode_octal_escapes(sample)
        self.assertEqual(decoded, "echo Hello")
        self.assertEqual(count, 6)

    def test_resolve_char_casting_concatenation(self):
        sample = 'powershell -c "$cmd = [char]0x63+[char]0x61+[char]0x6c+[char]0x63; & $cmd"'
        resolved, count = resolve_char_casting_and_arrays(sample)
        self.assertEqual(count, 1)
        self.assertIn('"calc"', resolved)

    def test_resolve_char_casting_join_array(self):
        sample = 'powershell -c "(-join (0x70,0x6f,0x77,0x65,0x72,0x73,0x68,0x65,0x6c,0x6c|%{[char]$_}))"'
        resolved, count = resolve_char_casting_and_arrays(sample)
        self.assertEqual(count, 1)
        self.assertIn('"powershell"', resolved)

    def test_resolve_char_casting_string_join(self):
        sample = "[string]::Join('', (0x64,0x69,0x72|ForEach-Object{[char]$_}))"
        resolved, count = resolve_char_casting_and_arrays(sample)
        self.assertEqual(count, 1)
        self.assertEqual(resolved, '"dir"')

    def test_normalize_radix_arithmetic_hex_and_octal(self):
        sample = "set /a num=0x10 + 040"
        normalized, count = normalize_radix_arithmetic(sample)
        self.assertIn("16 + 32", normalized)
        self.assertEqual(count, 2)

    def test_normalize_radix_arithmetic_base_notation(self):
        sample = "set /a val=2#1010 + 8#77 + 16#FF"
        normalized, count = normalize_radix_arithmetic(sample)
        self.assertIn("10 + 63 + 255", normalized)
        self.assertEqual(count, 3)

    def test_resolve_char_splicing_decimal(self):
        sample = "set _1=c&set _2=a&set _3=l&set _4=c&%_1%%_2%%_3%%_4%.exe"
        resolved, meta = resolve_wirebits_char_splicing(sample)
        self.assertIn("calc.exe", resolved)
        self.assertEqual(meta["spliced_fragments_resolved"], 4)
        self.assertEqual(meta["dead_stores_pruned"], 4)

    def test_resolve_char_splicing_hex_indices(self):
        sample = "set _0x01=c&set _0x02=m&set _0x03=d&%_0x01%%_0x02%%_0x03% /c whoami"
        resolved, meta = resolve_wirebits_char_splicing(sample)
        self.assertIn("cmd /c whoami", resolved)
        self.assertEqual(meta["spliced_fragments_resolved"], 3)
        self.assertEqual(meta["dead_stores_pruned"], 3)

    def test_corpus_19_wirebits_parity(self):
        # Exact script from BenchmarkCorpus 19 (benchmarks/corpus_data.py)
        script = 'set _1=p&set _2=o&set _3=w&set _4=e&set _5=r&set _6=shell&%_1%%_2%%_3%%_4%%_5%%_6% -Version 5.1'
        expected = "powershell -Version 5.1"
        clean, meta = normalize_wirebits(script)
        self.assertEqual(clean.strip(), expected)
        self.assertEqual(meta["dead_stores_pruned"], 6)

    def test_wirebits_normalizer_class_pipeline(self):
        normalizer = WireBitsNormalizer()
        script = (
            "//4mY2xzDQo="
            "set _1=w&set _2=h&set _3=o&set _4=a&set _5=m&set _6=i&%_1%%_2%%_3%%_4%%_5%%_6%"
        )
        clean, meta = normalizer.normalize(script)
        self.assertEqual(clean.strip(), "whoami")
        self.assertTrue(meta["headers_neutralized"])
        self.assertTrue(meta["is_wirebits"])

    def test_end_to_end_core_deobfuscator(self):
        script = (
            "//4mY2xzDQo="
            "set _1=p&set _2=o&set _3=w&set _4=e&set _5=r&set _6=shell&"
            "%_1%%_2%%_3%%_4%%_5%%_6% -c whoami"
        )
        engine = BatchDeobfuscator(enable_wirebits=True)
        clean, meta = engine.deobfuscate(script)
        self.assertIn("powershell -c whoami", clean)
        self.assertIn("wirebits_telemetry", meta)
        wt = meta["wirebits_telemetry"]
        self.assertTrue(wt["is_wirebits"])
        self.assertTrue(wt["headers_neutralized"])

    def test_cryptographic_zeroize(self):
        d = {"key": "secret_token", "bytes": bytearray(b"sensitive_radix_buffer"), "tags": {"tag1", "tag2"}}
        b = bytearray(b"super_secret_payload")
        zeroize_dict(d)
        zeroize_bytes(b)
        self.assertEqual(len(d), 0)
        self.assertEqual(all(byte == 0 for byte in b), True)

    def test_resolve_char_casting_out_of_bounds_safety(self):
        # Out-of-range codepoints (> 0x10FFFF) must degrade gracefully without crashing
        sample1 = "[char]0x120000+[char]0x41"
        res1, count1 = resolve_char_casting_and_arrays(sample1)
        self.assertEqual(res1, sample1)
        self.assertEqual(count1, 0)

        sample2 = "(-join (0x120000, 0x41|%{[char]$_}))"
        res2, count2 = resolve_char_casting_and_arrays(sample2)
        self.assertEqual(res2, sample2)
        self.assertEqual(count2, 0)

        sample3 = "[string]::Join('', (0x120000, 0x41|%{[char]$_}))"
        res3, count3 = resolve_char_casting_and_arrays(sample3)
        self.assertEqual(res3, sample3)
        self.assertEqual(count3, 0)

    def test_wirebits_normalizer_zeroize(self):
        norm = WireBitsNormalizer(custom_env={"_1": "calc", "_secret": "classified"})
        self.assertIn("_1", norm.custom_env)
        norm.zeroize()
        self.assertEqual(len(norm.custom_env), 0)

    def test_legacy_engine_zeroize_memory_hygiene(self):
        from src.deobfuscator_engine import BatchDeobfuscator as LegacyDeobfuscator
        engine = LegacyDeobfuscator()
        self.assertGreater(len(engine.env_vars), 0)
        engine.zeroize()
        self.assertEqual(len(engine.env_vars), 0)


if __name__ == "__main__":
    unittest.main()
