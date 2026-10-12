#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Suite for BatCloak Normalization & Malformed Header Preprocessing.
Tests:
  1. BatCloak fake UTF-16LE BOM header neutralization (0xFF 0xFE &cls\\r\\n).
  2. machine1337 double BOM trap de-masking.
  3. Statistical separation of genuine UTF-16LE from 8-bit fake BOM payloads.
  4. Dynamic %RANDOM% variable noise pruning and empty chaff elimination.
  5. Dead Store Elimination (DSE) on unreferenced stager variables.
  6. End-to-end deobfuscation of BatCloak stager archetype.
  7. Secure forensic buffer zeroization (zeroize_bytes).

Engineered by Maya Thorne.
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from deobfuscator.batcloak import (
    normalize_batcloak_headers,
    is_genuine_utf16le,
    is_genuine_utf16be,
    strip_batcloak_random_vars,
    eliminate_dead_stores,
    detect_batcloak_signatures,
    BatCloakNormalizer,
    zeroize_bytes,
)
from deobfuscator.core import BatchDeobfuscator, deobfuscate_script, deobfuscate_bytes


class TestBatCloakNormalizer(unittest.TestCase):

    def test_fake_bom_batcloak_cls_header(self):
        """Neutralize classic BatCloak 0xFF 0xFE &cls\\r\\n header trap."""
        fake_header = b"\xff\xfe\x26\x63\x6c\x73\x0d\x0a"
        body = b"@echo off\r\nset target=calc.exe\r\n%target%"
        raw_payload = fake_header + body

        clean_text, meta = normalize_batcloak_headers(raw_payload)
        self.assertTrue(meta["fake_bom_detected"])
        self.assertEqual(meta["header_pattern"], "batcloak-bom-cls")
        self.assertEqual(meta["stripped_header_bytes"], 8)
        self.assertIn("@echo off", clean_text)
        self.assertIn("calc.exe", clean_text)
        # Ensure no Chinese glyph corruption occurred
        self.assertNotIn("\u6326", clean_text)

    def test_machine1337_double_bom_trap(self):
        """Neutralize machine1337 double BOM header trap."""
        trap_header = b"\xff\xfe\x26\x63\x6c\x73\x0d\x0a\xff\xfe\x0a\x0d"
        body = b"powershell -NoProfile -ExecutionPolicy Bypass -Command Write-Host PWNED"
        raw_payload = trap_header + body

        clean_text, meta = normalize_batcloak_headers(raw_payload)
        self.assertTrue(meta["fake_bom_detected"])
        self.assertEqual(meta["header_pattern"], "machine1337-double-bom")
        self.assertEqual(meta["stripped_header_bytes"], 12)
        self.assertIn("powershell -NoProfile", clean_text)
        self.assertIn("PWNED", clean_text)

    def test_genuine_utf16le_preservation(self):
        """Verify genuine UTF-16LE scripts with alternating null bytes are correctly preserved."""
        script_str = "@echo off\r\necho GENUINE_UTF16\r\n"
        # Encode as true UTF-16LE with BOM
        genuine_bytes = b"\xff\xfe" + script_str.encode("utf-16le")

        self.assertTrue(is_genuine_utf16le(genuine_bytes))
        clean_text, meta = normalize_batcloak_headers(genuine_bytes)
        self.assertFalse(meta["fake_bom_detected"])
        self.assertEqual(meta["encoding_used"], "utf-16le")
        self.assertIn("GENUINE_UTF16", clean_text)

    def test_genuine_utf16be_preservation(self):
        """Verify genuine UTF-16BE scripts are correctly detected and decoded."""
        script_str = "@echo off\r\necho GENUINE_BE\r\n"
        genuine_bytes = b"\xfe\xff" + script_str.encode("utf-16be")

        self.assertTrue(is_genuine_utf16be(genuine_bytes))
        clean_text, meta = normalize_batcloak_headers(genuine_bytes)
        self.assertFalse(meta["fake_bom_detected"])
        self.assertEqual(meta["encoding_used"], "utf-16be")
        self.assertIn("GENUINE_BE", clean_text)

    def test_strip_batcloak_random_vars(self):
        """Strip dynamic %RANDOM% noise assignments and randomized dummy variables."""
        script = "\n".join([
            "@echo off",
            "set %RANDOM%_junk=",
            "set %RANDOM%=59218",
            "set dummy_%RANDOM%_seed=noise",
            "set _0x3f2a=whoami",
            "set n_1849182390123=",
            "%_0x3f2a% /all",
        ])

        clean, removed = strip_batcloak_random_vars(script)
        self.assertGreaterEqual(len(removed), 3)
        self.assertNotIn("%RANDOM%_junk", clean)
        self.assertNotIn("%RANDOM%=", clean)
        self.assertNotIn("dummy_%RANDOM%", clean)
        self.assertIn("%_0x3f2a% /all", clean)

    def test_dead_store_elimination(self):
        """Eliminate unreferenced dummy variables without side effects."""
        script = "\n".join([
            "@echo off",
            "set unused_var1=junk_value_1",
            "set unused_var2=junk_value_2",
            "set real_cmd=calc.exe",
            "%real_cmd%",
        ])

        clean, eliminated = eliminate_dead_stores(script)
        self.assertIn("unused_var1", eliminated)
        self.assertIn("unused_var2", eliminated)
        self.assertNotIn("unused_var1", clean)
        self.assertNotIn("unused_var2", clean)
        self.assertIn("calc.exe", clean)

    def test_dead_store_preserves_side_effects(self):
        """Ensure interactive set /p and arithmetic set /a are never stripped."""
        script = "\n".join([
            "set /p user_input=Enter name: ",
            "set /a counter=1+1",
            "echo Done",
        ])

        clean, eliminated = eliminate_dead_stores(script)
        self.assertEqual(len(eliminated), 0)
        self.assertIn("set /p user_input", clean)
        self.assertIn("set /a counter", clean)

    def test_detect_batcloak_signatures(self):
        """Identify BatCloak signature indicators and compute confidence."""
        raw = b"\xff\xfe\x26\x63\x6c\x73\x0d\x0a"
        text = "@echo off & set %RANDOM%_junk= & set _0x1a2b=cmd & set _0x3c4d=powershell & powershell -enc AAAA"

        sig = detect_batcloak_signatures(raw, text)
        self.assertTrue(sig["is_batcloak_family"])
        self.assertGreaterEqual(sig["confidence"], 0.70)
        self.assertIn("batcloak-bom-cls-header", sig["indicators"])
        self.assertIn("random-variable-injection", sig["indicators"])

    def test_batcloak_end_to_end_deobfuscation(self):
        """Test full multi-pass BatCloak corpus deobfuscation."""
        corpus = "@echo off & set %RANDOM%_junk= & set real=powershell -NoProfile -enc & %real%"
        engine = BatchDeobfuscator(enable_batcloak=True, eliminate_dead_code=True)
        clean, meta = engine.deobfuscate(corpus)

        self.assertIn("powershell -NoProfile -enc", clean)
        self.assertNotIn("%RANDOM%", clean)
        self.assertTrue(meta["converged"])
        self.assertIn("batcloak_telemetry", meta)
        self.assertTrue(meta["batcloak_telemetry"]["detected"])

    def test_deobfuscate_bytes_with_fake_header(self):
        """Test raw byte deobfuscation helper with BatCloak header trap."""
        payload_bytes = (
            b"\xff\xfe\x26\x63\x6c\x73\x0d\x0a"
            b"@echo off & set %RANDOM%_junk= & set exec=whoami & %exec% /all"
        )

        clean, meta = deobfuscate_bytes(payload_bytes)
        self.assertIn("whoami /all", clean)
        self.assertNotIn("%RANDOM%", clean)
        self.assertTrue(meta["header_metadata"]["fake_bom_detected"])
        self.assertEqual(meta["header_metadata"]["header_pattern"], "batcloak-bom-cls")

    def test_zeroize_bytes_memory_wipe(self):
        """Verify byte buffer memory wiping leaves zero remnant bytes."""
        secret = bytearray(b"SENSITIVE_KEY_DECRYPT_BUFFER_1234")
        self.assertNotEqual(secret, bytearray(len(secret)))
        zeroize_bytes(secret)
        self.assertEqual(secret, bytearray(len(secret)))
        self.assertTrue(all(b == 0 for b in secret))


if __name__ == "__main__":
    unittest.main(verbosity=2)
