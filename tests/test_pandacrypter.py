#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit and Integration Tests for PandaCrypter & Certutil Stager Deobfuscator Engine.
Tests cover colon noise neutralization, Certutil -decode / -decodehex static emulation,
multi-format hex parsing, virtual file tracing, and embedded payload recovery.

Engineered by Maya Thorne.
"""

import unittest
from deobfuscator.pandacrypter import (
    PandaCrypterNormalizer,
    normalize_pandacrypter,
    detect_pandacrypter_signatures,
    detect_certutil_signatures,
    strip_pandacrypter_colon_padding,
    emulate_certutil_decode,
    emulate_certutil_decodehex,
    extract_embedded_payloads_from_comments,
    trace_virtual_staged_files,
    zeroize_bytes,
    zeroize_dict,
)
from deobfuscator.core import BatchDeobfuscator


class TestPandaCrypterEngine(unittest.TestCase):
    """Test suite for PandaCrypter and Certutil Stager Deobfuscator."""

    def test_strip_colon_padding(self):
        script = (
            "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n"
            "::: PANDACRYPTER STUB HEADER\n"
            "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n"
            ":valid_label\n"
            "echo Running payload\n"
            ":: Normal comment\n"
            "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n"
        )
        cleaned, stripped_count = strip_pandacrypter_colon_padding(script)
        self.assertGreater(stripped_count, 0)
        self.assertNotIn("::::::::::::::::::", cleaned)
        self.assertIn(":valid_label", cleaned)
        self.assertIn("echo Running payload", cleaned)

    def test_detect_certutil_signatures(self):
        raw = "c^e^r^t^u^t^i^l -decodehex %temp%\\p.hex %temp%\\p.bat"
        sig = detect_certutil_signatures(raw)
        self.assertTrue(sig["is_certutil"])
        self.assertEqual(sig["decodehex_count"], 1)
        self.assertGreaterEqual(sig["confidence"], 0.9)

    def test_detect_pandacrypter_signatures(self):
        script = (
            "::::::::::::::::::::::::::::::::::::::::::::::::::\n"
            "::: PandaCrypter evader\n"
            "::::::::::::::::::::::::::::::::::::::::::::::::::\n"
            "findstr \"^::B64:\" \"%~f0\" > \"%temp%\\p.b64\"\n"
            "certutil -decode \"%temp%\\p.b64\" \"%temp%\\run.bat\"\n"
            "call \"%temp%\\run.bat\"\n"
            "::B64:ZWNobyBQYW5kYQ=="
        )
        sig = detect_pandacrypter_signatures(script)
        self.assertTrue(sig["is_pandacrypter"])
        self.assertIn("colon_padding", sig["indicators"])
        self.assertIn("findstr_self_extraction", sig["indicators"])
        self.assertIn("certutil_decode", sig["indicators"])

    def test_emulate_certutil_decode_standard(self):
        # Base64 for 'whoami /all'
        b64 = "d2hvYW1pIC9hbGw="
        decoded = emulate_certutil_decode(b64)
        self.assertEqual(decoded.decode("utf-8"), "whoami /all")

    def test_emulate_certutil_decode_certificate_headers(self):
        b64 = (
            "-----BEGIN CERTIFICATE-----\n"
            "ZWNobyBIZWxsbyBXb3JsZA==\n"
            "-----END CERTIFICATE-----\n"
        )
        decoded = emulate_certutil_decode(b64)
        self.assertEqual(decoded.decode("utf-8"), "echo Hello World")

    def test_emulate_certutil_decode_comment_prefixed(self):
        b64 = (
            "::B64:c2V0IHZhcj10ZXN0\n"
            "::B64:ICYgZWNobyAldmFyJQ==\n"
        )
        decoded = emulate_certutil_decode(b64)
        self.assertEqual(decoded.decode("utf-8"), "set var=test & echo %var%")

    def test_emulate_certutil_decodehex_spaced_pairs(self):
        # Hex for 'cmd /c whoami'
        hex_data = "63 6d 64 20 2f 63 20 77 68 6f 61 6d 69"
        decoded = emulate_certutil_decodehex(hex_data)
        self.assertEqual(decoded.decode("utf-8"), "cmd /c whoami")

    def test_emulate_certutil_decodehex_raw_continuous(self):
        hex_data = "636d64202f632077686f616d69"
        decoded = emulate_certutil_decodehex(hex_data, format_id=4)
        self.assertEqual(decoded.decode("utf-8"), "cmd /c whoami")

    def test_emulate_certutil_decodehex_dash_separated(self):
        hex_data = "65-63-68-6F-20-6F-6B"
        decoded = emulate_certutil_decodehex(hex_data)
        self.assertEqual(decoded.decode("utf-8"), "echo ok")

    def test_emulate_certutil_decodehex_comma_0x(self):
        hex_data = "0x65, 0x63, 0x68, 0x6f, 0x20, 0x74, 0x65, 0x73, 0x74"
        decoded = emulate_certutil_decodehex(hex_data)
        self.assertEqual(decoded.decode("utf-8"), "echo test")

    def test_emulate_certutil_decodehex_address_and_ascii_dump(self):
        # Certutil format 12 dump: offset hex bytes ascii
        hex_data = (
            "0000  63 6d 64 20 2f 63 20 77  68 6f 61 6d 69          cmd /c whoami\n"
        )
        decoded = emulate_certutil_decodehex(hex_data, format_id=12)
        self.assertEqual(decoded.decode("utf-8"), "cmd /c whoami")

    def test_extract_embedded_payloads_from_comments(self):
        script = (
            "@echo off\n"
            "findstr \"^::HEX:\" \"%~f0\" > hex.txt\n"
            "exit /b\n"
            "::HEX: 48 65 6c 6c 6f\n"
            "::HEX: 20 57 6f 72 6c 64\n"
        )
        payloads = extract_embedded_payloads_from_comments(script)
        self.assertIn("hex", payloads)
        self.assertIn("48 65 6c 6c 6f", payloads["hex"])

    def test_trace_virtual_staged_files_echo(self):
        script = (
            "echo 63 6d 64 20 > \"%temp%\\payload.hex\"\n"
            "echo 2f 63 20 64 69 72 >> \"%temp%\\payload.hex\"\n"
            "certutil -decodehex \"%temp%\\payload.hex\" run.bat\n"
        )
        staged = trace_virtual_staged_files(script)
        self.assertIn("payload.hex", staged)
        self.assertIn("63 6d 64 20", staged["payload.hex"])
        self.assertIn("2f 63 20 64 69 72", staged["payload.hex"])

    def test_normalize_pandacrypter_echo_hex_pipeline(self):
        script = (
            "@echo off\n"
            "echo 63 6d 64 20 2f 63 20 77 68 6f 61 6d 69 > \"%temp%\\stager.hex\"\n"
            "certutil -decodehex \"%temp%\\stager.hex\" \"%temp%\\run.bat\"\n"
            "call \"%temp%\\run.bat\"\n"
        )
        clean, tele = normalize_pandacrypter(script)
        self.assertTrue(tele["is_certutil"])
        self.assertEqual(tele["decoded_payloads_count"], 1)
        self.assertIn("cmd /c whoami", clean)

    def test_normalize_pandacrypter_findstr_base64_pipeline(self):
        script = (
            "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n"
            "::: PANDACRYPTER STUB\n"
            "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n"
            "@echo off\n"
            "findstr \"^::B64:\" \"%~f0\" > \"%temp%\\payload.b64\"\n"
            "certutil -decode \"%temp%\\payload.b64\" \"%temp%\\out.bat\"\n"
            "call \"%temp%\\out.bat\"\n"
            "exit /b\n"
            "::B64:ZWNobyBIZWxsbyBmcm9tIFBhbmRhQ3J5cHRlcg=="
        )
        clean, tele = normalize_pandacrypter(script)
        self.assertTrue(tele["is_pandacrypter"])
        self.assertGreater(tele["colon_padding_stripped"], 0)
        self.assertEqual(tele["decoded_payloads_count"], 1)
        self.assertIn("echo Hello from PandaCrypter", clean)

    def test_emulate_binary_pe_payload(self):
        # Hex for MZ executable header: 4D 5A 90 00 03 00 00 00
        script = (
            "echo 4D 5A 90 00 03 00 00 00 > payload.hex\n"
            "certutil -decodehex payload.hex dropper.exe\n"
            "start dropper.exe\n"
        )
        clean, tele = normalize_pandacrypter(script)
        self.assertEqual(tele["decoded_payloads_count"], 1)
        payload_info = tele["decoded_payloads"][0]
        self.assertTrue(payload_info["is_pe"])
        self.assertIn("PANDACRYPTER / CERTUTIL STAGED BINARY", clean)

    def test_zeroize_memory_safety(self):
        b = bytearray(b"sensitive_certutil_payload_key")
        zeroize_bytes(b)
        self.assertEqual(b, bytearray(len(b)))

        d = {"key": "secret", "nested": {"inner": bytearray(b"data")}}
        zeroize_dict(d)
        self.assertEqual(d, {})

    def test_normalizer_oop_class(self):
        normalizer = PandaCrypterNormalizer()
        script = (
            "::::::::::::::::::::::::::::::::::::::\n"
            "echo 65 63 68 6f 20 74 65 73 74 > payload.hex\n"
            "certutil -decodehex payload.hex test.bat\n"
            "call test.bat\n"
        )
        cleaned = normalizer.normalize(script)
        tele = normalizer.get_telemetry()
        self.assertTrue(tele["is_certutil"])
        self.assertIn("echo test", cleaned)

    def test_integration_with_batch_deobfuscator(self):
        engine = BatchDeobfuscator(enable_pandacrypter=True)
        script = (
            ":::::::::::::::::::::::::::::::::::::::::::::::::\n"
            "@echo off & set var=run.bat\n"
            "echo 63 6d 64 20 2f 63 20 77 68 6f 61 6d 69 > p.hex\n"
            "certutil -decodehex p.hex %var%\n"
            "call %var%\n"
        )
        clean_text, meta = engine.deobfuscate(script)
        self.assertIn("pandacrypter_telemetry", meta)
        pt = meta["pandacrypter_telemetry"]
        self.assertTrue(pt["is_certutil"])
        self.assertIn("cmd /c whoami", clean_text)


if __name__ == "__main__":
    unittest.main()
