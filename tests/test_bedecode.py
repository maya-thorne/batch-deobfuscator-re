#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Batch-Encryption-DeCoder (BEDeCode) runtime stub unpacker and PE forensics engine.
Covers signature detection, character mapping table extraction, slicing evaluation,
environment bootstrapping, multi-layer onion unrolling, dynamic substitution,
memory zeroization, and end-to-end core deobfuscator integration.
"""

import struct
import unittest
from deobfuscator.bedecode import (
    BEDeCodeNormalizer,
    clean_bedecode_escapes,
    detect_bedecode_signatures,
    eval_batch_slice,
    eval_batch_subst,
    extract_bedecode_tables,
    inspect_bedecode_pe,
    normalize_bedecode,
    resolve_bedecode_slices,
    resolve_env_bootstrapping,
    unwrap_bedecode_inline_stub,
    zeroize_bytes,
    zeroize_dict,
    WINDOWS_BOOTSTRAP_ENV,
)
from deobfuscator.core import BatchDeobfuscator, deobfuscate_script


class TestBEDeCodeUnpacker(unittest.TestCase):
    """Test suite for BEDeCode static runtime stub unpacker."""

    def test_clean_bedecode_escapes(self):
        """Test normalization of BatchEncryption caret escape sequences."""
        raw = "abc^^def^&ghi^jkl"
        cleaned = clean_bedecode_escapes(raw)
        self.assertEqual(cleaned, "abc^def&ghijkl")

    def test_batch_slice_evaluation(self):
        """Test cmd.exe environment variable slicing expressions."""
        val = "abcdefghijklmnopqrstuvwxyz"
        # :~offset,length
        self.assertEqual(eval_batch_slice(val, ":~0,3"), "abc")
        self.assertEqual(eval_batch_slice(val, ":~2,4"), "cdef")
        # :~-length (last N characters)
        self.assertEqual(eval_batch_slice(val, ":~-3"), "xyz")
        # :~offset,-end
        self.assertEqual(eval_batch_slice(val, ":~0,-23"), "abc")
        # :~-offset,-end
        self.assertEqual(eval_batch_slice(val, ":~-5,-2"), "vwx")
        # :~-offset,length
        self.assertEqual(eval_batch_slice(val, ":~-3,2"), "xy")
        # :~offset (from offset to end)
        self.assertEqual(eval_batch_slice(val, ":~23"), "xyz")

    def test_batch_subst_evaluation(self):
        """Test cmd.exe dynamic variable replacement expressions."""
        val = "powershell -ExecutionPolicy Bypass"
        # Standard replacement
        self.assertEqual(eval_batch_subst(val, ":powershell=cmd"), "cmd -ExecutionPolicy Bypass")
        # Prefix wildcard match (*old=new replaces everything from beginning through old)
        self.assertEqual(eval_batch_subst(val, ":*ExecutionPolicy=NoProfile"), "NoProfile Bypass")
        self.assertEqual(eval_batch_subst(val, ":ExecutionPolicy=NoProfile"), "powershell -NoProfile Bypass")

    def test_env_bootstrapping(self):
        """Test resolution of bootstrap environment variables in headers."""
        snippet = "%COMSPEC:~-7,3% /c echo %SYSTEMROOT:~0,2%"
        resolved, subs = resolve_env_bootstrapping(snippet)
        self.assertGreater(subs, 0)
        self.assertIn("cmd /c echo C:", resolved)

    def test_bedecode_signature_detection(self):
        """Test detection of BEDeCode and BatchEncryption obfuscation patterns."""
        sample = "@set '=abcdefghijklmnopqrstuvwxyz&%'~2,1%%'~12,1%%'~3,1% /c whoami"
        sig = detect_bedecode_signatures(sample)
        self.assertTrue(sig["is_bedecode"])
        self.assertGreaterEqual(sig["confidence"], 0.40)
        self.assertTrue(sig["signatures"]["special_var_table"])
        self.assertTrue(sig["signatures"]["symbol_slices"])

    def test_single_layer_inline_stub_unwrapping(self):
        """Test unwrapping a single-layer BatchEncryption table stub."""
        script = (
            "@echo off\n"
            "@set '=abcdefghijklmnopqrstuvwxyz\n"
            "%'~2,1%%'~12,1%%'~3,1% /c whoami\n"
        )
        unwrapped, meta = unwrap_bedecode_inline_stub(script)
        self.assertIn("cmd /c whoami", unwrapped)
        self.assertGreaterEqual(meta["layers_unwrapped"], 1)
        self.assertGreaterEqual(meta["slices_resolved"], 3)

    def test_multi_layer_onion_stub_unwrapping(self):
        """Test unrolling nested multi-layer BatchEncryption onion layers."""
        # Layer 1 sets key '1' which decodes layer 2's key '2', which decodes payload
        script = (
            "@set '1=0123456789abcdefghijklmnopqrstuvwxyz\n"
            "@set '2=%'1:~12,1%%'1:~22,1%%'1:~13,1%\n"
            "%'2% /c whoami\n"
        )
        unwrapped, meta = unwrap_bedecode_inline_stub(script, max_layers=5)
        self.assertIn("/c whoami", unwrapped)
        self.assertGreaterEqual(meta["layers_unwrapped"], 1)

    def test_dynamic_substitution_cipher(self):
        """Test dynamic substitution cipher unwrapping (%VAR:old=new%)."""
        script = "set v=powershell & %v:powershell=cmd% /c whoami"
        engine = BatchDeobfuscator(enable_bedecode=True)
        clean, meta = engine.deobfuscate(script)
        self.assertIn("cmd /c whoami", clean)
        self.assertTrue(meta["bedecode_telemetry"]["detected"])

    def test_pe_static_stub_inspection(self):
        """Test static triage and embedded batch script extraction from PE executables."""
        # Synthesize a minimal PE binary with MSVBVM60.DLL / ThunRTMain (BEDeCode.exe signature)
        # and an embedded batch script marker
        pe_header = bytearray(b"MZ" + b"\x00" * 0x3A)
        pe_header += struct.pack("<I", 0x40)  # e_lfanew
        pe_header += b"PE\x00\x00"  # Signature
        pe_header += struct.pack("<H", 1)   # 1 section
        pe_header += b"\x00" * 12
        pe_header += struct.pack("<H", 0)   # opt hdr size
        pe_header += b"\x00" * 2
        # Section header (.text)
        pe_header += b".text\x00\x00\x00"
        pe_header += struct.pack("<IIII", 0x200, 0x1000, 0x200, 0x200)
        pe_header += b"\x00" * 16

        # Pad to section offset 0x200
        pe_body = bytearray(pe_header)
        if len(pe_body) < 0x200:
            pe_body += b"\x00" * (0x200 - len(pe_body))

        # Section payload containing VB6 imports and an embedded batch script
        section_payload = (
            b"MSVBVM60.DLL\x00ThunRTMain\x00BatchEncryption\x00"
            b"@set '=abcdefghijklmnopqrstuvwxyz&%'~2,1%%'~12,1%%'~3,1% /c whoami\x00"
        )
        pe_body += section_payload
        if len(pe_body) < 0x400:
            pe_body += b"\x00" * (0x400 - len(pe_body))

        res = inspect_bedecode_pe(bytes(pe_body))
        self.assertTrue(res["is_pe"])
        self.assertIn("VB6 Native Compiled Batch Tool", res["family"])
        self.assertTrue(res["has_embedded_script"])
        self.assertIsNotNone(res["extracted_script"])
        self.assertIn("@set '=", res["extracted_script"])

    def test_zeroize_memory_wiping(self):
        """Test cryptographic memory sanitization for extracted tables and buffers."""
        secret_dict = {"key": "supersecretpasswordtable123", "sub": "replacement"}
        zeroize_dict(secret_dict)
        self.assertEqual(len(secret_dict), 0)

        buf = bytearray(b"sensitive_stager_payload")
        zeroize_bytes(buf)
        self.assertEqual(set(buf), {0})

    def test_bedecode_normalizer_class(self):
        """Test BEDeCodeNormalizer stateful wrapper class."""
        normalizer = BEDeCodeNormalizer()
        script = "@set '=abcdefghijklmnopqrstuvwxyz\n%'~2,1%%'~12,1%%'~3,1% /c whoami"
        sig = normalizer.detect(script)
        self.assertTrue(sig["is_bedecode"])

        clean, meta = normalizer.normalize(script)
        self.assertIn("cmd /c whoami", clean)
        self.assertTrue(meta["is_bedecode"])

    def test_core_integration_with_bedecode(self):
        """Test end-to-end integration of BEDeCode in BatchDeobfuscator engine."""
        script = (
            "@echo off\n"
            "set alpha=abcdefghijklmnopqrstuvwxyz\n"
            "set a=%alpha:~2,1%\n"
            "set b=%alpha:~12,1%\n"
            "set c=%alpha:~3,1%\n"
            "@set '=whoami\n"
            "%a%%b%%c% /c %'%\n"
        )
        clean = deobfuscate_script(script, enable_bedecode=True)
        self.assertIn("cmd /c whoami", clean)


if __name__ == "__main__":
    unittest.main()
