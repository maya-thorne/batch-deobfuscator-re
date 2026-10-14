#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Verification Suite for batch-deobfuscator-re
Tests both:
  1. Multi-Pass Fixed-Point Batch Deobfuscator (src/deobfuscator_engine.py)
  2. Ghidra-based Static PE Packer Forensics & Overlay Unpacker (src/pe_packer_forensics.py)
"""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from deobfuscator_engine import BatchDeobfuscator
from pe_packer_forensics import PEBatchPackerForensics


class TestBatchDeobfuscatorEngine(unittest.TestCase):
    def setUp(self):
        self.engine = BatchDeobfuscator()

    def test_caret_and_quote_stripping(self):
        obf = 'w^h^o^a^m^i /a""l""l'
        deobf = self.engine.deobfuscate(obf)
        self.assertIn("whoami /all", deobf)

    def test_env_substring_slicing(self):
        # %ComSpec% -> C:\Windows\system32\cmd.exe
        # :~-7,3 -> cmd
        obf = "%ComSpec:~-7,3% /c echo READY"
        deobf = self.engine.deobfuscate(obf)
        self.assertIn("cmd /c echo READY", deobf)

    def test_dynamic_set_table_and_substitution(self):
        obf = "\n".join([
            "@echo off",
            "set \"_a=po\"",
            "set \"_b=wershell\"",
            "%_a%%_b% -NoProfile",
        ])
        deobf = self.engine.deobfuscate(obf)
        self.assertIn("powershell -NoProfile", deobf)

    def test_xorpacker_overlay_decryption(self):
        stub = b"MZ" + b"\x00" * 256 + b"randomkey" + b"\x00" * 64
        dyn_key = b"K9x7Qp2M"
        master_key = PEBatchPackerForensics.DEFAULT_XOR_MASTER_KEY
        plaintext_payload = b"@echo off\r\necho DECRYPTED_OK\r\n"
        enc_payload = PEBatchPackerForensics.xor_bytes(plaintext_payload, dyn_key)
        enc_key = PEBatchPackerForensics.xor_bytes(dyn_key, master_key)
        synthetic_pe = stub + b"***" + enc_payload + b"***" + enc_key

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            tf.write(synthetic_pe)
            tmp_path = Path(tf.name)

        try:
            forensics = PEBatchPackerForensics(tmp_path)
            info = forensics.detect_packer_family()
            self.assertIn("xorPacker", info["family"])
            res = forensics.decrypt_xorpacker_overlay()
            self.assertIsNotNone(res)
            self.assertEqual(res["dynamic_key"], "K9x7Qp2M")
            self.assertIn("DECRYPTED_OK", res["decrypted_preview"])
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_core_zeroize_buffers(self):
        from deobfuscator.core import BatchDeobfuscator as CoreDeobf, zeroize_dict, zeroize_bytes
        engine = CoreDeobf()
        engine.env_vars["secret_token"] = "SensitiveBatchKey123"
        engine.pass_history.append({"pass": 1, "delta": 10})
        self.assertIn("secret_token", engine.env_vars)
        engine.zeroize()
        self.assertEqual(len(engine.env_vars), 0)
        self.assertEqual(len(engine.pass_history), 0)

        # Test zeroize_dict & zeroize_bytes standalone
        b = bytearray(b"HighlySensitiveKeyData")
        zeroize_bytes(b)
        self.assertEqual(b, bytearray(len(b)))

        d = {"sub": {"key": "val"}, "buf": bytearray(b"test"), "lst": [1, 2, 3]}
        zeroize_dict(d)
        self.assertEqual(d, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
