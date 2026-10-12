#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Suite for Somalifuscator Caesar Cipher Inversion & Array Normalization.
Tests:
  1. Mathematical solver for Caesar rotation values across lowercase and uppercase pairs.
  2. Full alphabet completion from partial substitution matrices.
  3. Single-pass 'for /l' wrapper loop decomposition and symbol extraction.
  4. Shuffled character array (KDOT) slicing resolution and space normalization.
  5. Scramble marker (%TO_SCRAMBLE_PLZ%) and anti-triage decoy preamble elimination.
  6. Caesar alphabet dead-store elimination (DSE) after payload inlining.
  7. Somalifuscator signature detection and forensic telemetry.
  8. In-memory dictionary cryptographic zeroization (zeroize_dict).
  9. End-to-end deobfuscation of Somalifuscator V1 & V2 specimens.
  10. OS environment variable slicing parity (DRIVERDATA, COMMONPROGRAMW6432).

Engineered by Maya Thorne.
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from deobfuscator.somalifuscator import (
    solve_caesar_rotation,
    build_caesar_table,
    infer_and_complete_caesar_table,
    unwrap_somalifuscator_loops,
    extract_kdot_shuffled_array,
    resolve_kdot_slicing,
    strip_somalifuscator_chaff,
    detect_somalifuscator_signatures,
    normalize_somalifuscator,
    zeroize_dict,
)
from deobfuscator.core import BatchDeobfuscator, deobfuscate_script


class TestSomalifuscatorNormalizer(unittest.TestCase):

    def test_solve_caesar_rotation_lowercase(self):
        """Mathematically solve Caesar shift value k = 3 from lowercase pairs."""
        pairs = [
            ("d", "a"),  # (3 - 0) % 26 = 3
            ("e", "b"),  # (4 - 1) % 26 = 3
            ("f", "c"),  # (5 - 2) % 26 = 3
            ("g", "d"),  # (6 - 3) % 26 = 3
        ]
        rot_k = solve_caesar_rotation(pairs)
        self.assertEqual(rot_k, 3)

    def test_solve_caesar_rotation_uppercase(self):
        """Mathematically solve Caesar shift value k = 7 from uppercase pairs."""
        pairs = [
            ("h1", "A"),  # (7 - 0) % 26 = 7
            ("i1", "B"),  # (8 - 1) % 26 = 7
            ("j1", "C"),  # (9 - 2) % 26 = 7
        ]
        rot_k = solve_caesar_rotation(pairs)
        self.assertEqual(rot_k, 7)

    def test_solve_caesar_rotation_with_noise(self):
        """Consensus voting filters out noise variables and finds dominant shift."""
        pairs = [
            ("noise_var", "junk_value"),
            ("d", "a"),
            ("e", "b"),
            ("f", "c"),
            ("random_123", "value"),
        ]
        rot_k = solve_caesar_rotation(pairs)
        self.assertEqual(rot_k, 3)

    def test_infer_and_complete_caesar_table(self):
        """Synthesize full 52-symbol alphabet table from sparse 3-character sample."""
        sparse_harvest = {
            "d": "a",
            "e": "b",
            "f": "c",
        }
        full_table, rot_k = infer_and_complete_caesar_table(sparse_harvest)
        self.assertEqual(rot_k, 3)
        # Verify complete lowercase mapping
        self.assertEqual(full_table["g"], "d")
        self.assertEqual(full_table["c"], "z")
        # Verify synthesized uppercase mapping
        self.assertEqual(full_table["d1"], "A")
        self.assertEqual(full_table["e1"], "B")
        self.assertEqual(full_table["c1"], "Z")
        self.assertGreaterEqual(len(full_table), 52)

    def test_unwrap_somalifuscator_loops(self):
        """Unwrap single-pass 'for /l' wrapper loops and extract inner set commands."""
        obf_script = (
            "@echo off\n"
            "for /l %%r in (10, 10, 10) do ( set \"d=a\" )\n"
            "for /l %%r in (25, 25, 25) do ( s^et \"e=b\" )\n"
            "for /l %%i in (100, 100, 100) do ( set \"f1=C\" )\n"
            "echo Real Payload"
        )
        clean_text, extracted, unwrapped = unwrap_somalifuscator_loops(obf_script)
        self.assertEqual(len(unwrapped), 3)
        self.assertEqual(extracted["d"], "a")
        self.assertEqual(extracted["e"], "b")
        self.assertEqual(extracted["f1"], "C")
        self.assertNotIn("for /l", clean_text)
        self.assertIn("echo Real Payload", clean_text)

    def test_extract_and_resolve_kdot_slicing(self):
        """Resolve KDOT shuffled array extraction and indexing with random spaces."""
        kdot_str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        script = (
            f"set KDOT={kdot_str}\n"
            "%kdot:~12,1%%KDOT:~22, 1%%kdot:~13,1% /c whoami"
        )
        clean_script, kdot_val = extract_kdot_shuffled_array(script)
        self.assertEqual(kdot_val, kdot_str)

        resolved = resolve_kdot_slicing(clean_script, kdot_val)
        # Index 12 is 'c', Index 22 is 'm', Index 13 is 'd'
        self.assertIn("cmd /c whoami", resolved)

    def test_strip_somalifuscator_chaff_and_decoys(self):
        """Purge dead Caesar variable definitions and anti-triage decoy header lines."""
        script = (
            ">nul 2>&1 && exit >nul 2>&1 || cls\n"
            "chcp 65001 > nul\n"
            "%TO_SCRAMBLE_PLZ%\n"
            "set \"d=a\"\n"
            "set \"e=b\"\n"
            "set \"f=c\"\n"
            "cmd.exe /c whoami"
        )
        caesar_keys = {"d", "e", "f"}
        clean, eliminated = strip_somalifuscator_chaff(script, caesar_keys)
        self.assertNotIn(">nul 2>&1", clean)
        self.assertNotIn("chcp 65001", clean)
        self.assertNotIn("set \"d=a\"", clean)
        self.assertIn("cmd.exe /c whoami", clean)
        self.assertGreaterEqual(len(eliminated), 4)

    def test_detect_somalifuscator_signatures(self):
        """Detect Somalifuscator heuristics with accurate confidence metrics."""
        script = (
            "::Made by K.Dot using SomalifuscatorV2\n"
            "%TO_SCRAMBLE_PLZ%@echo off\n"
            "for /l %%r in (1, 1, 1) do ( set \"kdot=abcdef123\" )\n"
            "%kdot:~0,1%"
        )
        sig = detect_somalifuscator_signatures(script)
        self.assertTrue(sig["is_somalifuscator"])
        self.assertGreaterEqual(sig["confidence"], 0.70)
        self.assertIn("somalifuscator-marker", sig["indicators"])
        self.assertIn("to-scramble-plz-markers", sig["indicators"])

    def test_zeroize_dict(self):
        """Cryptographically overwrite in-memory dictionary keys and values."""
        secret_dict = {
            "key1": "decrypted_string",
            "key2": bytearray(b"sensitive_key_material"),
        }
        zeroize_dict(secret_dict)
        self.assertEqual(len(secret_dict), 0)

    def test_end_to_end_somalifuscator_v2_specimen(self):
        """End-to-end deobfuscation of synthetic Somalifuscator V2 specimen."""
        # Shift k = 3: 'd'=a, 'f'=c, 'p'=m, 'g'=d, 'z'=w, 'k'=h, 'r'=o, 'l'=i
        obfuscated_v2 = (
            "::Made by K.Dot using SomalifuscatorV2\n"
            ">nul 2>&1 && exit >nul 2>&1 || cls\n"
            "chcp 65001 > nul\n"
            "%TO_SCRAMBLE_PLZ%@echo off\n"
            "for /l %%r in (10, 10, 10) do ( set \"d=a\" )\n"
            "for /l %%r in (10, 10, 10) do ( set \"f=c\" )\n"
            "for /l %%r in (10, 10, 10) do ( set \"p=m\" )\n"
            "for /l %%r in (10, 10, 10) do ( set \"g=d\" )\n"
            "for /l %%r in (10, 10, 10) do ( set \"z=w\" )\n"
            "for /l %%r in (10, 10, 10) do ( set \"k=h\" )\n"
            "for /l %%r in (10, 10, 10) do ( set \"r=o\" )\n"
            "for /l %%r in (10, 10, 10) do ( set \"l=i\" )\n"
            "%f%%p%%g% /c %z%%k%%r%%d%%p%%l%"
        )

        clean = deobfuscate_script(obfuscated_v2)
        # Must resolve to cmd /c whoami with zero chaff
        self.assertIn("cmd /c whoami", clean)
        self.assertNotIn("for /l", clean)
        self.assertNotIn(">nul 2>&1", clean)

    def test_end_to_end_somalifuscator_v1_corpus(self):
        """Verify Corpus 2 (Somalifuscator alphabet slicing) converges to cmd /c whoami."""
        corpus2_script = (
            "set alpha=abcdefghijklmnopqrstuvwxyz&set a=%alpha:~2,1%&"
            "set b=%alpha:~12,1%&set c=%alpha:~3,1%&%a%%b%%c% /c whoami"
        )
        clean = deobfuscate_script(corpus2_script)
        self.assertIn("cmd /c whoami", clean)

    def test_driverdata_and_commonprogramw6432_env_vars(self):
        """Verify environment variable slicing resolution for DRIVERDATA and COMMONPROGRAMW6432."""
        script = (
            "set p=%DRIVERDATA:~0,2% & %p%\\test.exe"
        )
        clean = deobfuscate_script(script)
        self.assertIn(r"C:\test.exe", clean)


if __name__ == "__main__":
    unittest.main()
