#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for BatchToApp / DosX native wrapper embedded batch extraction and deobfuscation engine.
Covers signature detection, noise variable slicing neutralization, mutation block unwrapping,
operator table resolution, fake label pruning, header normalization, PE inspection,
resource Deflate decompression, memory zeroization, and end-to-end integration.
"""

import struct
import unittest
import zlib
from typing import Dict, Any

from deobfuscator.batchtoapp import (
    BatchToAppNormalizer,
    decompress_deflate_stream,
    detect_batchtoapp_signatures,
    extract_embedded_batch_from_pe,
    inspect_batchtoapp_pe,
    normalize_batchtoapp,
    normalize_batchtoapp_headers,
    prune_batchtoapp_fake_labels,
    resolve_batchtoapp_operators,
    score_candidate_script,
    strip_batchtoapp_mutation_block,
    strip_batchtoapp_noise_slices,
    zeroize_bytes,
    zeroize_dict,
)
from deobfuscator.core import BatchDeobfuscator, deobfuscate_script, deobfuscate_bytes


def create_minimal_pe(resource_payload: bytes, app_id: str = "deadbeef") -> bytes:
    """
    Constructs a minimal valid PE32 byte structure containing CLR header
    and Deflate-compressed BatchToApp resource for unit testing.
    """
    # DOS Header (64 bytes)
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    # e_lfanew at 0x3C points to 0x80
    struct.pack_into("<I", dos_header, 0x3C, 0x80)

    # Padding up to 0x80
    pre_pe = dos_header + bytes(0x80 - len(dos_header))

    # PE Signature
    pe_sig = b"PE\x00\x00"

    # COFF File Header (20 bytes)
    # Machine: 0x014C (x86), NumSections: 1, OptHdrSize: 224 (0xE0)
    coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102)

    # Optional Header PE32 (224 bytes)
    # Magic: 0x10B (PE32)
    opt_header = bytearray(224)
    struct.pack_into("<H", opt_header, 0, 0x10B)
    # Number of RvaAndSizes = 16
    struct.pack_into("<I", opt_header, 92, 16)

    # DataDirectory[14] is CLR Runtime Header (offset 96 + 14 * 8 = 208)
    clr_rva = 0x2000
    clr_size = 72
    struct.pack_into("<II", opt_header, 208, clr_rva, clr_size)

    # Section Header (.text, 40 bytes)
    sec_vsize = 0x3000
    sec_vaddr = 0x2000
    sec_rsize = 0x1000
    sec_rptr = 0x400  # File offset 0x400
    sec_header = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        sec_vsize,
        sec_vaddr,
        sec_rsize,
        sec_rptr,
        0, 0, 0, 0,
        0x60000020
    )

    headers = pre_pe + pe_sig + coff_header + bytes(opt_header) + sec_header
    # Pad headers up to sec_rptr (0x400)
    pe_bytes = bytearray(headers + bytes(sec_rptr - len(headers)))

    # Construct Section Data at offset 0x400 (RVA 0x2000)
    sec_data = bytearray(sec_rsize)

    # CLR Header at RVA 0x2000 (offset 0 inside sec_data)
    # IMAGE_COR20_HEADER:
    # offset 0: cb (4 bytes) = 72
    # offset 8: MetaData Directory (RVA, Size)
    # offset 24: Resources Directory (RVA: 0x2100, Size: len(resource_payload) + 4)
    res_rva = 0x2100
    res_size = len(resource_payload) + 4
    struct.pack_into("<I", sec_data, 0, 72)
    struct.pack_into("<II", sec_data, 24, res_rva, res_size)

    # Resource Blob at RVA 0x2100 (offset 0x100 inside sec_data)
    res_offset_in_sec = 0x100
    struct.pack_into("<I", sec_data, res_offset_in_sec, len(resource_payload))
    sec_data[res_offset_in_sec + 4:res_offset_in_sec + 4 + len(resource_payload)] = resource_payload

    # Add BatchToApp watermark strings in section data for inspection verification
    watermarks = (
        b"GeneratedWithBatchToApp\x00"
        b"embeddedBatchScript\x00"
        b"_CorExeMain\x00"
        b"DeflateStream\x00"
        b"CreateNoWindow = false\x00"
        b"FileAttributes.System\x00"
        + f"b2a.testapp.{app_id}.cmd\x00".encode("ascii")
    )
    sec_data[res_offset_in_sec + 4 + len(resource_payload) + 16:res_offset_in_sec + 4 + len(resource_payload) + 16 + len(watermarks)] = watermarks

    return bytes(pe_bytes + sec_data)


class TestBatchToAppEngine(unittest.TestCase):
    """Test suite for BatchToApp / DosX deobfuscator and PE forensics extractor."""

    def test_decompress_deflate_stream(self):
        """Test decompression of raw Deflate (RFC 1951) matching .NET DeflateStream."""
        original = b"@shift /0\r\necho Hello from BatchToApp\r\n:b2a_ExitProcess"
        compressor = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
        raw_deflate = compressor.compress(original) + compressor.flush()

        decompressed = decompress_deflate_stream(raw_deflate)
        self.assertEqual(decompressed, original)

    def test_strip_batchtoapp_noise_slices_single(self):
        """Test stripping character noise slicing ^c%PATH:~40000,-40000%."""
        obfuscated = "^c%path:~45123,-51234%^m%temp:~41234,-41234%^d%windir:~48921,-48921% /c whoami"
        cleaned, count = strip_batchtoapp_noise_slices(obfuscated)
        self.assertEqual(cleaned, "cmd /c whoami")
        self.assertGreaterEqual(count, 3)

    def test_strip_batchtoapp_noise_slices_with_newlines(self):
        """Test joining inline caret line continuations inside tokens."""
        obfuscated = "^\r\n^c%path:~50000,-50000%^\r\n^m%path:~50000,-50000%^\r\n^d%path:~50000,-50000% dir"
        cleaned, count = strip_batchtoapp_noise_slices(obfuscated)
        self.assertEqual(cleaned, "cmd dir")
        self.assertGreaterEqual(count, 3)

    def test_strip_batchtoapp_mutation_block(self):
        """Test detecting and stripping dead mutation blocks and binary junk preambles."""
        script = (
            "@goto label_0x1a2b3c4d\r\n"
            "\x81\x92\xa3\xb4\xc5\xd6\xe7\xf8\r\n"
            "@exit /b 127\r\n"
            ":label_0x1a2b3c4d\r\n\r\n"
            "echo Target executed"
        )
        cleaned, stripped = strip_batchtoapp_mutation_block(script)
        self.assertTrue(stripped)
        self.assertNotIn("label_0x1a2b3c4d", cleaned)
        self.assertNotIn("@exit /b", cleaned)
        self.assertIn("echo Target executed", cleaned)

    def test_resolve_batchtoapp_operators(self):
        """Test harvesting and resolving operator maps and closing bracket variable."""
        script = (
            "@set IlIIlllIIllII=^)\n"
            "%guard% @set IIllIIlIlIll=^\n"
            "echo\n"
            "%guard% @set lIIllIlIIllI=^\n"
            "if\n"
            "%IIllIIlIlIll% Hello World\n"
            "%lIIllIlIIllI% 1==1 (\n"
            "    %IIllIIlIlIll% inside block\n"
            "%IlIIlllIIllII%\n"
        )
        cleaned, meta = resolve_batchtoapp_operators(script)
        self.assertEqual(meta["operators_resolved"], 2)
        self.assertEqual(meta["closing_bracket_var"], "IlIIlllIIllII")
        self.assertIn("echo Hello World", cleaned)
        self.assertIn("if 1==1 (", cleaned)
        self.assertIn("inside block\n)", cleaned)
        self.assertNotIn("%guard%", cleaned)
        self.assertNotIn("@set IlIIlllIIllII", cleaned)

    def test_prune_batchtoapp_fake_labels(self):
        """Test pruning unreferenced fake labels while preserving referenced real labels."""
        script = (
            "goto :label_0xaaaaaaaa\n"
            ":label_0x11111111\n"
            ":label_0x22222222\n"
            ":label_0xaaaaaaaa\n"
            "echo Target reached\n"
            ":label_0x33333333\n"
            "goto :eof\n"
        )
        cleaned, pruned = prune_batchtoapp_fake_labels(script)
        self.assertEqual(pruned, 3)
        self.assertIn(":label_0xaaaaaaaa", cleaned)
        self.assertNotIn(":label_0x11111111", cleaned)
        self.assertNotIn(":label_0x22222222", cleaned)
        self.assertNotIn(":label_0x33333333", cleaned)

    def test_normalize_batchtoapp_headers(self):
        """Test stripping @shift /0 wrapper header and :b2a_ExitProcess exit label."""
        script = (
            "@shift /0\n"
            "echo core payload\n"
            ":b2a_ExitProcess\n"
        )
        cleaned, meta = normalize_batchtoapp_headers(script)
        self.assertTrue(meta["header_shift_removed"])
        self.assertTrue(meta["exit_label_removed"])
        self.assertEqual(cleaned, "echo core payload")

    def test_detect_batchtoapp_signatures_positive(self):
        """Test signature detection on a synthetic BatchToApp obfuscated script."""
        script = (
            "@shift /0\n"
            "@goto label_0x12345678\n"
            "junk\n"
            "@exit /b 1\n"
            ":label_0x12345678\n"
            "@set IlIlIl=^)\n"
            "^e%path:~40000,-40000%^c%temp:~40000,-40000%^h%windir:~40000,-40000%^o%appdata:~40000,-40000% test\n"
            ":label_0x99999999\n"
            ":b2a_ExitProcess\n"
        )
        sig = detect_batchtoapp_signatures(script)
        self.assertTrue(sig["is_batchtoapp"])
        self.assertGreaterEqual(sig["confidence"], 0.60)
        self.assertTrue(sig["signatures"]["wrapper_header"])
        self.assertTrue(sig["signatures"]["wrapper_exit_label"])
        self.assertTrue(sig["signatures"]["mutation_block"])
        self.assertTrue(sig["signatures"]["closing_bracket_var"])
        self.assertTrue(sig["signatures"]["fake_labels"])

    def test_detect_batchtoapp_signatures_negative(self):
        """Test signature detection on standard unobfuscated batch scripts."""
        script = "@echo off\nset foo=bar\necho %foo%\npause"
        sig = detect_batchtoapp_signatures(script)
        self.assertFalse(sig["is_batchtoapp"])
        self.assertLess(sig["confidence"], 0.20)

    def test_inspect_batchtoapp_pe_non_pe(self):
        """Test PE triage returns is_pe=False on arbitrary bytes."""
        non_pe = b"Hello, this is definitely not a PE binary!"
        info = inspect_batchtoapp_pe(non_pe)
        self.assertFalse(info["is_pe"])
        self.assertFalse(info["is_batchtoapp"])
        self.assertEqual(info["confidence"], 0.0)

    def test_inspect_batchtoapp_pe_synthetic(self):
        """Test PE inspection and embedded batch extraction on a synthetic BatchToApp PE."""
        embedded_script = b"@shift /0\r\necho embedded payload\r\n:b2a_ExitProcess"
        compressor = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
        compressed = compressor.compress(embedded_script) + compressor.flush()

        pe_bytes = create_minimal_pe(compressed, app_id="c0ffee01")
        info = inspect_batchtoapp_pe(pe_bytes)

        self.assertTrue(info["is_pe"])
        self.assertTrue(info["is_batchtoapp"])
        self.assertGreaterEqual(info["confidence"], 0.80)
        self.assertEqual(info["app_id"], "c0ffee01")
        self.assertTrue(info["has_embedded_script"])
        self.assertIn("echo embedded payload", info["extracted_script"])

    def test_memory_zeroization(self):
        """Test zeroize_dict and zeroize_bytes sanitize memory buffers."""
        buf = bytearray(b"secret payload data")
        zeroize_bytes(buf)
        self.assertEqual(buf, bytearray(len(buf)))

        d = {"key": "secret string", "data": bytearray(b"bytes")}
        zeroize_dict(d)
        self.assertEqual(len(d), 0)

    def test_normalizer_class_interface(self):
        """Test BatchToAppNormalizer object-oriented API methods."""
        normalizer = BatchToAppNormalizer()
        raw_script = (
            "@shift /0\n"
            "^e%path:~40000,-40000%^c%path:~40000,-40000%^h%path:~40000,-40000%^o%path:~40000,-40000% test\n"
            ":b2a_ExitProcess\n"
        )
        sig = normalizer.detect(raw_script)
        self.assertTrue(sig["is_batchtoapp"])

        clean, meta = normalizer.normalize(raw_script)
        self.assertIn("echo test", clean)
        self.assertTrue(meta["detected"])
        self.assertGreaterEqual(meta["noise_slices_stripped"], 4)

    def test_end_to_end_core_integration(self):
        """Test end-to-end deobfuscation through BatchDeobfuscator and deobfuscate_script."""
        obfuscated = (
            "@shift /0\n"
            "@goto label_0xdeadbeef\n"
            "\x90\x91\x92\x93\n"
            "@exit /b 255\n"
            ":label_0xdeadbeef\n"
            "@set IlIlIlIlIlIlIlIl=^)\n"
            "%guard% @set IIlIIllIlIIllIIl=^\n"
            "echo\n"
            "%guard% @set lIIlIIllIlIIllII=^\n"
            "set\n"
            "%IIlIIllIlIIllIIl% Starting Payload\n"
            "%lIIlIIllIlIIllII% secret=p@ssword\n"
            ":label_0x00010001\n"
            ":label_0x00020002\n"
            "%IIlIIllIlIIllIIl% Token is %secret%\n"
            ":b2a_ExitProcess\n"
        )

        clean = deobfuscate_script(obfuscated)
        self.assertIn("echo Starting Payload", clean)
        self.assertIn("echo Token is p@ssword", clean)
        self.assertNotIn("label_0x", clean)
        self.assertNotIn(":b2a_ExitProcess", clean)
        self.assertNotIn("@shift /0", clean)
        self.assertNotIn("@exit /b", clean)

    def test_deobfuscate_bytes_pe_integration(self):
        """Test deobfuscate_bytes detects and extracts BatchToApp PE executables."""
        embedded = b"@shift /0\r\nset _cmd=calc.exe\r\nstart %_cmd%\r\n:b2a_ExitProcess"
        compressor = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
        compressed = compressor.compress(embedded) + compressor.flush()

        pe_bytes = create_minimal_pe(compressed, app_id="a1b2c3d4")
        clean_text, meta = deobfuscate_bytes(pe_bytes)

        self.assertIn("start calc.exe", clean_text)
        self.assertNotIn(":b2a_ExitProcess", clean_text)
        self.assertIn("batchtoapp_telemetry", meta)

    def test_detect_batchtoapp_signatures_crlf(self):
        """Test signature detection on Windows standard CRLF (\r\n) obfuscated script."""
        script = (
            "@shift /0\r\n"
            "@goto label_0x12345678\r\n"
            "binary_junk_data\r\n"
            "@exit /b 1\r\n"
            ":label_0x12345678\r\n"
            "@set IlIlIl=^)\r\n"
            "^e%path:~40000,-40000%^c%temp:~40000,-40000%^h%windir:~40000,-40000%^o%appdata:~40000,-40000% test\r\n"
            ":label_0x99999999\r\n"
            ":b2a_ExitProcess\r\n"
        )
        sig = detect_batchtoapp_signatures(script)
        self.assertTrue(sig["is_batchtoapp"])
        self.assertTrue(sig["signatures"]["wrapper_header"])
        self.assertTrue(sig["signatures"]["wrapper_exit_label"])
        self.assertTrue(sig["signatures"]["noise_slicing"])
        self.assertTrue(sig["signatures"]["mutation_block"])
        self.assertTrue(sig["signatures"]["closing_bracket_var"])
        self.assertTrue(sig["signatures"]["fake_labels"])

    def test_prune_batchtoapp_fake_labels_syntax_variants(self):
        """Test fake label pruning preserves targets across cmd.exe call/goto syntax variations."""
        script = (
            "goto:label_0xaaaaaaaa\n"
            "goto : label_0xbbbbbbbb\n"
            "call(:label_0xcccccccc)\n"
            "call (:label_0xdddddddd)\n"
            "call : label_0xeeeeeeee\n"
            ":label_0x11111111\n"
            ":label_0xaaaaaaaa\n"
            "echo Target A\n"
            ":label_0xbbbbbbbb\n"
            "echo Target B\n"
            ":label_0xcccccccc\n"
            "echo Target C\n"
            ":label_0xdddddddd\n"
            "echo Target D\n"
            ":label_0xeeeeeeee\n"
            "echo Target E\n"
            ":label_0x22222222\n"
        )
        cleaned, pruned = prune_batchtoapp_fake_labels(script)
        self.assertEqual(pruned, 2)
        self.assertIn(":label_0xaaaaaaaa", cleaned)
        self.assertIn(":label_0xbbbbbbbb", cleaned)
        self.assertIn(":label_0xcccccccc", cleaned)
        self.assertIn(":label_0xdddddddd", cleaned)
        self.assertIn(":label_0xeeeeeeee", cleaned)
        self.assertNotIn(":label_0x11111111", cleaned)
        self.assertNotIn(":label_0x22222222", cleaned)

    def test_normalize_batchtoapp_headers_with_trailing_lines(self):
        """Test stripping exit label when followed by comments, fake labels, and blank lines."""
        script = (
            "@shift /0\n"
            "echo hello\n"
            ":b2a_ExitProcess\n"
            ":: trailing comment\n"
            "\n\n\n\n\n\n\n"
        )
        cleaned, meta = normalize_batchtoapp_headers(script)
        self.assertTrue(meta["header_shift_removed"])
        self.assertTrue(meta["exit_label_removed"])
        self.assertNotIn(":b2a_ExitProcess", cleaned)

    def test_extract_embedded_batch_without_echo(self):
        """Test extracting batch scripts that contain commands without echo or @shift."""
        embedded = b"start /b calc.exe\r\npowershell -NoProfile -Command Write-Host PWN\r\nexit /b 0"
        compressor = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
        compressed = compressor.compress(embedded) + compressor.flush()

        pe_bytes = create_minimal_pe(compressed, app_id="feedbeef")
        extracted = extract_embedded_batch_from_pe(pe_bytes)
        self.assertIsNotNone(extracted)
        self.assertIn("start /b calc.exe", extracted)
        self.assertIn("powershell", extracted)

    def test_inspect_real_compiled_batchtoapp_pe(self):
        """Test forensic triage and extraction on a real CSC-compiled BatchToApp binary."""
        import os, subprocess, tempfile
        from pathlib import Path

        csc_path = r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
        stub_path = Path("references/github_arsenal/BatchToApp-DosX/source/Builder/stub.cs")
        if not os.path.exists(csc_path) or not stub_path.exists():
            self.skipTest("CSC compiler or stub.cs not present on this machine")

        stub_src = stub_path.read_text(encoding="utf-8")
        app_id = "beefcafe"
        stub_src = stub_src.replace("/* {IS_HIDDEN} */", "true")
        stub_src = stub_src.replace("/* {APP_ID} */", f'"{app_id}"')
        stub_src = stub_src.replace("/* {FS_PROTECTION} */", "FileAttributes.System")

        with tempfile.TemporaryDirectory() as td:
            cs_file = os.path.join(td, "stub.cs")
            with open(cs_file, "w", encoding="utf-8") as f:
                f.write(stub_src)

            batch_script = "@shift /0\r\necho Real BatchToApp PE Extraction Verified\r\n:b2a_ExitProcess\r\n".encode("cp866")
            compressor = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
            comp_data = compressor.compress(batch_script) + compressor.flush()
            res_file = os.path.join(td, "embeddedBatchScript")
            with open(res_file, "wb") as f:
                f.write(comp_data)

            exe_file = os.path.join(td, "real_b2a.exe")
            cmd = [csc_path, "/target:winexe", "/optimize+", "/debug-", f"/resource:{res_file}", f"/out:{exe_file}", cs_file]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, f"Compilation failed: {proc.stderr}")

            with open(exe_file, "rb") as f:
                exe_bytes = f.read()
            info = inspect_batchtoapp_pe(exe_bytes)

            self.assertTrue(info["is_pe"])
            self.assertTrue(info["is_batchtoapp"])
            self.assertEqual(info["app_id"], app_id)
            self.assertTrue(info["is_hidden"])
            self.assertTrue(info["fs_protection"])
            self.assertTrue(info["has_embedded_script"])
            self.assertIn("Real BatchToApp PE Extraction Verified", info["extracted_script"])

    def test_extract_embedded_batch_multi_resource_disambiguation(self):
        """Test disambiguating true batch payload from auxiliary non-batch resources (e.g. copyright/configs)."""
        # Resource 1: Auxiliary license text containing the word 'Copyright'
        c1 = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
        res1 = c1.compress(b"Copyright (c) 2026 Acme Corp. All rights reserved.\n") + c1.flush()

        # Resource 2: True embedded batch script
        c2 = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
        res2 = c2.compress(b"@shift /0\r\necho Real Batch In Multi-Resource PE\r\n:b2a_ExitProcess\r\n") + c2.flush()

        combined = len(res1).to_bytes(4, "little") + res1 + len(res2).to_bytes(4, "little") + res2
        pe = create_minimal_pe(combined, app_id="multi001")

        extracted = extract_embedded_batch_from_pe(pe)
        self.assertIsNotNone(extracted)
        self.assertIn("echo Real Batch In Multi-Resource PE", extracted)
        self.assertNotIn("Copyright", extracted)

    def test_detect_and_strip_noise_sliced_mutation_block(self):
        """Test detecting and stripping real BatchToApp mutation blocks where @goto label is noise-sliced."""
        noise = "%path:~45123,-51234%"
        lbl_clean = "label_0x12345678"
        lbl_obf = "".join("^" + c + noise for c in lbl_clean)
        cb_clean = "IIllIIllIIll"
        cb_obf = "".join("^" + c + noise for c in cb_clean)

        script = (
            "@shift /0\r\n"
            f"@goto {lbl_obf}\r\n"
            "random_binary_junk_data_here\r\n"
            "@exit /b 123\r\n"
            f":{lbl_clean}\r\n\r\n"
            f"@set {cb_obf}=^)\r\n"
            ":b2a_ExitProcess\r\n"
        )

        sig = detect_batchtoapp_signatures(script)
        self.assertTrue(sig["is_batchtoapp"])
        self.assertTrue(sig["signatures"]["mutation_block"])
        self.assertTrue(sig["signatures"]["closing_bracket_var"])

        cleaned, stripped = strip_batchtoapp_mutation_block(script)
        self.assertTrue(stripped)
        self.assertNotIn("random_binary_junk", cleaned)
        self.assertNotIn("@exit /b", cleaned)

    def test_resolve_batchtoapp_operators_case_insensitive_and_delayed(self):
        """Test case-insensitive resolution of operator mappings and closing bracket with delayed expansion."""
        script = (
            "@set MyBracket=^)\n"
            "@set MyEcho=echo\n"
            "@set MyIf=if\n"
            "%myecho% lower test\n"
            "%MYECHO% upper test\n"
            "!myecho! delayed test\n"
            "%myif% 1==1 (\n"
            "    %myecho% inner block\n"
            "%mybracket%\n"
        )
        cleaned, meta = resolve_batchtoapp_operators(script)
        self.assertIn("echo lower test", cleaned)
        self.assertIn("echo upper test", cleaned)
        self.assertIn("echo delayed test", cleaned)
        self.assertIn("if 1==1 (", cleaned)
        self.assertIn("inner block\n)", cleaned)
        self.assertNotIn("%myecho%", cleaned)
        self.assertNotIn("%MYECHO%", cleaned)
        self.assertNotIn("!myecho!", cleaned)
        self.assertNotIn("%mybracket%", cleaned)

    def test_prune_batchtoapp_fake_labels_caret_escapes(self):
        """Test fake label pruning preserves caret-escaped labels on goto/call while eliminating decoys."""
        script = (
            "goto :label_0x12^34^56^78\n"
            "call :label_0xab^cd^ef^12\n"
            ":label_0x12345678\n"
            "echo Target Escaped Reached\n"
            ":label_0xabcdef12\n"
            "echo Target Call Reached\n"
            ":label_0x99999999\n"
            ":label_0x88888888\n"
        )
        cleaned, pruned = prune_batchtoapp_fake_labels(script)
        self.assertEqual(pruned, 2)
        self.assertIn(":label_0x12345678", cleaned)
        self.assertIn(":label_0xabcdef12", cleaned)
        self.assertNotIn(":label_0x99999999", cleaned)
        self.assertNotIn(":label_0x88888888", cleaned)

    def test_normalize_batchtoapp_headers_whitespace_variants(self):
        """Test header normalization handles arbitrary whitespace in @shift /0 and :b2a_ExitProcess."""
        script = (
            "@shift   /0\n"
            "echo core body\n"
            ":  b2a_ExitProcess   \n"
        )
        cleaned, meta = normalize_batchtoapp_headers(script)
        self.assertTrue(meta["header_shift_removed"])
        self.assertTrue(meta["exit_label_removed"])
        self.assertEqual(cleaned, "echo core body")

    def test_extract_embedded_batch_utf8_unicode(self):
        """Test extracting UTF-8 Unicode multi-byte strings without CP866 mojibake conversion."""
        unicode_payload = "@shift /0\r\necho ✓ Unicode UTF-8 Verified 🚀\r\n:b2a_ExitProcess".encode("utf-8")
        c = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
        comp = c.compress(unicode_payload) + c.flush()

        pe = create_minimal_pe(comp, app_id="utf8test")
        extracted = extract_embedded_batch_from_pe(pe)
        self.assertIsNotNone(extracted)
        self.assertIn("✓ Unicode UTF-8 Verified 🚀", extracted)

    def test_normalize_batchtoapp_headers_with_anti_tamper_guard(self):
        """Test stripping default BatchToApp anti-tamper temp directory check and exit label."""
        script = (
            '@if not "%~dp0" == "%TEMP%\\" goto b2a_ExitProcess\n'
            "@shift /0\n"
            "echo Core payload running\n"
            ":b2a_ExitProcess\n"
        )
        cleaned, meta = normalize_batchtoapp_headers(script)
        self.assertTrue(meta["guard_check_removed"])
        self.assertTrue(meta["header_shift_removed"])
        self.assertTrue(meta["exit_label_removed"])
        self.assertEqual(cleaned, "echo Core payload running")
        self.assertNotIn("b2a_ExitProcess", cleaned)
        self.assertNotIn("%TEMP%", cleaned)

    def test_strip_batchtoapp_mutation_block_preserves_legitimate_subroutines(self):
        """Test that legitimate subroutines are preserved and only BatchToApp mutation blocks are stripped."""
        script = (
            "@goto setup\n"
            "echo should NOT be deleted\n"
            "@exit /b 0\n"
            ":setup\n"
            "echo in setup\n"
        )
        cleaned, stripped = strip_batchtoapp_mutation_block(script)
        self.assertFalse(stripped)
        self.assertIn("echo should NOT be deleted", cleaned)
        self.assertIn(":setup", cleaned)

    def test_prune_batchtoapp_fake_labels_dynamic_dispatch(self):
        """Test dynamic label dispatch goto :label_0x12%var% protects target label definitions."""
        script = (
            "goto :label_0x12%stage%\n"
            ":label_0x12345678\n"
            "echo Dynamically Dispatched Label\n"
            ":label_0x99999999\n"
            ":label_0x88888888\n"
        )
        cleaned, pruned = prune_batchtoapp_fake_labels(script)
        self.assertEqual(pruned, 2)
        self.assertIn(":label_0x12345678", cleaned)
        self.assertNotIn(":label_0x99999999", cleaned)
        self.assertNotIn(":label_0x88888888", cleaned)

    def test_prune_batchtoapp_fake_labels_word_boundary_and_comments(self):
        """Test that fake labels mentioned in comments or token substrings are correctly pruned."""
        script = (
            "set my_goto=label_0x11111111\n"
            "set recall=call_0x22222222\n"
            ":: goto :label_0x33333333\n"
            "REM goto :label_0x44444444\n"
            ":label_0x11111111\n"
            ":label_0x22222222\n"
            ":label_0x33333333\n"
            ":label_0x44444444\n"
            "goto :label_0xaaaaaaaa\n"
            ":label_0xaaaaaaaa\n"
            "echo real target\n"
        )
        cleaned, pruned = prune_batchtoapp_fake_labels(script)
        self.assertEqual(pruned, 4)
        clean_lines = [l.strip() for l in cleaned.splitlines()]
        self.assertIn(":label_0xaaaaaaaa", clean_lines)
        self.assertNotIn(":label_0x11111111", clean_lines)
        self.assertNotIn(":label_0x22222222", clean_lines)
        self.assertNotIn(":label_0x33333333", clean_lines)
        self.assertNotIn(":label_0x44444444", clean_lines)

    def test_score_candidate_script_rejects_nul_bytes(self):
        """Test candidate scorer immediately rejects binary streams containing NUL bytes."""
        binary_data = "echo hello\x00set x=1\x00goto somewhere"
        score = score_candidate_script(binary_data)
        self.assertEqual(score, 0)

    def test_detect_batchtoapp_signatures_guard(self):
        """Test signature detector identifies anti-tamper temp folder guard."""
        script = '@if not "%~dp0" == "%TEMP%\\" goto b2a_ExitProcess\necho test\n:b2a_ExitProcess'
        sig = detect_batchtoapp_signatures(script)
        self.assertTrue(sig["is_batchtoapp"])
        self.assertTrue(sig["signatures"]["wrapper_guard"])


if __name__ == "__main__":
    unittest.main()


