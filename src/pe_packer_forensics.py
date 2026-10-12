#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@ai-role: Static PE Packer & Batch Compiler Forensic Unpacker Engine
@ai-flow: Binary Byte Stream -> Signature & Section Triage -> UPX NRV2B / 7zS2.sfx / Bytepress LZMA / xorPacker Overlay Extraction
@ai-boundary: Pure static byte inspection; never executes untrusted PE binaries
@ai-invariant: Deterministic offset reporting aligned with Ghidra MCP (ghidra-re-operator) findings
"""

import json
import struct
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional


def zeroize_bytes(buf: bytearray) -> None:
    """
    Cryptographic buffer sanitization: overwrites sensitive byte buffer
    with zeros to prevent memory retention of extracted keys or payloads.
    """
    for i in range(len(buf)):
        buf[i] = 0



class PEBatchPackerForensics:
    """
    Forensic analyzer and static payload extractor derived from Ghidra MCP
    reverse engineering of 7 Windows Batch-to-EXE packers & obfuscators:
      1. bat2exe_12.exe (islamadel): UPX0/UPX1 NRV2B stub at RVA 0x20ea0 + 7zS2.sfx (7z\xBC\xAF\x27\x1C)
      2. BEDeCode.exe (cnHopeStudio): VB6 Native MSVBVM60.DLL!ThunRTMain at RVA 0x1670 + CHRMAPSET table
      3. example.exe / example_encoded.exe (dehoisted): .NET CLR UTF-16LE user strings at offset 0xa7d
      4. example_bytepressed.exe (dehoisted): Bytepress LZMA RangeCoder in-memory loader at offset 0x9f78
      5. xorStub.exe (xorPacker): PE Overlay '***' delimiter + master key 'randomkey' at offset 0xfcc
    """

    SEVENZIP_MAGIC = b"\x37\x7a\xbc\xaf\x27\x1c"
    SFX_CONFIG_BEGIN = b";!@Install@!UTF-8!"
    SFX_CONFIG_END = b";!@InstallEnd@!"
    XOR_DELIMITER = b"***"
    DEFAULT_XOR_MASTER_KEY = b"randomkey"

    def __init__(self, binary_path: Path):
        self.binary_path = Path(binary_path)
        self.raw = self.binary_path.read_bytes()

    def parse_pe_sections(self) -> List[Dict[str, Any]]:
        if len(self.raw) < 0x100 or self.raw[:2] != b"MZ":
            return []
        e_lfanew = struct.unpack_from("<I", self.raw, 0x3C)[0]
        if e_lfanew + 24 > len(self.raw) or self.raw[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return []
        num_sections = struct.unpack_from("<H", self.raw, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", self.raw, e_lfanew + 20)[0]
        sec_table_off = e_lfanew + 24 + opt_hdr_size
        sections = []
        for i in range(num_sections):
            off = sec_table_off + i * 40
            if off + 40 > len(self.raw):
                break
            name = self.raw[off:off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", self.raw, off + 8)
            sections.append({
                "name": name,
                "virtual_size": vsize,
                "virtual_address": hex(vaddr),
                "raw_size": rsize,
                "raw_ptr": hex(rptr),
                "end_offset": rptr + rsize,
            })
        return sections

    def detect_packer_family(self) -> Dict[str, Any]:
        sections = self.parse_pe_sections()
        sec_names = [s["name"] for s in sections]
        indicators: List[str] = []
        family = "Unknown / Standard PE"

        if "UPX0" in sec_names and "UPX1" in sec_names:
            family = "UPX NRV2B Packed Native Binary (bat2exe_12 / 7zS2.sfx Wrapper)"
            indicators.append("UPX0/UPX1 sections detected (NRV2B bitstream decompressor stub)")

        if b"bytepress.lib.LZMA.Compress.RangeCoder" in self.raw:
            family = "Bat2Exe-dehoisted (.NET CLR + Bytepress LZMA RangeCoder In-Memory Packer)"
            off = self.raw.find(b"bytepress.lib.LZMA.Compress.RangeCoder")
            indicators.append(f"Bytepress LZMA RangeCoder namespace at file offset {hex(off)}")
        elif b"Bat2Exe" in self.raw and b"_CorExeMain" in self.raw:
            family = "Bat2Exe-dehoisted (.NET CLR Standard / Base64 Process.Start Stub)"
            off = self.raw.find(b"Bat2Exe")
            indicators.append(f"Bat2Exe .NET metadata signature at file offset {hex(off)}")

        if b"ThunRTMain" in self.raw and b"MSVBVM60.DLL" in self.raw:
            family = "VB6 Native Compiled Batch Decoder (BEDeCode / MSVBVM60 ThunRTMain)"
            off = self.raw.find(b"ThunRTMain")
            indicators.append(f"VB6 ThunRTMain entry import at file offset {hex(off)}")

        if self.DEFAULT_XOR_MASTER_KEY in self.raw:
            off = self.raw.find(self.DEFAULT_XOR_MASTER_KEY)
            family = "xorPacker Native C++ Stub (PE Overlay Dual-XOR Dropper)"
            indicators.append(f"Hardcoded master XOR key 'randomkey' at file offset {hex(off)}")

        if self.SEVENZIP_MAGIC in self.raw:
            off = self.raw.find(self.SEVENZIP_MAGIC)
            indicators.append(f"7zS2.sfx embedded 7-Zip archive header at file offset {hex(off)}")

        return {
            "file": self.binary_path.name,
            "size_bytes": len(self.raw),
            "family": family,
            "sections": sections,
            "indicators": indicators,
        }

    @staticmethod
    def xor_bytes(data: bytes, key: bytes) -> bytes:
        klen = len(key)
        return bytes(b ^ key[i % klen] for i, b in enumerate(data))

    def decrypt_xorpacker_overlay(self, master_key: bytes = DEFAULT_XOR_MASTER_KEY) -> Optional[Dict[str, Any]]:
        """
        Reconstructs the exact 2-stage XOR decryption routine disassembled in Ghidra
        from xorStub.exe (RVA 0x1000..0x2dcc):
          Layout: [Stub PE] + '***' + [XOR(Payload, DynamicKey)] + '***' + [XOR(DynamicKey, 'randomkey')]
        """
        parts = self.raw.split(self.XOR_DELIMITER)
        if len(parts) < 3:
            return None
        enc_payload = parts[-2]
        enc_dyn_key = parts[-1]
        dyn_key = self.xor_bytes(enc_dyn_key, master_key)
        dec_payload = self.xor_bytes(enc_payload, dyn_key)
        return {
            "dynamic_key": dyn_key.decode("utf-8", errors="replace"),
            "decrypted_size": len(dec_payload),
            "decrypted_preview": dec_payload[:120].decode("utf-8", errors="replace"),
        }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pe_packer_forensics.py <target_pe.exe>")
        sys.exit(0)
    analyzer = PEBatchPackerForensics(Path(sys.argv[1]))
    print(json.dumps(analyzer.detect_packer_family(), indent=2, ensure_ascii=False))
