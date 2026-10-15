#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@ai-role: BatchToApp / DosX Native Wrapper Embedded Batch Extraction & Deobfuscation Engine
@ai-flow: PE Binary/Script -> Signature Triage -> Deflate Resource Decompression -> Mutation Block Stripping -> Noise Slicing Inversion -> Operator Variable Resolution -> Fake Label Pruning -> Header Normalization -> Zeroize
@ai-boundary: Pure static analysis; safe in-memory binary inspection and AST transformation without executing untrusted code
@ai-invariant: Reversible transformation matching BatchToApp-DosX specification (RFC 1951 Deflate, CP866/UTF-8 decoding, operator mapping)
"""

import os
import re
import struct
import zlib
from typing import Dict, Any, List, Optional, Tuple, Set, Union


def zeroize_bytes(buf: Union[bytearray, List[int]]) -> None:
    """Cryptographically sanitize raw bytearray buffers in memory."""
    for i in range(len(buf)):
        buf[i] = 0


def zeroize_dict(d: Dict[Any, Any]) -> None:
    """Cryptographically sanitize sensitive symbol and mapping dictionaries in memory."""
    for k in list(d.keys()):
        val = d[k]
        if isinstance(val, str):
            d[k] = "\x00" * len(val)
        elif isinstance(val, (bytearray, list)):
            zeroize_bytes(val)
        elif isinstance(val, dict):
            zeroize_dict(val)
    d.clear()


def decompress_deflate_stream(data: bytes) -> bytes:
    """
    Decompresses raw Deflate (RFC 1951), zlib (RFC 1950), or gzip (RFC 1952) streams.
    BatchToApp uses .NET System.IO.Compression.DeflateStream, which emits raw deflate (-15 wbits).
    """
    for wbits in (-15, 15, 31, -9, 9):
        try:
            return zlib.decompress(data, wbits)
        except Exception:
            continue
    raise ValueError("Unable to decompress data: invalid Deflate/zlib stream")


def rva_to_file_offset(rva: int, sections: List[Dict[str, int]]) -> Optional[int]:
    """Map a Relative Virtual Address (RVA) to a physical PE file offset using section headers."""
    for sec in sections:
        vaddr = sec["vaddr"]
        rptr = sec["rptr"]
        rsize = sec["rsize"]
        if vaddr <= rva < vaddr + rsize:
            return rptr + (rva - vaddr)
    return None


def score_candidate_script(text: str) -> int:
    """Quantitative scoring to disambiguate embedded batch scripts from metadata/resources."""
    if not text or len(text.strip()) == 0 or "\x00" in text:
        return 0
    tl = text.lower()
    score = (50 if ":b2a_exitprocess" in tl else 0) + \
            (30 if ("@shift /0" in tl or "shift /0" in tl) else 0) + \
            (20 if "embeddedbatchscript" in tl else 0) + \
            (25 if re.search(r':label_0x[0-9a-fA-F]{8}', text) else 0) + \
            (15 if "b2a." in tl else 0)

    # Word-boundary batch command keywords (prevent substring false positives like 'copyright')
    cmds = len(re.findall(r'(?i)\b(?:echo|set|goto|call|shift|pause|if|for|cmd|cls|title|start|rem|type|copy|del|dir|exit|powershell)\b', text))
    score += min(40, cmds * 4)
    vars_count = len(re.findall(r'%[a-zA-Z0-9_]+%|![a-zA-Z0-9_]+!|%~[a-zA-Z0-9]+', text))
    score += min(30, vars_count * 3)
    labels_count = len(re.findall(r'(?m)^[ \t]*:[a-zA-Z0-9_]+', text))
    score += min(25, labels_count * 5)
    noise_count = len(re.findall(r'%[A-Za-z0-9_()]+:~[0-9]+,\s*-?[0-9]+%', text))
    score += min(30, noise_count * 5)

    stripped = text.strip()
    if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
        score -= 20
    return max(0, score)


def extract_embedded_batch_from_pe(raw_bytes: bytes) -> Optional[str]:
    """
    Statically extracts the embedded batch script from a BatchToApp / DosX compiled .NET PE executable.
    Does NOT execute the PE binary.
    """
    if len(raw_bytes) < 0x100 or raw_bytes[:2] != b"MZ":
        return None

    e_lfanew = struct.unpack_from("<I", raw_bytes, 0x3C)[0]
    if e_lfanew + 24 > len(raw_bytes) or raw_bytes[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None

    candidates: List[Tuple[int, str]] = []

    def try_decode_decompressed(decomp: bytes) -> None:
        for enc in ("utf-8", "cp866", "latin-1"):
            try:
                t = decomp.decode(enc)
                sc = score_candidate_script(t)
                if sc >= 5:
                    candidates.append((sc, t))
                break
            except Exception:
                continue

    try:
        opt_hdr_size = struct.unpack_from("<H", raw_bytes, e_lfanew + 20)[0]
        opt_hdr_magic = struct.unpack_from("<H", raw_bytes, e_lfanew + 24)[0]
        num_sections = min(struct.unpack_from("<H", raw_bytes, e_lfanew + 6)[0], 96)
        sec_table_off = e_lfanew + 24 + opt_hdr_size

        sections: List[Dict[str, int]] = []
        for i in range(num_sections):
            off = sec_table_off + i * 40
            if off + 40 > len(raw_bytes):
                break
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", raw_bytes, off + 8)
            sections.append({"vsize": vsize, "vaddr": vaddr, "rsize": rsize, "rptr": rptr})

        # Check CLR Data Directory (Directory index 14)
        dd_start = e_lfanew + 24 + (112 if opt_hdr_magic == 0x20B else 96)
        clr_dd_off = dd_start + 14 * 8
        if clr_dd_off + 8 <= len(raw_bytes):
            clr_rva, clr_size = struct.unpack_from("<II", raw_bytes, clr_dd_off)
            if clr_rva > 0:
                clr_file_off = rva_to_file_offset(clr_rva, sections)
                if clr_file_off is not None and clr_file_off + 32 <= len(raw_bytes):
                    # In IMAGE_COR20_HEADER: offset 24 is Resources Directory (RVA: uint32, Size: uint32)
                    res_rva, res_size = struct.unpack_from("<II", raw_bytes, clr_file_off + 24)
                    if res_rva > 0 and res_size > 4:
                        res_file_off = rva_to_file_offset(res_rva, sections)
                        if res_file_off is not None and res_file_off + 4 <= len(raw_bytes):
                            res_ptr = res_file_off
                            end_res = min(len(raw_bytes), res_file_off + res_size)
                            while res_ptr + 4 < end_res:
                                res_len = struct.unpack_from("<I", raw_bytes, res_ptr)[0]
                                if res_len <= 0 or res_ptr + 4 + res_len > end_res:
                                    res_ptr += 4
                                    continue
                                comp_bytes = raw_bytes[res_ptr + 4:res_ptr + 4 + res_len]
                                try:
                                    decomp = decompress_deflate_stream(comp_bytes)
                                    try_decode_decompressed(decomp)
                                except Exception:
                                    pass
                                res_ptr = ((res_ptr + 4 + res_len + 3) // 4) * 4
    except Exception:
        pass

    # If any candidate from CLR manifest has strong BatchToApp markers (score >= 50), return top match immediately
    high_candidates = [c for c in candidates if c[0] >= 50]
    if high_candidates:
        high_candidates.sort(key=lambda c: c[0], reverse=True)
        return high_candidates[0][1]

    # Heuristic fallback scanner: 4-byte aligned search first (75% faster), then unaligned if needed
    for step in (4, 1):
        if candidates and max(c[0] for c in candidates) >= 20:
            break
        pos = 0
        limit = len(raw_bytes) - 16
        while pos < limit:
            candidate_len = struct.unpack_from("<I", raw_bytes, pos)[0]
            if 10 < candidate_len <= min(10 * 1024 * 1024, len(raw_bytes) - (pos + 4)):
                candidate_data = raw_bytes[pos + 4:pos + 4 + candidate_len]
                try:
                    decomp = decompress_deflate_stream(candidate_data)
                    try_decode_decompressed(decomp)
                    if any(c[0] >= 50 for c in candidates):
                        break
                except Exception:
                    pass
            pos += step
        if candidates:
            break

    if candidates:
        candidates.sort(key=lambda c: c[0], reverse=True)
        return candidates[0][1]

    return None


def inspect_batchtoapp_pe(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Performs forensic triage on a potential BatchToApp / DosX compiled PE binary.
    Extracts embedded script, wrapper metadata, and application configuration without executing the binary.
    """
    if len(raw_bytes) < 0x100 or raw_bytes[:2] != b"MZ":
        return {"is_pe": False, "is_batchtoapp": False, "confidence": 0.0, "family": "Not a PE binary", "indicators": []}

    e_lfanew = struct.unpack_from("<I", raw_bytes, 0x3C)[0]
    if e_lfanew + 24 > len(raw_bytes) or raw_bytes[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return {"is_pe": False, "is_batchtoapp": False, "confidence": 0.0, "family": "Invalid PE header", "indicators": []}

    machine = struct.unpack_from("<H", raw_bytes, e_lfanew + 4)[0]
    architecture = "x64" if machine == 0x8664 else ("x86" if machine == 0x014C else "MSIL")

    indicators: List[str] = []
    confidence = 0.0

    # Indicator 1: Class name GeneratedWithBatchToApp
    if b"GeneratedWithBatchToApp" in raw_bytes:
        indicators.append("GeneratedWithBatchToApp class identifier detected")
        confidence += 0.40

    # Indicator 2: Resource name embeddedBatchScript
    if b"embeddedBatchScript" in raw_bytes:
        indicators.append("embeddedBatchScript manifest resource symbol detected")
        confidence += 0.35

    # Indicator 3: Temporary batch file naming pattern b2a. (ASCII or UTF-16LE)
    if b"b2a." in raw_bytes or "b2a.".encode("utf-16le") in raw_bytes:
        indicators.append("DosX b2a temp file execution pattern detected")
        confidence += 0.20

    # Indicator 4: .NET CLR and DeflateStream decompressor references
    if b"_CorExeMain" in raw_bytes and b"DeflateStream" in raw_bytes:
        indicators.append(".NET CLR DeflateStream wrapper decompression architecture verified")
        confidence += 0.15

    # Extract App ID from binary:
    # 1. Check ASCII pattern (synthetic mock PE or uncompressed IL)
    app_id = None
    app_id_match = re.search(rb'b2a\.[^.\r\n]+\.([0-9a-fA-F]{8})\.cmd', raw_bytes)
    if app_id_match:
        app_id = app_id_match.group(1).decode("ascii", errors="replace")
    else:
        # 2. Check UTF-16LE UserStrings stream in real compiled .NET assemblies
        # In stub.cs, appId is an 8-hex-char GUID token emitted after embeddedBatchScript / b2a.
        hex8_utf16 = rb'((?:[0-9a-fA-F]\x00){8})'
        for anchor in (
            b'e\x00m\x00b\x00e\x00d\x00d\x00e\x00d\x00B\x00a\x00t\x00c\x00h\x00S\x00c\x00r\x00i\x00p\x00t\x00',
            b'b\x002\x00a\x00.\x00',
        ):
            anchor_pos = raw_bytes.find(anchor)
            if anchor_pos != -1:
                window = raw_bytes[anchor_pos + len(anchor):anchor_pos + len(anchor) + 300]
                m = re.search(hex8_utf16, window)
                if m:
                    app_id = m.group(1).decode("utf-16le", errors="replace")
                    break

    if app_id:
        indicators.append(f"BatchToApp unique application GUID token extracted: {app_id}")

    is_hidden = True if (b"CreateNoWindow = true" in raw_bytes or b"CreateNoWindow\x00\x01" in raw_bytes or re.search(rb'[\x06-\x09\x25]\x17\x6f', raw_bytes)) else (False if (b"CreateNoWindow = false" in raw_bytes or re.search(rb'[\x06-\x09\x25]\x16\x6f', raw_bytes)) else None)
    fs_protection = True if (b"\x20\x07\x01\x00\x00" in raw_bytes or b"FileAttributes.System" in raw_bytes) else (False if b"\x20\x03\x01\x00\x00" in raw_bytes else None)
    if fs_protection:
        indicators.append("Filesystem anti-tamper protection (System/Hidden/ReadOnly) enabled")

    # Attempt static embedded script extraction
    extracted_script = extract_embedded_batch_from_pe(raw_bytes)
    if extracted_script:
        indicators.append("Embedded batch script successfully decompressed from DeflateStream resource")
        confidence = max(confidence, 0.95)

    is_batchtoapp = confidence >= 0.35 or extracted_script is not None

    return {
        "is_pe": True,
        "is_batchtoapp": is_batchtoapp,
        "confidence": min(1.0, confidence),
        "family": "BatchToApp-DosX .NET Native Executable Wrapper" if is_batchtoapp else "Standard PE Binary",
        "architecture": architecture,
        "size_bytes": len(raw_bytes),
        "indicators": indicators,
        "app_id": app_id,
        "is_hidden": is_hidden,
        "fs_protection": fs_protection,
        "has_embedded_script": extracted_script is not None,
        "extracted_script": extracted_script,
        "extracted_script_preview": extracted_script[:200] if extracted_script else None,
    }


def strip_batchtoapp_noise_slices(script_text: str) -> Tuple[str, int]:
    """
    Neutralizes BatchToApp ObfuscateString character-by-character noise variable slicing.
    Pattern: ^c%varied_var:~40000,-40000% where variable is a system env var and slice evaluates to empty.
    Also handles inline caret line continuations (^\r\n / ^\n).
    """
    count = 0
    curr = script_text

    # Step 1: Join inline caret line continuations inside tokens (^\r\n or ^\n)
    caret_nl_pattern = re.compile(r'\^(\r?\n)')
    if caret_nl_pattern.search(curr):
        curr, n_nl = caret_nl_pattern.subn('', curr)
        count += n_nl

    # Step 2: Strip character noise slicing: ^<char>%<sys_var>:~<offset>,<spaces>-<len>%
    # Matches: ^c%path:~45123,-51234% -> c
    char_noise_pattern = re.compile(
        r'\^([^\r\n%])%[A-Za-z0-9_()]+:~[0-9]{3,},\s*-?[0-9]{3,}%'
    )
    m = char_noise_pattern.search(curr)
    while m:
        curr, n = char_noise_pattern.subn(r'\1', curr)
        count += n
        if n == 0:
            break
        m = char_noise_pattern.search(curr)

    # Step 3: Strip standalone out-of-bounds noise slicing expressions (%var:~40000,-40000%)
    slice_pattern = re.compile(r'%[A-Za-z0-9_()]+:~[0-9]{3,},\s*-?[0-9]{3,}%')
    if slice_pattern.search(curr):
        curr, n = slice_pattern.subn('', curr)
        count += n

    return curr, count


def strip_batchtoapp_mutation_block(script_text: str) -> Tuple[str, bool]:
    """
    Detects and eliminates BatchToApp ObfuscateBatchCalls mutation block and CP866 binary junk preamble.
    Supports both plain and noise-sliced @goto targets.
    """
    # 1. Plain matching (unobfuscated or already de-noised goto label)
    # Target label must match BatchToApp's signature label_0x[0-9a-fA-F]{8} to avoid stripping legitimate subroutines
    pattern_plain = re.compile(
        r'(?:\r?\n|^)[ \t]*@?goto\s+[:]?((?:label_0x[0-9a-fA-F]{8}))[ \t]*\r?\n'
        r'.*?\r?\n'
        r'[ \t]*@?exit\s+/b\s+[0-9]+[ \t]*\r?\n'
        r'[ \t]*:\1[ \t]*(?:\r?\n|$)',
        re.DOTALL | re.IGNORECASE
    )
    if pattern_plain.search(script_text):
        cleaned = pattern_plain.sub('\n', script_text)
        return cleaned.lstrip(), True

    # 2. Noise-sliced matching (goto target contains ObfuscateString noise slices)
    pattern_obf = re.compile(
        r'(?:\r?\n|^)[ \t]*@?goto\s+[:]?([^\r\n]+)\r?\n'
        r'.*?\r?\n'
        r'[ \t]*@?exit\s+/b\s+[0-9]+[ \t]*\r?\n'
        r'[ \t]*:(label_0x[0-9a-fA-F]{8})[ \t]*(?:\r?\n|$)',
        re.DOTALL | re.IGNORECASE
    )
    m = pattern_obf.search(script_text)
    if m:
        goto_target_raw = m.group(1)
        label_def = m.group(2).lower()
        cleaned_target = strip_batchtoapp_noise_slices(goto_target_raw)[0].replace('^', '').strip().lower()
        if cleaned_target == label_def:
            cleaned = script_text[:m.start()] + '\n' + script_text[m.end():]
            return cleaned.lstrip(), True

    return script_text, False


def resolve_batchtoapp_operators(script_text: str) -> Tuple[str, Dict[str, Any]]:
    """
    Harvests BatchToApp ObfuscateBatchCalls operator substitution dictionary and closing bracket variable.
    Inverts operator mappings (%IIlIllII% -> echo) and closing bracket references (%closingBracketVar% -> )).
    Prunes operator declaration lines with full case-insensitivity and delayed expansion support.
    """
    operator_map: Dict[str, str] = {}
    closing_bracket_var: Optional[str] = None
    pruned_lines = 0

    lines = script_text.splitlines()
    remaining_lines: List[str] = []

    # 1. Harvest closing bracket variable: @set <bracket_var>=^)
    closing_bracket_pat = re.compile(
        r'^[ \t]*(?:%[a-zA-Z0-9_]+%[ \t]*)?@?[ \t]*set\s+([^\r\n=]+?)\s*=\s*\^\)[ \t]*$',
        re.IGNORECASE
    )

    # 2. Harvest operator declaration lines:
    op_decl_pat = re.compile(
        r'^(?:%[a-zA-Z0-9_]+%[ \t]*)?[ \t]*@?[ \t]*set[ \t]+([a-zA-Z0-9_]+)\s*=\s*\^?(?:\r?\n)?\s*([a-zA-Z0-9_]+)[ \t]*$',
        re.IGNORECASE
    )

    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        cb_m = closing_bracket_pat.match(line)
        if cb_m:
            cb_raw = cb_m.group(1).strip()
            closing_bracket_var = strip_batchtoapp_noise_slices(cb_raw)[0].replace('^', '').strip()
            pruned_lines += 1
            i += 1
            continue

        op_m = op_decl_pat.match(line)
        if op_m:
            var_name = op_m.group(1)
            cmd_val = op_m.group(2)
            operator_map[var_name] = cmd_val
            pruned_lines += 1
            i += 1
            continue

        # Check multi-line set declaration: line ends with '=^' and next line is command
        multi_m = re.match(r'^(?:%[a-zA-Z0-9_]+%[ \t]*)?[ \t]*@?[ \t]*set[ \t]+([a-zA-Z0-9_]+)\s*=\s*\^[ \t]*$', line, re.IGNORECASE)
        if multi_m and i + 1 < n:
            next_line = lines[i + 1].strip()
            if re.match(r'^[a-zA-Z0-9_]+$', next_line):
                var_name = multi_m.group(1)
                cmd_val = next_line
                operator_map[var_name] = cmd_val
                pruned_lines += 2
                i += 2
                continue

        remaining_lines.append(line)
        i += 1

    curr = "\n".join(remaining_lines)

    # Invert closing bracket variable if found (case-insensitive %var% and !var!)
    if closing_bracket_var:
        curr = re.sub(r'[%!]' + re.escape(closing_bracket_var) + r'[%!]', ')', curr, flags=re.IGNORECASE)

    # Invert operator variables (longest variable name first to prevent substring collisions, case-insensitive)
    for var_name, cmd_val in sorted(operator_map.items(), key=lambda kv: len(kv[0]), reverse=True):
        curr = re.sub(r'[%!]' + re.escape(var_name) + r'[%!]', cmd_val, curr, flags=re.IGNORECASE)

    meta = {
        "operators_resolved": len(operator_map),
        "operator_map": dict(operator_map),
        "closing_bracket_var": closing_bracket_var,
        "declaration_lines_pruned": pruned_lines,
    }

    # Cryptographically wipe in-memory operator table
    zeroize_dict(operator_map)

    return curr, meta


def prune_batchtoapp_fake_labels(script_text: str) -> Tuple[str, int]:
    """
    Identifies and prunes fake decoy labels inserted by BatchToApp AddFakeLabels (:label_0x[0-9a-f]{8}).
    Collects all legitimate jump/call references and eliminates only unreferenced fake labels.
    Supports goto, call, call(:label), goto:label, caret escapes, dynamic references, and whitespace variations.
    """
    ref_pattern = re.compile(
        r'(?<![a-zA-Z0-9_])(?:goto|call)(?:[ \t]+(?:\([ \t]*)?|[ \t]*(?:\([ \t]*)?)[: \t]*([a-zA-Z0-9_\^%!]+)',
        re.IGNORECASE
    )
    referenced_labels: Set[str] = set()
    dynamic_targets: List[Tuple[str, str]] = []

    for line in script_text.splitlines():
        stripped_line = line.strip()
        if stripped_line.startswith("::") or re.match(r'(?i)^@?rem\b', stripped_line):
            continue
        # Split line on command separators & and | outside quotes
        segments = re.split(r'(?<!\^)[&|]+', line)
        for seg in segments:
            seg_trimmed = re.sub(r'^[ \t@()]+', '', seg)
            if re.match(r'(?i)^set\b', seg_trimmed):
                continue
            for m in ref_pattern.finditer(seg):
                raw_target = m.group(1).replace('^', '').strip().lower()
                if "%" in raw_target or "!" in raw_target:
                    first_exp = min([raw_target.find(c) for c in ("%", "!") if c in raw_target])
                    last_exp = max([raw_target.rfind(c) for c in ("%", "!") if c in raw_target])
                    prefix = raw_target[:first_exp]
                    suffix = raw_target[last_exp + 1:] if last_exp + 1 < len(raw_target) else ""
                    if len(prefix) > 8 or len(suffix) > 0:
                        dynamic_targets.append((prefix, suffix))
                else:
                    referenced_labels.add(raw_target)

    label_def_pattern = re.compile(r'^[ \t]*:[ \t]*([a-zA-Z0-9_\^]+)[ \t]*$')
    pruned = 0
    clean_lines: List[str] = []

    for line in script_text.splitlines():
        m = label_def_pattern.match(line)
        if m:
            clean_label = m.group(1).replace('^', '').lower()
            if re.match(r'^label_0x[0-9a-fA-F]{8}$', clean_label):
                is_dyn = any(clean_label.startswith(p) and clean_label.endswith(s) for p, s in dynamic_targets)
                if clean_label not in referenced_labels and not is_dyn:
                    pruned += 1
                    continue
        clean_lines.append(line)

    return "\n".join(clean_lines), pruned


def normalize_batchtoapp_headers(script_text: str) -> Tuple[str, Dict[str, bool]]:
    """
    Strips BatchToApp wrapper headers:
      - Anti-tamper temp directory guards (@if not "%~dp0" == "%TEMP%\" goto b2a_ExitProcess)
      - Wrapper argument shift directives (@shift /0)
      - Trailing wrapper exit labels (:b2a_ExitProcess)
    """
    lines = script_text.splitlines()
    has_shift = False
    has_guard = False
    has_exit = False

    # Check initial non-empty lines for wrapper guards and shift directives
    i = 0
    non_empty = 0
    while i < len(lines) and non_empty < 30:
        line_str = lines[i].strip()
        if not line_str:
            i += 1
            continue
        non_empty += 1
        if re.search(r'(?i)\bgoto\s+:?b2a_exitprocess\b', line_str) and re.match(r'(?i)^[ \t]*@?if\b', line_str):
            has_guard = True
            lines.pop(i)
            continue
        if re.match(r'(?i)^[ \t]*@?shift\s*/0[ \t]*$', line_str):
            has_shift = True
            lines.pop(i)
            continue
        if not (line_str.startswith("::") or re.match(r'(?i)^[ \t]*@?rem\b', line_str)):
            if not re.match(r'(?i)^[ \t]*@?set\b', line_str):
                break
        i += 1

    # Check for :b2a_ExitProcess from bottom upwards
    for j in range(len(lines) - 1, -1, -1):
        if re.match(r'(?i)^:[ \t]*b2a_exitprocess[ \t]*$', lines[j].strip()):
            has_exit = True
            lines.pop(j)

    meta = {
        "header_shift_removed": has_shift,
        "guard_check_removed": has_guard,
        "exit_label_removed": has_exit,
    }
    return "\n".join(lines).strip(), meta


def detect_batchtoapp_signatures(
    script_text: Optional[str] = None, raw_bytes: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Heuristic detection of BatchToApp / DosX native wrapper and batch obfuscation signatures.
    """
    indicators: List[str] = []
    confidence = 0.0

    # PE Mode Detection
    if raw_bytes is not None and len(raw_bytes) >= 0x100 and raw_bytes[:2] == b"MZ":
        pe_info = inspect_batchtoapp_pe(raw_bytes)
        return pe_info

    if not script_text:
        return {
            "is_batchtoapp": False,
            "confidence": 0.0,
            "indicators": [],
            "signatures": {},
        }

    # Script Mode Detection (CRLF & LF safe regexes)
    has_wrapper_header = bool(re.search(r'^[ \t]*@?shift\s*/0[ \t]*\r?$', script_text, re.MULTILINE | re.IGNORECASE))
    if has_wrapper_header:
        indicators.append("BatchToApp wrapper header '@shift /0' detected")
        confidence += 0.25

    has_wrapper_guard = bool(re.search(r'^[ \t]*@?if\b.*?goto\s+:?b2a_exitprocess', script_text, re.MULTILINE | re.IGNORECASE))
    if has_wrapper_guard:
        indicators.append("BatchToApp anti-tamper header guard 'goto b2a_ExitProcess' detected")
        confidence += 0.30

    has_wrapper_exit = bool(re.search(r'^[ \t]*:[ \t]*b2a_exitprocess[ \t]*\r?$', script_text, re.MULTILINE | re.IGNORECASE))
    if has_wrapper_exit:
        indicators.append("BatchToApp wrapper exit routine ':b2a_ExitProcess' detected")
        confidence += 0.35

    noise_slice_matches = len(re.findall(r'%[A-Za-z0-9_()]+:~[0-9]{3,},\s*-?[0-9]{3,}%', script_text))
    if noise_slice_matches > 0:
        indicators.append(f"BatchToApp ObfuscateString noise variable slices detected ({noise_slice_matches} instances)")
        confidence += min(0.35, 0.10 + noise_slice_matches * 0.02)

    # Detect mutation block (plain or noise-sliced goto target)
    has_mutation_block = False
    mut_m = re.search(
        r'@?goto\s+[:]?([^\r\n]+)\s*\r?\n.*?\r?\n@?exit\s+/b\s+[0-9]+\s*\r?\n:[ \t]*(label_0x[0-9a-fA-F]{8}|[a-zA-Z0-9_]+)',
        script_text, re.DOTALL | re.IGNORECASE
    )
    if mut_m:
        g_target = strip_batchtoapp_noise_slices(mut_m.group(1))[0].replace('^', '').strip().lower()
        g_lbl = mut_m.group(2).lower()
        if g_target == g_lbl or g_lbl.startswith("label_0x"):
            has_mutation_block = True
            indicators.append("BatchToApp ObfuscateBatchCalls mutation jump block detected")
            confidence += 0.30

    # Detect closing bracket (plain or noise-sliced variable name)
    has_closing_bracket = bool(re.search(
        r'^[ \t]*(?:%[a-zA-Z0-9_]+%[ \t]*)?@?[ \t]*set\s+[^\r\n=]+?=\s*\^\)[ \t]*\r?$',
        script_text, re.MULTILINE | re.IGNORECASE
    ))
    if has_closing_bracket:
        indicators.append("BatchToApp closing bracket variable definition detected")
        confidence += 0.25

    fake_labels_matches = len(re.findall(r'^[ \t]*:[ \t]*label_0x[0-9a-fA-F]{8}[ \t]*\r?$', script_text, re.MULTILINE))
    if fake_labels_matches > 0:
        indicators.append(f"BatchToApp mutated/fake label identifiers detected ({fake_labels_matches} labels)")
        confidence += min(0.30, 0.10 + fake_labels_matches * 0.05)

    is_batchtoapp = confidence >= 0.25

    return {
        "is_batchtoapp": is_batchtoapp,
        "confidence": min(1.0, confidence),
        "indicators": indicators,
        "signatures": {
            "wrapper_header": has_wrapper_header, "wrapper_guard": has_wrapper_guard,
            "wrapper_exit_label": has_wrapper_exit, "noise_slicing": noise_slice_matches > 0,
            "mutation_block": has_mutation_block, "closing_bracket_var": has_closing_bracket,
            "fake_labels": fake_labels_matches > 0,
        },
    }


def normalize_batchtoapp(
    script_text: str, custom_env: Optional[Dict[str, str]] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Main entry point for BatchToApp / DosX static batch script normalization:
      - Neutralizes noise variable slicing
      - Unwraps mutation blocks and binary junk
      - Resolves operator variable maps and closing brackets
      - Prunes unreferenced fake labels
      - Cleans wrapper headers, guards, and exit markers
    """
    sig = detect_batchtoapp_signatures(script_text)
    if not sig["is_batchtoapp"] and sig["confidence"] < 0.20:
        return script_text, {
            "detected": False, "is_batchtoapp": False, "confidence": sig["confidence"],
            "signatures": sig["signatures"], "indicators": sig["indicators"],
            "noise_slices_stripped": 0, "mutation_block_stripped": False,
            "operators_resolved": 0, "fake_labels_pruned": 0,
        }

    curr = script_text

    # Phase 1-5: Sequential BatchToApp unwrapping pipeline
    curr, noise_count = strip_batchtoapp_noise_slices(curr)
    curr, mut_stripped = strip_batchtoapp_mutation_block(curr)
    curr, op_meta = resolve_batchtoapp_operators(curr)
    curr, fake_pruned = prune_batchtoapp_fake_labels(curr)
    curr, header_meta = normalize_batchtoapp_headers(curr)

    meta = {
        "detected": True, "is_batchtoapp": True, "confidence": sig["confidence"],
        "signatures": sig["signatures"], "indicators": sig["indicators"],
        "noise_slices_stripped": noise_count, "mutation_block_stripped": mut_stripped,
        "operators_resolved": op_meta["operators_resolved"], "closing_bracket_var": op_meta["closing_bracket_var"],
        "declaration_lines_pruned": op_meta["declaration_lines_pruned"], "fake_labels_pruned": fake_pruned,
        "header_shift_removed": header_meta["header_shift_removed"], "guard_check_removed": header_meta["guard_check_removed"],
        "exit_label_removed": header_meta["exit_label_removed"],
    }
    return curr, meta


class BatchToAppNormalizer:
    """Stateful object-oriented normalizer wrapper for BatchToApp / DosX engine."""

    def __init__(self, custom_env: Optional[Dict[str, str]] = None):
        self.custom_env = custom_env or {}

    def detect(self, script_text: str, raw_bytes: Optional[bytes] = None) -> Dict[str, Any]:
        return detect_batchtoapp_signatures(script_text, raw_bytes=raw_bytes)

    def normalize(self, script_text: str) -> Tuple[str, Dict[str, Any]]:
        return normalize_batchtoapp(script_text, custom_env=self.custom_env)

    def inspect_pe(self, raw_bytes: bytes) -> Dict[str, Any]:
        return inspect_batchtoapp_pe(raw_bytes)

    def extract_script(self, raw_bytes: bytes) -> Optional[str]:
        return extract_embedded_batch_from_pe(raw_bytes)
