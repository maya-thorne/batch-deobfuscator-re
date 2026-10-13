#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@ai-role: Batch-Encryption-DeCoder (BEDeCode) Static Runtime Stub Unpacker & PE Forensics Engine
@ai-flow: Script/PE Bytes -> Signature Triage -> Env Bootstrapping -> Recursive Key Table Peeling -> Slice/Subst Inversion -> Zeroize
@ai-boundary: Pure static analysis; safe in-memory AST and binary inspection without executing untrusted code
@ai-invariant: Reversible character mapping inversion matching VB6 BEDeCode & BatchEncryption specification
"""

import os
import re
import struct
from typing import Dict, Any, List, Optional, Tuple, Union


def zeroize_bytes(buf: Union[bytearray, List[int]]) -> None:
    """Cryptographic memory wipe for byte arrays."""
    for i in range(len(buf)):
        buf[i] = 0


def zeroize_dict(d: Dict[Any, Any]) -> None:
    """Cryptographic memory wipe for sensitive symbol and key mapping dictionaries."""
    for k in list(d.keys()):
        val = d[k]
        if isinstance(val, str):
            d[k] = "\x00" * len(val)
        elif isinstance(val, (bytearray, list)):
            zeroize_bytes(val)
    d.clear()


# Standard Windows bootstrap environment variables used by BatchEncryption
WINDOWS_BOOTSTRAP_ENV: Dict[str, str] = {
    "allusersprofile": r"C:\ProgramData",
    "programdata": r"C:\ProgramData",
    "programfiles": r"C:\Program Files",
    "programfiles(x86)": r"C:\Program Files (x86)",
    "commonprogramfiles": r"C:\Program Files\Common Files",
    "commonprogramfiles(x86)": r"C:\Program Files (x86)\Common Files",
    "systemroot": r"C:\Windows",
    "systemdrive": "C:",
    "windir": r"C:\Windows",
    "comspec": r"C:\Windows\system32\cmd.exe",
    "os": "Windows_NT",
    "username": "Administrator",
    "userprofile": r"C:\Users\Administrator",
    "appdata": r"C:\Users\Administrator\AppData\Roaming",
    "localappdata": r"C:\Users\Administrator\AppData\Local",
    "temp": r"C:\Users\Administrator\AppData\Local\Temp",
    "tmp": r"C:\Users\Administrator\AppData\Local\Temp",
    "pathext": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
}


def clean_bedecode_escapes(raw_text: str) -> str:
    """
    Normalizes BatchEncryption caret escape sequences in symbol tables.
    In VB6 BEDeCode:
      Replace ^^ with caret placeholder
      Replace ^& with ampersand placeholder
      Strip loose carets (^)
      Restore escaped carets and ampersands
    """
    text = raw_text.replace("^^", "\x01")
    text = text.replace("^&", "\x02")
    text = text.replace("^", "")
    text = text.replace("\x01", "^")
    text = text.replace("\x02", "&")
    return text


def eval_batch_slice(value: str, slice_expr: str) -> str:
    """
    Evaluates cmd.exe environment variable slicing expressions:
      :~offset,length
      :~-length
      :~offset,-end
      :~-offset,-end
      :~-offset,length
      :~offset
    """
    vlen = len(value)
    if slice_expr.startswith(":~"):
        spec = slice_expr[2:].strip()
    elif slice_expr.startswith("~"):
        spec = slice_expr[1:].strip()
    else:
        return value

    if not spec:
        return value

    parts = spec.split(",")
    try:
        if len(parts) == 1:
            offset = int(parts[0].replace("+", "").strip())
            if offset >= 0:
                return value[offset:] if offset < vlen else ""
            else:
                return value[offset:] if abs(offset) <= vlen else value
        elif len(parts) == 2:
            offset = int(parts[0].replace("+", "").strip())
            length = int(parts[1].replace("+", "").strip())

            start = offset if offset >= 0 else max(0, vlen + offset)
            if start > vlen:
                return ""

            if length >= 0:
                end = min(vlen, start + length)
                return value[start:end]
            else:
                end = max(0, vlen + length)
                return value[start:end] if start < end else ""
    except ValueError:
        return ""

    return ""


def eval_batch_subst(value: str, subst_expr: str) -> str:
    """
    Evaluates cmd.exe variable substitution expressions:
      :old=new
      :*old=new  (prefix wildcard match)
    """
    if not subst_expr.startswith(":") or "=" not in subst_expr:
        return value

    body = subst_expr[1:]
    eq_idx = body.find("=")
    if eq_idx == -1:
        return value

    old_pat = body[:eq_idx]
    new_str = body[eq_idx + 1:]

    if old_pat.startswith("*"):
        match_pat = old_pat[1:]
        idx = value.lower().find(match_pat.lower())
        if idx != -1:
            return new_str + value[idx + len(match_pat):]
        return value

    if not old_pat:
        return value

    # Case-insensitive replacement
    pattern = re.compile(re.escape(old_pat), re.IGNORECASE)
    return pattern.sub(lambda _: new_str, value)


def resolve_env_bootstrapping(
    text: str, custom_env: Optional[Dict[str, str]] = None
) -> Tuple[str, int]:
    """
    Resolves bootstrap environment variable slices and expansions (%ENV:~offset,len%)
    often used in BatchEncryption preambles to dynamically reconstruct '@set '=.
    """
    env = dict(WINDOWS_BOOTSTRAP_ENV)
    if custom_env:
        for k, v in custom_env.items():
            env[k.lower()] = v

    substitutions_made = 0

    # Pattern for %VAR:~slice% or %VAR:old=new% or %VAR%
    pat = re.compile(r"%([a-zA-Z0-9_\(\)]+)(:[^%]+)?%")

    def _repl(m: re.Match) -> str:
        nonlocal substitutions_made
        vname = m.group(1).lower()
        spec = m.group(2)

        if vname not in env:
            return m.group(0)

        val = env[vname]
        if not spec:
            substitutions_made += 1
            return val

        if spec.startswith(":~"):
            resolved = eval_batch_slice(val, spec)
            substitutions_made += 1
            return resolved
        elif spec.startswith(":") and "=" in spec:
            resolved = eval_batch_subst(val, spec)
            substitutions_made += 1
            return resolved

        return m.group(0)

    # Resolve up to 4 passes for nested env references
    curr = text
    for _ in range(4):
        prev = curr
        curr = pat.sub(_repl, curr)
        if curr == prev:
            break

    return curr, substitutions_made


def detect_bedecode_signatures(script_text: str) -> Dict[str, Any]:
    """
    Detects Batch-Encryption-DeCoder (BEDeCode) / BatchEncryption obfuscation patterns:
      1. Special variable assignments: @set '=<table...>, set '=...
      2. High density of slices targeting single-quote or symbol variables (%'~offset,len%)
      3. Environment bootstrapping preambles (%ALLUSERSPROFILE:~...%)
      4. Dynamic %VAR:old=new% cipher synthesis
      5. Multi-stage nested encryption headers
    """
    indicators: List[str] = []
    signatures: Dict[str, bool] = {}
    confidence = 0.0

    # Pattern 1: @set '=<table...> or set '=<table...>
    has_quote_var = bool(re.search(r'(?:^|[;&@\(\)\s])set\s+[\'\"`~!#\$\%\&\*\+\,\-\.\/\:\;\<\=\>\?\[\\\]\^\_\{|\}]\s*=', script_text, re.IGNORECASE))
    signatures["special_var_table"] = has_quote_var
    if has_quote_var:
        indicators.append("Single-character symbol table assignment (@set '=...) detected")
        confidence += 0.35

    # Pattern 2: High density of %'~...% or %':~...% slices
    quote_slices = re.findall(r"%[\'\"`~!#\$\%\&\*\+\,\-\.\/\:\;\<\=\>\?\[\\\]\^\_\{|\}](?::?~|:)[^%]+%", script_text)
    signatures["symbol_slices"] = len(quote_slices) > 0
    if quote_slices:
        indicators.append(f"High-density symbol slices detected ({len(quote_slices)} references)")
        confidence += min(0.35, len(quote_slices) * 0.05)

    # Pattern 3: Dynamic string substitution (%VAR:old=new%)
    subst_matches = re.findall(r"%[a-zA-Z0-9_\'\"]+:[^%]+=.*?%", script_text)
    signatures["substitution_cipher"] = len(subst_matches) > 0
    if subst_matches:
        indicators.append(f"Dynamic string replacement cipher detected ({len(subst_matches)} references)")
        confidence += min(0.35, 0.20 + len(subst_matches) * 0.05)

    # Pattern 4: Environment bootstrap slices (%ALLUSERSPROFILE:~...%, %CommonProgramFiles:~...%)
    bootstrap_matches = re.findall(r"%(?:allusersprofile|programfiles|commonprogramfiles|systemroot|comspec|appdata):~[^%]+%", script_text, re.IGNORECASE)
    signatures["env_bootstrapping"] = len(bootstrap_matches) > 0
    if bootstrap_matches:
        indicators.append(f"Pre-seeded environment variable bootstrap slices ({len(bootstrap_matches)} matches)")
        confidence += 0.20

    is_bedecode = (
        (has_quote_var and len(quote_slices) > 0)
        or has_quote_var
        or (len(quote_slices) >= 2)
        or (len(subst_matches) > 0)
        or (confidence >= 0.30)
    )
    confidence = min(1.0, confidence)

    return {
        "is_bedecode": is_bedecode,
        "confidence": round(confidence, 3),
        "indicators": indicators,
        "signatures": signatures,
        "quote_slices_count": len(quote_slices),
        "substitution_count": len(subst_matches),
    }


def extract_bedecode_tables(text: str) -> Dict[str, str]:
    """
    Extracts variable character mapping tables (@set '=<value>, set "VAR=<value>").
    Handles caret unescaping and delimiter splitting.
    """
    tables: Dict[str, str] = {}
    pat = re.compile(
        r'(?:^|[;&@\(\)\s])set(?:\s+(?:/[ap]\s+)?|/[ap]\s*)'
        r'(?:\"([^\r\n=\"]+)=([^\"\r\n]*)\"?|([^\r\n=\s]+)=([^\r\n]*))',
        re.IGNORECASE,
    )

    for m in pat.finditer(text):
        if m.group(1) is not None:
            vname = m.group(1).strip().lower()
            val = m.group(2)
        else:
            vname = m.group(3).strip().lower()
            val = m.group(4)

        if vname and val is not None:
            clean_val = clean_bedecode_escapes(val)
            tables[vname] = clean_val

    return tables


def resolve_bedecode_slices(text: str, tables: Dict[str, str]) -> Tuple[str, int]:
    """
    Resolves slicing and substitution on extracted character mapping tables.
    Matches %VAR:~slice% and %VAR:old=new% where VAR is in tables.
    """
    if not tables:
        return text, 0

    substitutions_made = 0
    # Support arbitrary variable names including single quote and punctuation
    pat = re.compile(r"%([^%:\r\n~]+)((?::?~|:)[^%\r\n]+)?%")

    def _repl(m: re.Match) -> str:
        nonlocal substitutions_made
        vname = m.group(1).strip().lower()
        spec = m.group(2)

        if vname not in tables:
            return m.group(0)

        val = tables[vname]
        if not spec:
            substitutions_made += 1
            return val

        if spec.startswith(":~") or spec.startswith("~"):
            resolved = eval_batch_slice(val, spec)
            substitutions_made += 1
            return resolved
        elif spec.startswith(":") and "=" in spec:
            resolved = eval_batch_subst(val, spec)
            substitutions_made += 1
            return resolved

        return m.group(0)

    curr = text
    for _ in range(6):
        prev = curr
        curr = pat.sub(_repl, curr)
        if curr == prev:
            break

    return curr, substitutions_made


def unwrap_bedecode_inline_stub(
    script_text: str, max_layers: int = 10, custom_env: Optional[Dict[str, str]] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Recursively unrolls nested BatchEncryption / BEDeCode onion stubs:
      1. Pre-resolves environment bootstrapping (e.g. %ALLUSERSPROFILE:~...%)
      2. Extracts key tables (@set '=<alphabet>)
      3. Inlines slice references (%'~offset,len%)
      4. Detects subsequent layers (@set ' revealed after first decode)
      5. Cleans up dead preambles and table assignments
    """
    curr = script_text
    total_slices_resolved = 0
    layers_unwrapped = 0
    extracted_tables: Dict[str, str] = {}
    history: List[Dict[str, Any]] = []

    # Step 1: Pre-resolve environment variable bootstrapping
    curr, env_subs = resolve_env_bootstrapping(curr, custom_env=custom_env)

    # Step 2: Iterative onion layer unrolling
    for layer in range(1, max_layers + 1):
        prev = curr
        tables = extract_bedecode_tables(curr)
        if not tables:
            break

        extracted_tables.update(tables)
        curr, subs = resolve_bedecode_slices(curr, tables)
        total_slices_resolved += subs

        if subs > 0:
            layers_unwrapped += 1
            history.append({
                "layer": layer,
                "tables_count": len(tables),
                "slices_resolved": subs,
                "delta": len(prev) - len(curr),
            })

        # Strip redundant key definition lines if all their references were resolved
        cleaned_lines = []
        for line in curr.splitlines():
            s_line = line.strip()
            # If line is purely a table assignment that has been resolved, filter it
            if re.match(r"^@?set\s+[\'\"`~!#\$\%\&\*\+\,\-\.\/\:\;\<\=\>\?\[\\\]\^\_\{|\}]\s*=", s_line, re.IGNORECASE):
                # Check if this variable is still referenced downstream
                m = re.match(r"^@?set\s+([^\s=]+)=", s_line, re.IGNORECASE)
                if m:
                    vn = m.group(1).strip()
                    if f"%{vn}" not in curr.replace(line, ""):
                        continue
            cleaned_lines.append(line)

        curr = "\n".join(cleaned_lines)
        if curr == prev or subs == 0:
            break

    # Final pass: Strip leading noise preambles like '&cls' or empty lines
    curr = re.sub(r"^\s*&cls\s*", "", curr, flags=re.IGNORECASE)

    # Cryptographically wipe extracted tables in memory
    zeroize_dict(extracted_tables)

    meta = {
        "layers_unwrapped": layers_unwrapped,
        "env_bootstraps_resolved": env_subs,
        "slices_resolved": total_slices_resolved,
        "layer_history": history,
    }
    return curr, meta


def inspect_bedecode_pe(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Static forensic analysis of PE executables to detect and unpack Batch-to-EXE
    or BEDeCode runtime wrapper binaries without executing them.
    """
    if len(raw_bytes) < 0x100 or raw_bytes[:2] != b"MZ":
        return {"is_pe": False, "family": "Not a PE binary"}

    e_lfanew = struct.unpack_from("<I", raw_bytes, 0x3C)[0]
    if e_lfanew + 24 > len(raw_bytes) or raw_bytes[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return {"is_pe": False, "family": "Invalid PE header"}

    num_sections = struct.unpack_from("<H", raw_bytes, e_lfanew + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", raw_bytes, e_lfanew + 20)[0]
    sec_table_off = e_lfanew + 24 + opt_hdr_size

    sections = []
    max_end_offset = 0
    for i in range(num_sections):
        off = sec_table_off + i * 40
        if off + 40 > len(raw_bytes):
            break
        name = raw_bytes[off:off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", raw_bytes, off + 8)
        end_off = rptr + rsize
        if end_off > max_end_offset:
            max_end_offset = end_off
        sections.append({
            "name": name,
            "raw_size": rsize,
            "raw_ptr": hex(rptr),
            "end_offset": end_off,
        })

    overlay_size = max(0, len(raw_bytes) - max_end_offset)
    overlay_bytes = raw_bytes[max_end_offset:] if overlay_size > 0 else b""

    # Triage known wrappers
    family = "Standard PE Executable"
    indicators: List[str] = []
    extracted_script: Optional[str] = None

    if b"MSVBVM60.DLL" in raw_bytes and b"ThunRTMain" in raw_bytes:
        family = "VB6 Native Compiled Batch Tool (BEDeCode / cnHopeStudio Stub)"
        indicators.append("MSVBVM60 ThunRTMain VB6 entry point verified")
        if b"BatchEncryption" in raw_bytes:
            indicators.append("BatchEncryption string table signature detected")

    if b"Bat2Exe" in raw_bytes or b"_CorExeMain" in raw_bytes:
        family = "Bat2Exe .NET CLR Wrapper Stub"
        indicators.append("Bat2Exe .NET metadata signatures detected")

    # Static extraction from overlay or strings
    # Search for embedded batch script markers: '@echo off', '@set ''=', 'cmd.exe /c'
    batch_markers = [b"@echo off", b"@set '=", b"set '=", b"setlocal"]
    for marker in batch_markers:
        off = raw_bytes.find(marker)
        if off != -1:
            indicators.append(f"Embedded batch script signature '{marker.decode('latin1')}' found at offset {hex(off)}")
            # Read until null terminator or non-printable run
            end = off
            while end < len(raw_bytes) and raw_bytes[end] in b"\r\n\t " or (0x20 <= raw_bytes[end] <= 0x7E):
                end += 1
            if end - off > 15:
                extracted_script = raw_bytes[off:end].decode("utf-8", errors="replace")
                break

    return {
        "is_pe": True,
        "family": family,
        "size_bytes": len(raw_bytes),
        "sections_count": len(sections),
        "overlay_size_bytes": overlay_size,
        "indicators": indicators,
        "has_embedded_script": extracted_script is not None,
        "extracted_script_preview": extracted_script[:200] if extracted_script else None,
        "extracted_script": extracted_script,
    }


def normalize_bedecode(
    script_text: str, custom_env: Optional[Dict[str, str]] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    High-level entry point for BEDeCode normalization:
      - Detects BEDeCode signatures
      - Unwraps multi-layer nested inline stubs
      - Resolves dynamic string substitution
      - Gathers forensic telemetry
    """
    sig = detect_bedecode_signatures(script_text)
    if not sig["is_bedecode"] and sig["confidence"] < 0.25:
        return script_text, {
            "detected": False,
            "is_bedecode": False,
            "confidence": sig["confidence"],
            "signatures": sig["signatures"],
            "indicators": sig["indicators"],
            "layers_unwrapped": 0,
            "slices_resolved": 0,
        }

    unwrapped_text, stub_meta = unwrap_bedecode_inline_stub(
        script_text, custom_env=custom_env
    )

    meta = {
        "detected": True,
        "is_bedecode": True,
        "confidence": sig["confidence"],
        "signatures": sig["signatures"],
        "indicators": sig["indicators"],
        "layers_unwrapped": stub_meta["layers_unwrapped"],
        "env_bootstraps_resolved": stub_meta["env_bootstraps_resolved"],
        "slices_resolved": stub_meta["slices_resolved"],
        "layer_history": stub_meta["layer_history"],
    }
    return unwrapped_text, meta


class BEDeCodeNormalizer:
    """Stateful object-oriented normalizer wrapper for BEDeCode unpacker."""

    def __init__(self, custom_env: Optional[Dict[str, str]] = None, max_layers: int = 10):
        self.custom_env = custom_env or {}
        self.max_layers = max_layers

    def detect(self, script_text: str) -> Dict[str, Any]:
        return detect_bedecode_signatures(script_text)

    def normalize(self, script_text: str) -> Tuple[str, Dict[str, Any]]:
        return normalize_bedecode(script_text, custom_env=self.custom_env)

    def inspect_pe(self, raw_bytes: bytes) -> Dict[str, Any]:
        return inspect_bedecode_pe(raw_bytes)
