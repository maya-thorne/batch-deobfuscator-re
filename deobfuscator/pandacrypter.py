#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PandaCrypter & Certutil Multi-Stage Stager Deobfuscator & Forensic Emulation Engine.
Specialized analyzer for Certutil -decode (Base64) & -decodehex (Hexadecimal) pipelines,
PandaCrypter entropy reduction colon-padding neutralization, and embedded payload recovery.

Engineered by Maya Thorne.
"""

import re
import base64
import hashlib
from typing import Dict, Any, Tuple, List, Optional


PANDACRYPTER_INDICATORS = [
    "colon_padding",
    "certutil_decode",
    "certutil_decodehex",
    "findstr_self_extraction",
    "echo_hex_redirection",
    "embedded_b64_comments",
    "embedded_hex_comments",
    "powershell_amsi_bypass",
]

CERTUTIL_FORMAT_NAMES = {
    0: "Standard Hex / Mixed Hex Pairs",
    1: "Base64 with Certificate Header",
    2: "Base64 Raw",
    4: "Continuous Hex (CRYPT_STRING_HEX)",
    11: "Hex with Address Offset (CRYPT_STRING_HEXADDR)",
    12: "Hex with Address & ASCII Dump (CRYPT_STRING_HEXASCIIADDR)",
}


def zeroize_bytes(b: bytearray) -> None:
    """Cryptographically overwrite a mutable bytearray with zeroes."""
    if isinstance(b, bytearray):
        for i in range(len(b)):
            b[i] = 0


def zeroize_dict(d: Dict[Any, Any]) -> None:
    """Overwrite all values in a dictionary and clear its keys."""
    if not isinstance(d, dict):
        return
    for k in list(d.keys()):
        val = d[k]
        if isinstance(val, bytearray):
            zeroize_bytes(val)
        elif isinstance(val, (str, bytes)):
            d[k] = None
        elif isinstance(val, dict):
            zeroize_dict(val)
        elif isinstance(val, list):
            d[k] = []
    d.clear()


def strip_pandacrypter_colon_padding(script_text: str) -> Tuple[str, int]:
    """
    Neutralize PandaCrypter and stager colon-padding blocks.
    PandaCrypter inserts massive blocks of colons (:::...) to lower file entropy.
    Safely prunes repetitive colon lines (3+ colons) while preserving valid batch labels (:label, :EOF).
    """
    lines = script_text.splitlines()
    clean_lines: List[str] = []
    stripped_count = 0

    colon_pat = re.compile(r'^\s*:{3,}\s*$')
    colon_comment_pat = re.compile(r'^\s*:{3,}\s*(.*)$')

    for line in lines:
        if colon_pat.match(line):
            stripped_count += 1
            continue
        m = colon_comment_pat.match(line)
        if m:
            content = m.group(1).strip()
            # If the comment content is just more colons or meaningless punctuation, prune it
            if not content or re.match(r'^[\s\:\-\=\_\*\#\~\+\/]+$', content):
                stripped_count += 1
                continue
            # Otherwise convert to standard rem
            clean_lines.append(f"rem {content}")
            stripped_count += 1
            continue
        clean_lines.append(line)

    return "\n".join(clean_lines), stripped_count


def emulate_certutil_decode(b64_content: str) -> bytes:
    """
    Statically emulate Windows 'certutil -decode' Base64 extraction.
    Handles certificate headers, comments (::B64:, rem), whitespace, and padding.
    """
    lines = b64_content.splitlines()
    filtered_lines: List[str] = []
    in_cert = False

    for line in lines:
        s = line.strip()
        if "BEGIN CERTIFICATE" in s or "BEGIN NEW CERTIFICATE" in s:
            in_cert = True
            continue
        if "END CERTIFICATE" in s or "END NEW CERTIFICATE" in s:
            in_cert = False
            continue
        # Strip common comment markers
        s = re.sub(r'^(?:::(?:B64|PAYLOAD|ENC)?:?|rem\s+)', '', s, flags=re.IGNORECASE).strip()
        # Clean inline quotes
        s = s.replace('"', '').replace("'", "")
        if s and re.match(r'^[A-Za-z0-9+/=\s]+$', s):
            filtered_lines.append(s)

    joined = "".join(filtered_lines).replace(" ", "").replace("\t", "").replace("\r", "").replace("\n", "")
    if not joined:
        return b""

    # Fix base64 padding if needed
    missing_padding = len(joined) % 4
    if missing_padding:
        joined += "=" * (4 - missing_padding)

    try:
        return base64.b64decode(joined, validate=False)
    except Exception:
        # Fallback lenient regex search for base64 blocks
        m = re.search(r'[A-Za-z0-9+/]{8,}={0,2}', joined)
        if m:
            try:
                candidate = m.group(0)
                pad = len(candidate) % 4
                if pad:
                    candidate += "=" * (4 - pad)
                return base64.b64decode(candidate, validate=False)
            except Exception:
                pass
        return b""


def emulate_certutil_decodehex(hex_content: str, format_id: int = 0) -> bytes:
    """
    Statically emulate Windows 'certutil -decodehex' hexadecimal conversion.
    Supports:
      - Format 0: Default mixed hex pairs (spaced, dash-delimited, continuous)
      - Format 4: Pure hex raw string
      - Format 11: Hex with address offsets (0000 4d 5a ...)
      - Format 12: Hex with address offsets and right-hand ASCII preview dump
    """
    lines = hex_content.splitlines()
    byte_values: List[int] = []

    for line in lines:
        s = line.strip()
        if not s:
            continue
        # Strip batch comment prefixes like ::HEX: or rem
        s = re.sub(r'^(?:::(?:HEX|PAYLOAD)?:?|rem\s+)', '', s, flags=re.IGNORECASE).strip()
        if not s:
            continue

        # Check for address-prefixed format (e.g. 0000: 4d 5a 90... or 00000000  4d 5a ...)
        # Regex captures: optional address, followed by 1 to 16 hex byte pairs
        addr_match = re.match(r'^(?:0x)?(?:[0-9a-fA-F]{4,8}[:\s]+)((?:[0-9a-fA-F]{2}[\s\-]+)+)(?:.*)?$', s)
        if addr_match:
            hex_part = addr_match.group(1)
            pairs = re.findall(r'[0-9a-fA-F]{2}', hex_part)
            for p in pairs:
                try:
                    byte_values.append(int(p, 16))
                except ValueError:
                    pass
            continue

        # Check for comma-separated 0x.. format: 0x48, 0x65, 0x6c
        if "0x" in s.lower():
            hex_tokens = re.findall(r'0x([0-9a-fA-F]{1,2})', s, flags=re.IGNORECASE)
            if hex_tokens:
                for h in hex_tokens:
                    try:
                        byte_values.append(int(h, 16))
                    except ValueError:
                        pass
                continue

        # Standard space, dash, or tab separated hex pairs: 4d 5a 90 00 or 4d-5a-90-00
        # If line has right-hand ASCII dump without strict address, split by 2+ spaces or limit to valid hex
        tokens = re.split(r'[\s\-]+', s)
        valid_line_pairs = []
        for t in tokens:
            if re.fullmatch(r'[0-9a-fA-F]{2}', t):
                valid_line_pairs.append(t)
            elif re.fullmatch(r'[0-9a-fA-F]{4}', t):
                valid_line_pairs.append(t[:2])
                valid_line_pairs.append(t[2:])
            else:
                # Stop if non-hex token encountered (likely ASCII dump column)
                if valid_line_pairs:
                    break

        if valid_line_pairs:
            for p in valid_line_pairs:
                try:
                    byte_values.append(int(p, 16))
                except ValueError:
                    pass
            continue

        # Continuous unbroken hex string on the line: 4d5a9000...
        clean_s = re.sub(r'[^0-9a-fA-F]', '', s)
        if len(clean_s) >= 2 and len(clean_s) % 2 == 0:
            for i in range(0, len(clean_s), 2):
                try:
                    byte_values.append(int(clean_s[i:i+2], 16))
                except ValueError:
                    pass

    return bytes(byte_values)


def extract_embedded_payloads_from_comments(script_text: str) -> Dict[str, str]:
    """
    Extract embedded base64 or hex payloads hidden in batch comments or trailers.
    Detects markers like ::B64:, ::HEX:, ::PAYLOAD:, -----BEGIN CERTIFICATE-----,
    or dense base64/hex blocks placed after exit /b.
    """
    lines = script_text.splitlines()
    b64_lines: List[str] = []
    hex_lines: List[str] = []
    generic_payload_lines: List[str] = []
    in_cert = False

    for line in lines:
        s = line.strip()
        if "BEGIN CERTIFICATE" in s:
            in_cert = True
            b64_lines.append(s)
            continue
        if "END CERTIFICATE" in s:
            in_cert = False
            b64_lines.append(s)
            continue
        if in_cert:
            b64_lines.append(s)
            continue

        if re.match(r'^\s*::\s*B64:', line, re.IGNORECASE):
            b64_lines.append(re.sub(r'^\s*::\s*B64:\s*', '', line, flags=re.IGNORECASE))
        elif re.match(r'^\s*::\s*HEX:', line, re.IGNORECASE):
            hex_lines.append(re.sub(r'^\s*::\s*HEX:\s*', '', line, flags=re.IGNORECASE))
        elif re.match(r'^\s*::\s*PAYLOAD:', line, re.IGNORECASE):
            content = re.sub(r'^\s*::\s*PAYLOAD:\s*', '', line, flags=re.IGNORECASE).strip()
            generic_payload_lines.append(content)
        elif re.match(r'^\s*::\s*[A-Za-z0-9+/=]{32,}\s*$', line):
            # Dense base64 comment line
            content = re.sub(r'^\s*::\s*', '', line).strip()
            b64_lines.append(content)
        elif re.match(r'^\s*::\s*(?:[0-9a-fA-F]{2}[\s\-]){8,}[0-9a-fA-F]{2}\s*$', line):
            # Dense hex comment line
            content = re.sub(r'^\s*::\s*', '', line).strip()
            hex_lines.append(content)

    results: Dict[str, str] = {}
    if b64_lines:
        results["b64"] = "\n".join(b64_lines)
    if hex_lines:
        results["hex"] = "\n".join(hex_lines)
    if generic_payload_lines:
        results["payload"] = "\n".join(generic_payload_lines)
    return results


def trace_virtual_staged_files(script_text: str, custom_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Statically trace virtual files constructed via echo / findstr redirections in the batch file.
    Tracks:
      - echo <text> > <filepath>
      - echo <text> >> <filepath>
      - findstr ... > <filepath>
    """
    env = custom_env or {}
    lines = script_text.splitlines()
    staged_files: Dict[str, List[str]] = {}

    def normalize_target_name(raw_name: str) -> str:
        # Resolve variables like %temp%, %tmp% if possible
        name = raw_name.strip().strip('"').strip("'")
        for k, v in env.items():
            name = re.sub(rf'%{re.escape(k)}%', lambda _m, val=v: val, name, flags=re.IGNORECASE)
        # Normalize to lower basename or normalized relative name for safe matching
        return name.replace('\\', '/').split('/')[-1].lower()

    # Echo pattern: echo <payload> >[>] <file> or (echo <payload>) >[>] <file>
    echo_pat = re.compile(r'^\s*(?:\()?\s*echo\s+(.*?)\s*(?:>>|>)\s*(\S+)\s*(?:\))?$', re.IGNORECASE)
    # Findstr self-extraction pattern: findstr ... "%~f0" > <file>
    findstr_pat = re.compile(r'findstr\s+(?:/[a-z]\s+)*(?:"([^"]+)"|\'([^\']+)\'|(\S+))\s+(?:"?%~?[f0123456789a-zA-Z]+"?|\S+)\s*>\s*(\S+)', re.IGNORECASE)

    # Pre-extract embedded comment payloads in case findstr targets self
    embedded_comments = extract_embedded_payloads_from_comments(script_text)

    for line in lines:
        s = line.strip()
        if not s:
            continue

        # Check findstr extraction
        fm = findstr_pat.search(s)
        if fm:
            query = fm.group(1) or fm.group(2) or fm.group(3) or ""
            target_file = fm.group(4)
            key = normalize_target_name(target_file)
            if "hex" in query.lower() or "hex" in key:
                content = embedded_comments.get("hex", "")
                if not content and "payload" in embedded_comments:
                    content = embedded_comments["payload"]
                staged_files[key] = [content] if content else []
            else:
                content = embedded_comments.get("b64", "")
                if not content and "payload" in embedded_comments:
                    content = embedded_comments["payload"]
                staged_files[key] = [content] if content else []
            continue

        # Check echo redirection
        em = echo_pat.match(s)
        if em:
            text_part = em.group(1).strip()
            target_file = em.group(2).strip()
            key = normalize_target_name(target_file)
            # Strip outer quotes if echo "..."
            if text_part.startswith('"') and text_part.endswith('"') and len(text_part) >= 2:
                text_part = text_part[1:-1]
            if key not in staged_files:
                staged_files[key] = []
            staged_files[key].append(text_part)

    # Join lines for each file
    return {k: "\n".join(v) for k, v in staged_files.items()}


def detect_certutil_signatures(script_text: str) -> Dict[str, Any]:
    """
    Detect Certutil usage signatures and command invocations in batch code.
    Robustly handles carets (c^e^r^t^u^t^i^l), quotes, and delimiters.
    """
    # Normalize carets and empty quotes for signature scanning
    normalized = re.sub(r'\^', '', script_text)
    normalized = re.sub(r'\"\"', '', normalized)

    certutil_calls = re.findall(r'\bcertutil\b', normalized, flags=re.IGNORECASE)
    decode_matches = re.findall(r'-(?:f\s+)?decode\b', normalized, flags=re.IGNORECASE)
    decodehex_matches = re.findall(r'-(?:f\s+)?decodehex\b', normalized, flags=re.IGNORECASE)
    encode_matches = re.findall(r'-(?:f\s+)?encode\b', normalized, flags=re.IGNORECASE)

    is_certutil = bool(certutil_calls or decode_matches or decodehex_matches)
    confidence = 0.0
    if is_certutil:
        confidence = 0.7
        if decodehex_matches or decode_matches:
            confidence = 0.95

    return {
        "is_certutil": is_certutil,
        "confidence": confidence,
        "certutil_calls_count": len(certutil_calls),
        "decode_count": len(decode_matches),
        "decodehex_count": len(decodehex_matches),
        "encode_count": len(encode_matches),
    }


def detect_pandacrypter_signatures(script_text: str) -> Dict[str, Any]:
    """
    Detect PandaCrypter and advanced Certutil/PowerShell batch stager patterns.
    Indicators:
      - Heavy colon padding (:::...)
      - findstr self-extraction (%~f0)
      - certutil -decode or -decodehex invocation
      - Embedded base64/hex payload comments
      - Staged file invocation (call %temp%\\..., powershell -File %temp%\\...)
    """
    indicators: List[str] = []
    lines = script_text.splitlines()

    colon_padding_count = sum(1 for line in lines if re.match(r'^\s*:{3,}', line))
    if colon_padding_count >= 2:
        indicators.append("colon_padding")

    if re.search(r'findstr\s+.*%~?[f0]', script_text, re.IGNORECASE):
        indicators.append("findstr_self_extraction")

    cu_sig = detect_certutil_signatures(script_text)
    if cu_sig["decode_count"] > 0:
        indicators.append("certutil_decode")
    if cu_sig["decodehex_count"] > 0:
        indicators.append("certutil_decodehex")

    if re.search(r'echo\s+[0-9a-fA-F\s]{10,}\s*>>?', script_text):
        indicators.append("echo_hex_redirection")

    embedded = extract_embedded_payloads_from_comments(script_text)
    if "b64" in embedded or "payload" in embedded:
        indicators.append("embedded_b64_comments")
    if "hex" in embedded:
        indicators.append("embedded_hex_comments")

    if re.search(r'\[Ref\]\.Assembly\.GetType\(.*AmsiUtils', script_text, re.IGNORECASE) or "amsiInitFailed" in script_text:
        indicators.append("powershell_amsi_bypass")

    confidence = min(1.0, len(indicators) * 0.25)
    is_pandacrypter = ("colon_padding" in indicators and ("certutil_decode" in indicators or "certutil_decodehex" in indicators or "findstr_self_extraction" in indicators)) or len(indicators) >= 3

    return {
        "is_pandacrypter": is_pandacrypter,
        "confidence": confidence,
        "indicators": indicators,
        "colon_padding_count": colon_padding_count,
        "embedded_payload_types": list(embedded.keys()),
    }


def emulate_certutil_staging(script_text: str, custom_env: Optional[Dict[str, str]] = None) -> Tuple[str, Dict[str, Any]]:
    """
    Emulate Certutil -decode / -decodehex staging pipelines.
    Extracts staged source inputs, decodes hexadecimal or base64 streams,
    generates structured telemetry, and inlines decoded script commands.
    """
    env = custom_env or {}
    staged_files = trace_virtual_staged_files(script_text, env)
    embedded_comments = extract_embedded_payloads_from_comments(script_text)

    # Normalize command lines for certutil pattern matching
    lines = script_text.splitlines()
    processed_lines: List[str] = []
    decoded_payloads: List[Dict[str, Any]] = []

    # Regex to capture certutil command: certutil [options] -decode[hex] [-f] <infile> <outfile> [format]
    # Carets removed during inspection
    certutil_cmd_pat = re.compile(
        r'certutil(?:\.exe)?\s+(?:/[a-z0-9\-]+\s+|-v\s+)*'
        r'-(?:f\s+)?(decodehex|decode)\s+(?:-f\s+)?'
        r'(\S+)\s+(\S+)(?:\s+([0-9]+))?',
        re.IGNORECASE
    )

    call_staged_pat = re.compile(r'^\s*(?:call|start|cmd\s+/c|type\s+\S+\s*\|\s*cmd)\s+(\S+)', re.IGNORECASE)

    decoded_file_map: Dict[str, Dict[str, Any]] = {}

    def get_base_name(p: str) -> str:
        clean = p.strip('"').strip("'").replace('\\', '/').split('/')[-1].lower()
        for k, v in env.items():
            clean = re.sub(rf'%{re.escape(k)}%', lambda _m, val=v: val, clean, flags=re.IGNORECASE)
        return clean.replace('\\', '/').split('/')[-1].lower()

    for line in lines:
        stripped_line = re.sub(r'\^', '', line)
        stripped_line = re.sub(r'\"\"', '', stripped_line)

        m = certutil_cmd_pat.search(stripped_line)
        if m:
            mode = m.group(1).lower()  # 'decode' or 'decodehex'
            in_file_raw = m.group(2)
            out_file_raw = m.group(3)
            fmt_id = int(m.group(4)) if m.group(4) else 0

            in_key = get_base_name(in_file_raw)
            out_key = get_base_name(out_file_raw)

            # Retrieve content to decode
            raw_input = staged_files.get(in_key, "")
            if not raw_input:
                # Fallback to embedded comments if matched by name or general
                if "hex" in in_key and "hex" in embedded_comments:
                    raw_input = embedded_comments["hex"]
                elif "b64" in embedded_comments:
                    raw_input = embedded_comments["b64"]
                elif "payload" in embedded_comments:
                    raw_input = embedded_comments["payload"]

            decoded_bytes = b""
            if mode == "decodehex":
                decoded_bytes = emulate_certutil_decodehex(raw_input, fmt_id)
            else:
                decoded_bytes = emulate_certutil_decode(raw_input)

            if decoded_bytes:
                sha256_hash = hashlib.sha256(decoded_bytes).hexdigest()
                is_pe = decoded_bytes.startswith(b"MZ")
                decoded_text = ""
                try:
                    decoded_text = decoded_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    try:
                        decoded_text = decoded_bytes.decode("latin-1")
                    except Exception:
                        decoded_text = ""

                info = {
                    "in_file": in_file_raw,
                    "out_file": out_file_raw,
                    "mode": mode,
                    "format_id": fmt_id,
                    "format_desc": CERTUTIL_FORMAT_NAMES.get(fmt_id, "Unknown Format"),
                    "size_bytes": len(decoded_bytes),
                    "sha256": sha256_hash,
                    "is_pe": is_pe,
                    "preview": decoded_text[:200] if not is_pe else f"<PE Binary Executable size={len(decoded_bytes)} bytes>",
                    "decoded_text": decoded_text if not is_pe else "",
                }
                decoded_payloads.append(info)
                decoded_file_map[out_key] = info

                # Replace or comment out the certutil staging call
                if is_pe:
                    processed_lines.append(f"rem [PANDACRYPTER / CERTUTIL STAGED BINARY: {out_file_raw} (size={len(decoded_bytes)}, sha256={sha256_hash[:16]}...)]")
                else:
                    processed_lines.append(f"rem [CERTUTIL {mode.upper()} DECODED -> {out_file_raw}]:")
                    for pline in decoded_text.splitlines():
                        if pline.strip():
                            processed_lines.append(pline)
                continue

        # Check if line executes a previously decoded staged file (e.g. call %temp%\\run.bat)
        cm = call_staged_pat.match(stripped_line)
        if cm:
            target_raw = cm.group(1)
            target_key = get_base_name(target_raw)
            if target_key in decoded_file_map:
                info = decoded_file_map[target_key]
                if info["decoded_text"]:
                    processed_lines.append(f"rem [EXECUTION OF STAGED PAYLOAD {target_raw} INLINED BELOW]:")
                    for pline in info["decoded_text"].splitlines():
                        if pline.strip():
                            processed_lines.append(pline)
                    continue

        processed_lines.append(line)

    result_text = "\n".join(processed_lines)
    meta = {
        "decoded_payloads": decoded_payloads,
        "decoded_count": len(decoded_payloads),
        "staged_files_tracked": list(staged_files.keys()),
    }
    return result_text, meta


def normalize_pandacrypter(script_text: str, custom_env: Optional[Dict[str, str]] = None) -> Tuple[str, Dict[str, Any]]:
    """
    Main normalization entry point for PandaCrypter & Certutil Stager scripts.
    1. Neutralizes high-entropy / padding colon comment noise.
    2. Emulates Certutil -decode and -decodehex pipelines.
    3. Inlines and recovers staged payloads.
    4. Gathers comprehensive forensic telemetry.
    """
    env = custom_env or {}
    panda_sig = detect_pandacrypter_signatures(script_text)
    cert_sig = detect_certutil_signatures(script_text)

    # 1. Neutralize colon padding
    cleaned_text, stripped_colons = strip_pandacrypter_colon_padding(script_text)

    # 2. Emulate Certutil staging if signatures or commands detected
    staged_meta: Dict[str, Any] = {"decoded_payloads": [], "decoded_count": 0, "staged_files_tracked": []}
    if cert_sig["is_certutil"] or panda_sig["is_pandacrypter"] or "certutil" in cleaned_text.lower():
        cleaned_text, staged_meta = emulate_certutil_staging(cleaned_text, env)

    telemetry = {
        "is_pandacrypter": panda_sig["is_pandacrypter"],
        "is_certutil": cert_sig["is_certutil"],
        "confidence": max(panda_sig["confidence"], cert_sig["confidence"]),
        "indicators": list(set(panda_sig["indicators"])),
        "colon_padding_stripped": stripped_colons,
        "certutil_signatures": cert_sig,
        "decoded_payloads_count": staged_meta.get("decoded_count", 0),
        "decoded_payloads": staged_meta.get("decoded_payloads", []),
        "staged_files": staged_meta.get("staged_files_tracked", []),
    }

    return cleaned_text, telemetry


class PandaCrypterNormalizer:
    """Object-oriented wrapper for PandaCrypter and Certutil stager normalizer."""

    def __init__(self, custom_env: Optional[Dict[str, str]] = None):
        self.custom_env = custom_env or {}
        self.last_telemetry: Dict[str, Any] = {}

    def normalize(self, script_text: str) -> str:
        clean_text, tele = normalize_pandacrypter(script_text, self.custom_env)
        self.last_telemetry = tele
        return clean_text

    def get_telemetry(self) -> Dict[str, Any]:
        return self.last_telemetry
