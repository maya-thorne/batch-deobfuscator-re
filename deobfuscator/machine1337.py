"""
batobfuscate-machine1337 Header Neutralization & CJK Forensic Deobfuscator.
Specialized heuristics and static normalization for machine1337 evasion techniques:
  1. Multi-BOM & Fake UTF-16LE Header Trap Neutralization (FF FE 26 63 6C 73 0D 0A FF FE 0A 0D).
  2. CRLF, LF, and Big-Endian (FE FF ...) machine1337 header variants.
  3. Transcoded UTF-8 replacement character header recovery (EF BF BD EF BF BD &cls ...).
  4. CJK Transcode Forensics: Inverting Chinese pseudo-text (挦獬਍...) caused by
     premature UTF-16LE editor interpretation back to genuine 8-bit batch commands.
  5. Inline caret unescaping and &cls preamble de-masking.
  6. Cryptographic memory zeroization for temporary analysis buffers.

Engineered by Maya Thorne.
"""

import re
from typing import Dict, List, Tuple, Any, Optional, Union


# Canonical machine1337 header byte sequences
MACHINE1337_HEADER_V1 = bytes.fromhex("FFFE26636C730D0AFFFE0A0D")  # exact from bat.py
MACHINE1337_HEADER_V2 = bytes.fromhex("FFFE26636C730D0AFFFE0D0A")  # standard Windows CRLF
MACHINE1337_HEADER_LF1 = bytes.fromhex("FFFE26636C730AFFFE0A0D")   # Unix LF variant 1
MACHINE1337_HEADER_LF2 = bytes.fromhex("FFFE26636C730AFFFE0A")     # Unix LF variant 2
MACHINE1337_HEADER_TRUNC = bytes.fromhex("FFFE26636C73")            # Truncated BOM + &cls prefix
MACHINE1337_BE_HEADER = bytes.fromhex("FEFF6326736C0A0DFEFF0D0A")  # Big-endian UTF-16 variant

# Transcoded UTF-8 corrupted header (BOMs replaced by 0xEF 0xBF 0xBD, as in TEUEI.bat)
MACHINE1337_UTF8_CORRUPTED_V1 = b"\xef\xbf\xbd\xef\xbf\xbd&cls\x0a\xef\xbf\xbd\xef\xbf\xbd\x0a\x0d"
MACHINE1337_UTF8_CORRUPTED_V2 = b"\xef\xbf\xbd\xef\xbf\xbd&cls\r\n\xef\xbf\xbd\xef\xbf\xbd\r\n"
MACHINE1337_UTF8_PREFIX = b"\xef\xbf\xbd\xef\xbf\xbd&cls"

# Chinese character magic sequence for &cls in UTF-16LE: 0x6326 ('挦') + 0x736C ('獬')
MACHINE1337_CJK_MAGIC = "\u6326\u736c"

# Common batch keywords to validate recovered payloads
BATCH_VALIDATION_TOKENS = [
    r"@echo", r"echo\b", r"set\b", r"cls\b", r"cmd\b", r"powershell\b",
    r"whoami\b", r"curl\b", r"certutil\b", r"rem\b", r"::[^\r\n]*",
    r"pause\b", r"exit\b", r"goto\b", r"call\b", r"timeout\b", r"start\b"
]


def zeroize_bytes(buffer: bytearray) -> None:
    """Cryptographically sanitize raw bytearray buffers in memory."""
    if not isinstance(buffer, (bytearray, memoryview)):
        return
    try:
        for idx in range(len(buffer)):
            buffer[idx] = 0
    except Exception:
        pass


def zeroize_dict(target: Dict[str, Any]) -> None:
    """Cryptographically sanitize dictionary buffers in memory."""
    for key in list(target.keys()):
        val = target[key]
        if isinstance(val, dict):
            zeroize_dict(val)
        elif isinstance(val, list):
            for i in range(len(val)):
                val[i] = None
            val.clear()
        elif isinstance(val, bytearray):
            zeroize_bytes(val)
        target[key] = None
    target.clear()


def is_machine1337_header(data: bytes) -> Tuple[bool, str, int]:
    """
    Check if binary data begins with any known machine1337 header signature.
    Returns:
        Tuple[is_match, header_variant_name, stripped_byte_count]
    """
    if len(data) < 6:
        return False, "none", 0

    if data.startswith(MACHINE1337_HEADER_V1):
        return True, "machine1337-v1-exact", len(MACHINE1337_HEADER_V1)
    if data.startswith(MACHINE1337_HEADER_V2):
        return True, "machine1337-v2-crlf", len(MACHINE1337_HEADER_V2)
    if data.startswith(MACHINE1337_HEADER_LF1):
        return True, "machine1337-lf1", len(MACHINE1337_HEADER_LF1)
    if data.startswith(MACHINE1337_HEADER_LF2):
        return True, "machine1337-lf2", len(MACHINE1337_HEADER_LF2)
    if data.startswith(MACHINE1337_BE_HEADER):
        return True, "machine1337-be", len(MACHINE1337_BE_HEADER)
    if data.startswith(MACHINE1337_UTF8_CORRUPTED_V1):
        return True, "machine1337-utf8-corrupted-v1", len(MACHINE1337_UTF8_CORRUPTED_V1)
    if data.startswith(MACHINE1337_UTF8_CORRUPTED_V2):
        return True, "machine1337-utf8-corrupted-v2", len(MACHINE1337_UTF8_CORRUPTED_V2)
    if data.startswith(MACHINE1337_UTF8_PREFIX):
        # Scan until newline after second corrupted BOM
        match = re.match(rb"^\xef\xbf\xbd\xef\xbf\xbd&cls[\r\n]+(?:\xef\xbf\xbd\xef\xbf\xbd)?[\r\n]*", data)
        if match:
            return True, "machine1337-utf8-prefix-regex", match.end()
        return True, "machine1337-utf8-prefix", len(MACHINE1337_UTF8_PREFIX)
    # Check for double BOM pattern with &cls in between (must have second BOM)
    double_bom_m = re.match(rb"^\xff\xfe(?:&cls|cls)[\r\n]*\xff\xfe[\r\n]*", data, re.IGNORECASE)
    if double_bom_m:
        return True, "machine1337-double-bom-regex", double_bom_m.end()

    return False, "none", 0


def _decode_safely(payload: bytes) -> Tuple[str, str]:
    """Decode raw payload bytes attempting UTF-8, CP1252, CP437, and Latin-1."""
    for enc in ("utf-8", "cp1252", "cp437", "latin-1"):
        try:
            return payload.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return payload.decode("latin-1", errors="replace"), "latin-1"


def neutralize_machine1337_headers(data: bytes) -> Tuple[str, Dict[str, Any]]:
    """
    Strip machine1337 multi-BOM and fake wide-char headers from raw binary script data.
    Recursively strips nested multi-layer headers if applied repeatedly.
    Returns:
        Tuple[clean_text, metadata]
    """
    meta: Dict[str, Any] = {
        "is_machine1337": False,
        "fake_bom_detected": False,
        "header_stripped": False,
        "header_variant": "none",
        "header_pattern": "none",
        "cls_preamble_stripped": False,
        "stripped_bytes": 0,
        "layers_stripped": 0,
        "encoding_used": "utf-8",
    }

    curr_data = data
    total_stripped = 0
    layers = 0
    primary_variant = "none"

    while True:
        matched, variant, byte_count = is_machine1337_header(curr_data)
        if not matched or byte_count == 0:
            break
        if layers == 0:
            primary_variant = variant
        curr_data = curr_data[byte_count:]
        total_stripped += byte_count
        layers += 1

    if layers > 0:
        meta["is_machine1337"] = True
        meta["fake_bom_detected"] = True
        meta["header_stripped"] = True
        meta["header_variant"] = primary_variant
        meta["header_pattern"] = primary_variant
        meta["stripped_bytes"] = total_stripped
        meta["layers_stripped"] = layers

        # Also strip any leading whitespace or stray cls/newline/ampersand artifacts immediately following header
        match = re.match(rb"^\s*(?:&|@)?cls\s*(?:&|[\r\n]+)\s*|^\s*&+\s*|^[\r\n]+", curr_data, re.IGNORECASE)
        if match:
            curr_data = curr_data[match.end():]
            meta["stripped_bytes"] += match.end()
            meta["cls_preamble_stripped"] = True

        text, enc = _decode_safely(curr_data)
        meta["encoding_used"] = enc
        return text, meta

    # Check for generic fake UTF-16LE BOM followed by &cls
    if curr_data.startswith(b"\xff\xfe"):
        # Check if following bytes are ASCII (not genuine UTF-16 nulls)
        sample = curr_data[2:min(len(curr_data), 128)]
        odd_nulls = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)
        if len(sample) >= 4 and (odd_nulls / (len(sample) // 2)) < 0.20:
            # Fake BOM!
            body = curr_data[2:]
            lead_match = re.match(rb"^\s*(?:&|@)?cls\s*(?:&|[\r\n]+)\s*|^\s*&+\s*|^[\r\n]+", body, re.IGNORECASE)
            cut = 2
            if lead_match:
                body = body[lead_match.end():]
                cut += lead_match.end()
                meta["cls_preamble_stripped"] = True
            meta["is_machine1337"] = True
            meta["header_stripped"] = True
            meta["header_variant"] = "machine1337-heuristic-bom"
            meta["stripped_bytes"] = cut
            meta["layers_stripped"] = 1
            text, enc = _decode_safely(body)
            meta["encoding_used"] = enc
            return text, meta

    text, enc = _decode_safely(curr_data)
    meta["encoding_used"] = enc
    return text, meta


def recover_cjk_transcoded_batch(text: str) -> Tuple[str, bool]:
    """
    Detect and recover batch scripts that were mistakenly decoded as UTF-16LE Chinese pseudo-text.
    Example: '挦獬਍﻿ഊ敀档⁯䙏...' -> '@echo OFF\\r\\n...'
    Returns:
        Tuple[recovered_text, was_recovered]
    """
    if not text:
        return text, False

    # Check for signature CJK characters or high CJK code-point density
    has_magic = text.startswith(MACHINE1337_CJK_MAGIC) or MACHINE1337_CJK_MAGIC in text[:64]
    
    # Calculate density of CJK Unified Ideographs (0x4E00 - 0x9FFF) in first 200 chars
    prefix_sample = text[:min(len(text), 200)]
    cjk_count = sum(1 for ch in prefix_sample if 0x4E00 <= ord(ch) <= 0x9FFF or ord(ch) in (0x0A0D, 0x0D0A, 0xFEFF))
    cjk_ratio = cjk_count / max(1, len(prefix_sample))

    if not has_magic and cjk_ratio < 0.40:
        return text, False

    # Attempt to re-encode as UTF-16LE to obtain the original 8-bit stream
    try:
        raw_bytes = text.encode("utf-16le")
    except Exception:
        return text, False

    # Strip machine1337 header bytes from the reconstructed raw bytes
    matched, _, byte_count = is_machine1337_header(raw_bytes)
    if matched and byte_count > 0:
        raw_bytes = raw_bytes[byte_count:]
    elif raw_bytes.startswith(b"\xff\xfe"):
        raw_bytes = raw_bytes[2:]

    # Strip leading &cls / cls artifacts
    lead_m = re.match(rb"^(?:&cls\s*[\r\n]*|cls\s*[\r\n]*|[\r\n]+)", raw_bytes)
    if lead_m:
        raw_bytes = raw_bytes[lead_m.end():]

    decoded_text, _ = _decode_safely(raw_bytes)

    # Validate that the recovered text contains valid batch keywords
    keyword_hits = 0
    for pat in BATCH_VALIDATION_TOKENS:
        if re.search(pat, decoded_text, re.IGNORECASE):
            keyword_hits += 1

    if keyword_hits >= 1 or len(decoded_text.splitlines()) > 1:
        return decoded_text, True

    return text, False


def normalize_machine1337_carets_and_preamble(text: str) -> Tuple[str, Dict[str, Any]]:
    """
    Neutralize inline caret scrambling and &cls command preambles typical of machine1337 scripts.
    Example: '&cls & c^m^d /c p^o^w^e^r^s^h^e^l^l' -> 'cmd /c powershell'
    Returns:
        Tuple[clean_text, metadata]
    """
    meta = {
        "cls_preamble_stripped": False,
        "carets_normalized": 0,
    }
    curr = text

    # Strip leading cls / &cls preambles
    preamble_pat = re.compile(r"^\s*(?:&|@)?cls\s*(?:&|\r?\n)+\s*", re.IGNORECASE)
    if preamble_pat.search(curr):
        curr = preamble_pat.sub("", curr)
        meta["cls_preamble_stripped"] = True

    # Strip any leading stray ampersands
    if re.match(r"^\s*&+\s*", curr):
        curr = re.sub(r"^\s*&+\s*", "", curr)

    # Normalize inline caret-escaped identifiers outside quotes
    lines = curr.splitlines(keepends=True)
    out_lines = []
    total_carets = 0

    for line in lines:
        if "^" not in line:
            out_lines.append(line)
            continue

        in_quotes = False
        res = []
        i = 0
        n = len(line)
        while i < n:
            ch = line[i]
            if ch == '"':
                in_quotes = not in_quotes
                res.append(ch)
                i += 1
            elif not in_quotes and ch == '^':
                if i + 1 < n:
                    nxt = line[i + 1]
                    # If next character is alphanumeric or typical command char, strip caret
                    if nxt.isalnum() or nxt in "-_/:.":
                        res.append(nxt)
                        total_carets += 1
                        i += 2
                    elif nxt == '^':
                        # Chained carets: ^^ -> ^
                        res.append('^')
                        total_carets += 1
                        i += 2
                    else:
                        res.append(ch)
                        i += 1
                else:
                    res.append(ch)
                    i += 1
            else:
                res.append(ch)
                i += 1
        out_lines.append("".join(res))

    meta["carets_normalized"] = total_carets
    return "".join(out_lines), meta


def detect_machine1337_signatures(data_or_text: Union[bytes, str, None], text_hint: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform heuristic signature detection for batobfuscate-machine1337 techniques.
    Analyzes binary headers, UTF-8 corrupted BOMs, CJK transcode pseudo-text, and caret obfuscation.
    Returns:
        Telemetry dictionary with detection confidence and specific indicators.
    """
    sig = {
        "is_machine1337": False,
        "confidence": 0.0,
        "indicators": [],
        "variant": "none",
        "has_raw_header": False,
        "has_cjk_transcode": False,
        "has_utf8_corrupted_header": False,
        "has_cls_preamble": False,
        "has_caret_scramble": False,
    }

    score = 0.0
    text = ""
    raw_bytes = None

    if isinstance(data_or_text, bytes):
        raw_bytes = data_or_text
        text = text_hint or ""
    elif isinstance(data_or_text, str):
        text = data_or_text
    elif text_hint:
        text = text_hint

    # Check raw bytes if available
    if raw_bytes:
        matched, variant, _ = is_machine1337_header(raw_bytes)
        if matched:
            sig["has_raw_header"] = True
            sig["variant"] = variant
            score += 0.85
            sig["indicators"].append(f"binary-header:{variant}")

    # Check text for CJK pseudo-text
    if text:
        if text.startswith(MACHINE1337_CJK_MAGIC) or MACHINE1337_CJK_MAGIC in text[:64]:
            sig["has_cjk_transcode"] = True
            score += 0.90
            sig["indicators"].append("cjk-transcode-magic:\u6326\u736c")
        elif sum(1 for ch in text[:100] if 0x4E00 <= ord(ch) <= 0x9FFF) >= 15:
            sig["has_cjk_transcode"] = True
            score += 0.70
            sig["indicators"].append("cjk-density-elevation")

        # Check for UTF-8 corrupted replacement characters (EF BF BD)
        if "\ufffd\ufffd&cls" in text[:64] or "\ufffd\ufffd" in text[:32]:
            sig["has_utf8_corrupted_header"] = True
            score += 0.80
            sig["indicators"].append("utf8-corrupted-bom-chars")

        # Check for &cls preamble
        if re.search(r"^\s*(?:&|@)?cls\s*(?:&|\r?\n)+", text, re.IGNORECASE):
            sig["has_cls_preamble"] = True
            score += 0.25
            sig["indicators"].append("cls-command-preamble")

        # Check for inline caret scrambling on common commands
        if re.search(r"(?:c\^m\^d|p\^o\^w\^e\^r\^s\^h\^e\^l\^l|w\^h\^o\^a\^m\^i|c\^e\^r\^t\^u\^t\^i\^l)", text, re.IGNORECASE):
            sig["has_caret_scramble"] = True
            score += 0.35
            sig["indicators"].append("caret-scrambled-keywords")

    sig["confidence"] = min(1.0, round(score, 2))
    sig["is_machine1337"] = sig["confidence"] >= 0.50
    return sig


def normalize_machine1337(data_or_text: Union[bytes, str], custom_env: Optional[Dict[str, str]] = None) -> Tuple[str, Dict[str, Any]]:
    """
    High-level normalization pipeline for batobfuscate-machine1337.
    Accepts raw binary bytes or text string, removes fake headers, recovers CJK transcoded
    batch commands, and normalizes inline carets & preambles.
    Returns:
        Tuple[clean_script_text, forensic_telemetry]
    """
    telemetry: Dict[str, Any] = {
        "signatures": {},
        "is_machine1337": False,
        "confidence": 0.0,
        "indicators": [],
        "header_stripped": False,
        "header_variant": "none",
        "stripped_bytes": 0,
        "cjk_recovered": False,
        "cls_preamble_stripped": False,
        "carets_normalized": 0,
        "encoding_used": "utf-8",
    }

    # Step 1: Binary header neutralization if bytes provided
    if isinstance(data_or_text, bytes):
        curr_text, header_meta = neutralize_machine1337_headers(data_or_text)
        telemetry.update({
            "header_stripped": header_meta["header_stripped"],
            "header_variant": header_meta["header_variant"],
            "stripped_bytes": header_meta["stripped_bytes"],
            "encoding_used": header_meta["encoding_used"],
            "cls_preamble_stripped": header_meta.get("cls_preamble_stripped", False),
        })
    else:
        curr_text = data_or_text

    # Step 2: Signature detection
    sig = detect_machine1337_signatures(data_or_text if isinstance(data_or_text, bytes) else None, curr_text)
    telemetry["signatures"] = sig
    telemetry["is_machine1337"] = sig["is_machine1337"]
    telemetry["confidence"] = sig["confidence"]
    telemetry["indicators"] = sig["indicators"]

    # Step 3: CJK transcode recovery
    curr_text, was_cjk = recover_cjk_transcoded_batch(curr_text)
    if was_cjk:
        telemetry["cjk_recovered"] = True
        telemetry["is_machine1337"] = True
        telemetry["confidence"] = max(telemetry["confidence"], 0.95)
        if "cjk-transcode-recovered" not in telemetry["indicators"]:
            telemetry["indicators"].append("cjk-transcode-recovered")

    # Step 4: Caret and &cls preamble normalization
    curr_text, caret_meta = normalize_machine1337_carets_and_preamble(curr_text)
    telemetry["cls_preamble_stripped"] = telemetry["cls_preamble_stripped"] or caret_meta["cls_preamble_stripped"]
    telemetry["carets_normalized"] = caret_meta["carets_normalized"]

    return curr_text.strip(), telemetry


class Machine1337Normalizer:
    """Stateful wrapper class for machine1337 deobfuscation with memory hygiene."""

    def __init__(self, custom_env: Optional[Dict[str, str]] = None):
        self.custom_env = custom_env or {}
        self.last_telemetry: Dict[str, Any] = {}

    def normalize(self, data_or_text: Union[bytes, str]) -> Tuple[str, Dict[str, Any]]:
        clean_text, meta = normalize_machine1337(data_or_text, self.custom_env)
        self.last_telemetry = meta
        return clean_text, meta

    def detect(self, data_or_text: Union[bytes, str]) -> Dict[str, Any]:
        return detect_machine1337_signatures(data_or_text)

    def zeroize(self) -> None:
        if self.last_telemetry:
            zeroize_dict(self.last_telemetry)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.zeroize()

    def __del__(self):
        self.zeroize()
