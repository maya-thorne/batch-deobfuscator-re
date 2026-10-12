"""
BatCloak Normalization & Preprocessing Engine.
Specialized heuristics for neutralizing BatCloak, ScrubCrypt, and machine1337
malware evasion patterns, including:
  1. Fake UTF-16LE / UTF-16BE / multi-BOM header masking (e.g. 0xFF 0xFE &cls\\r\\n).
  2. Alternating null-byte statistical forensics for genuine vs fake wide-char streams.
  3. Dynamic %RANDOM% junk variable pruning and empty noise assignment elimination.
  4. Scrambled hex identifier (_0x[0-9a-fA-F]+) tracking and symbol recovery.
  5. Dead Store Elimination (DSE) for unreferenced stager chaff and ephemeral aliases.
  6. In-memory forensic buffer zeroization for sensitive payload bytes.

Engineered by Maya Thorne.
"""

import re
import ctypes
from typing import Dict, List, Tuple, Any, Optional, Set


def zeroize_bytes(buf: bytearray) -> None:
    """
    Cryptographically overwrite a byte buffer in-place to prevent forensic leakage in RAM.
    Safe against compiler/runtime dead-store elimination.
    """
    if not isinstance(buf, (bytearray, memoryview)):
        return
    try:
        # Overwrite with zeros in place
        for idx in range(len(buf)):
            buf[idx] = 0
    except Exception:
        pass


def is_genuine_utf16le(data: bytes) -> bool:
    """
    Statistically determine whether a byte sequence starting with 0xFF 0xFE is
    legitimate UTF-16LE text or an 8-bit ASCII payload disguised with a fake BOM.
    In true UTF-16LE ASCII scripts, odd byte indices (1, 3, 5, ...) are overwhelmingly 0x00.
    In fake BOM obfuscation, null bytes are virtually non-existent (<5%).
    """
    if len(data) < 4:
        return True

    sample = data[2:min(len(data), 1024)]
    if not sample:
        return True

    # Check null bytes on odd indices (0-indexed relative to payload start)
    null_count_odd = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)
    odd_positions = len(sample) // 2
    if odd_positions == 0:
        return True

    odd_null_ratio = null_count_odd / odd_positions

    # If odd null ratio exceeds 35%, it is legitimate UTF-16LE
    return odd_null_ratio >= 0.35


def is_genuine_utf16be(data: bytes) -> bool:
    """
    Statistically determine whether a byte sequence starting with 0xFE 0xFF is
    legitimate UTF-16BE text or an 8-bit ASCII payload disguised with a fake BOM.
    In true UTF-16BE ASCII scripts, even byte indices (0, 2, 4, ...) are overwhelmingly 0x00.
    """
    if len(data) < 4:
        return True

    sample = data[2:min(len(data), 1024)]
    if not sample:
        return True

    null_count_even = sum(1 for i in range(0, len(sample), 2) if sample[i] == 0)
    even_positions = (len(sample) + 1) // 2
    if even_positions == 0:
        return True

    even_null_ratio = null_count_even / even_positions
    return even_null_ratio >= 0.35


def normalize_batcloak_headers(data: bytes) -> Tuple[str, Dict[str, Any]]:
    """
    Detect and neutralize BatCloak, ScrubCrypt, and machine1337 header traps.
    Returns:
        Tuple[clean_text, metadata]
    """
    meta: Dict[str, Any] = {
        "fake_bom_detected": False,
        "header_pattern": "none",
        "stripped_header_bytes": 0,
        "encoding_used": "utf-8",
    }

    # Pattern A: machine1337 double BOM trap: FF FE 26 63 6C 73 0D 0A FF FE 0A 0D
    if data.startswith(b"\xff\xfe\x26\x63\x6c\x73\x0d\x0a\xff\xfe\x0a\x0d"):
        meta["fake_bom_detected"] = True
        meta["header_pattern"] = "machine1337-double-bom"
        meta["stripped_header_bytes"] = 12
        payload = data[12:]
        text = _decode_8bit_stream(payload, meta)
        return text, meta

    # Pattern B: Classic BatCloak BOM + &cls\\r\\n header: FF FE 26 63 6C 73 0D 0A
    if data.startswith(b"\xff\xfe\x26\x63\x6c\x73\x0d\x0a"):
        meta["fake_bom_detected"] = True
        meta["header_pattern"] = "batcloak-bom-cls"
        meta["stripped_header_bytes"] = 8
        payload = data[8:]
        text = _decode_8bit_stream(payload, meta)
        return text, meta

    # Pattern C: UTF-16LE BOM with non-UTF-16 payload
    if data.startswith(b"\xff\xfe"):
        if is_genuine_utf16le(data):
            meta["encoding_used"] = "utf-16le"
            try:
                return data[2:].decode("utf-16le", errors="replace"), meta
            except Exception:
                pass
        else:
            meta["fake_bom_detected"] = True
            meta["header_pattern"] = "batcloak-fake-utf16le-bom"
            meta["stripped_header_bytes"] = 2
            payload = data[2:]
            # If payload starts with immediate decoy commands like &cls or &\r\n
            if payload.startswith(b"&cls\r\n"):
                payload = payload[6:]
                meta["stripped_header_bytes"] += 6
            elif payload.startswith(b"&cls\n"):
                payload = payload[5:]
                meta["stripped_header_bytes"] += 5
            elif payload.startswith(b"&\r\n"):
                payload = payload[3:]
                meta["stripped_header_bytes"] += 3

            text = _decode_8bit_stream(payload, meta)
            return text, meta

    # Pattern D: UTF-16BE BOM with non-UTF-16 payload
    if data.startswith(b"\xfe\xff"):
        if is_genuine_utf16be(data):
            meta["encoding_used"] = "utf-16be"
            try:
                return data[2:].decode("utf-16be", errors="replace"), meta
            except Exception:
                pass
        else:
            meta["fake_bom_detected"] = True
            meta["header_pattern"] = "fake-utf16be-bom"
            meta["stripped_header_bytes"] = 2
            payload = data[2:]
            text = _decode_8bit_stream(payload, meta)
            return text, meta

    # Pattern E: Standard UTF-8 BOM
    if data.startswith(b"\xef\xbb\xbf"):
        meta["encoding_used"] = "utf-8-sig"
        meta["stripped_header_bytes"] = 3
        payload = data[3:]
        text = _decode_8bit_stream(payload, meta)
        return text, meta

    # Fallback to standard 8-bit stream decoding
    text = _decode_8bit_stream(data, meta)
    return text, meta


def _decode_8bit_stream(data: bytes, meta: Dict[str, Any]) -> str:
    """Decode raw bytes into string using UTF-8, CP1252, or CP437."""
    try:
        text = data.decode("utf-8")
        meta["encoding_used"] = "utf-8"
        return text
    except UnicodeDecodeError:
        pass

    try:
        text = data.decode("cp1252")
        meta["encoding_used"] = "cp1252"
        return text
    except UnicodeDecodeError:
        text = data.decode("latin1", errors="replace")
        meta["encoding_used"] = "latin1"
        return text


def strip_batcloak_random_vars(script_text: str) -> Tuple[str, List[str]]:
    """
    Remove dynamic %RANDOM% noise assignments and unreferenced empty variable declarations.
    Examples neutralized:
      - set %RANDOM%_junk=
      - set %RANDOM%=
      - set junk_%RANDOM%=
      - set _random_seed=%RANDOM% (when unused)
    Returns:
        Tuple[clean_text, removed_statements]
    """
    removed: List[str] = []

    # If script contains chained commands with ampersands, pre-split for line inspection
    if "&" in script_text:
        try:
            from .normalizers import split_chained_commands
            script_text = split_chained_commands(script_text)
        except Exception:
            pass

    lines = script_text.splitlines()
    clean_lines = []

    # Regex matching set statements whose variable name contains %RANDOM%
    random_var_decl = re.compile(
        r'^\s*@?\s*set(?:\s+(?:/[ap]\s+)?|/[ap]\s*)[\"\']?'
        r'([^=]*%random%[^=]*)'
        r'(?:=.*)?[\"\']?\s*$',
        re.IGNORECASE
    )

    # Regex matching empty variable assignments used as chaff: set var=
    empty_var_decl = re.compile(
        r'^\s*@?\s*set(?:\s+(?:/[ap]\s+)?|/[ap]\s*)[\"\']?'
        r'([a-zA-Z0-9_\-\.\:\$]+)=\s*[\"\']?\s*$',
        re.IGNORECASE
    )

    for line in lines:
        stripped = line.strip()

        # 1. Match %RANDOM% in variable definition
        m_rand = random_var_decl.match(stripped)
        if m_rand:
            removed.append(stripped)
            continue

        # 2. Check if it's an empty junk assignment like set foo= where foo has random naming
        m_empty = empty_var_decl.match(stripped)
        if m_empty:
            var_name = m_empty.group(1).lower()
            # If variable name looks like randomized hex or random identifier
            if (
                re.match(r'^_0x[0-9a-f]{4,8}$', var_name) or
                re.match(r'^[a-z0-9_]{10,}$', var_name) or
                "junk" in var_name or
                "rand" in var_name or
                "dummy" in var_name
            ):
                removed.append(stripped)
                continue

        clean_lines.append(line)

    return "\n".join(clean_lines), removed


def eliminate_dead_stores(script_text: str, preserve_vars: Optional[Set[str]] = None) -> Tuple[str, List[str]]:
    """
    Perform Dead Store Elimination (DSE) across the batch script.
    Identifies variable assignments (`set var=val`) whose variable name is never
    read or dereferenced in any subsequent or preceding line via `%var%` or `!var!`.
    Leaves assignments with side effects (interactive `set /p` or arithmetic `set /a`) intact.
    Returns:
        Tuple[clean_text, eliminated_variables]
    """
    lines = script_text.splitlines()
    eliminated: List[str] = []
    preserve = {v.lower() for v in (preserve_vars or set())}

    # Step 1: Gather all candidate simple assignments: (line_index, var_name, full_line)
    candidates: List[Tuple[int, str, str]] = []
    assign_pattern = re.compile(
        r'^\s*@?\s*set\s+(?:\"([a-zA-Z0-9_\-\.\:\$]+)=([^\"\r\n]*)\"?|([a-zA-Z0-9_\-\.\:\$]+)=([^=].*|$))\s*$',
        re.IGNORECASE
    )

    for idx, line in enumerate(lines):
        # Skip comment or echo lines
        stripped = line.strip()
        if re.match(r'^@?\s*(?:rem\b|::|echo\b)', stripped, re.IGNORECASE):
            continue

        # Skip arithmetic / prompt switches
        if re.match(r'^\s*@?\s*set\s+/[ap]\b', stripped, re.IGNORECASE):
            continue

        m = assign_pattern.match(stripped)
        if m:
            var_name = (m.group(1) or m.group(3) or "").strip().lower()
            if var_name and var_name not in preserve:
                candidates.append((idx, var_name, stripped))

    if not candidates:
        return script_text, []

    # Step 2: Build a combined usage text from all lines EXCEPT the assignment candidate line
    lines_to_remove: Set[int] = set()

    for line_idx, var_name, full_line in candidates:
        # Check if var_name is referenced in any other line
        # Reference forms: %var_name%, %var_name:~...%, %var_name:...%, !var_name!
        var_esc = re.escape(var_name)
        ref_pattern = re.compile(
            rf'(?:%{var_esc}(?::[^%\r\n]*)?%|!{var_esc}(?::[^!\r\n]*)?!)',
            re.IGNORECASE
        )

        has_reference = False
        for other_idx, other_line in enumerate(lines):
            if other_idx == line_idx:
                continue
            if ref_pattern.search(other_line):
                has_reference = True
                break

        # If not referenced anywhere else, it is a dead store
        if not has_reference:
            lines_to_remove.add(line_idx)
            eliminated.append(var_name)

    # Step 3: Reconstruct script without the dead store lines
    remaining_lines = [
        line for idx, line in enumerate(lines)
        if idx not in lines_to_remove
    ]

    return "\n".join(remaining_lines), eliminated


def detect_batcloak_signatures(raw_bytes: Optional[bytes], script_text: str) -> Dict[str, Any]:
    """
    Forensic heuristic signature analyzer for BatCloak and related obfuscation frameworks.
    Returns:
        Dict with detection indicators, confidence score (0.0 to 1.0), and architectural tags.
    """
    indicators: List[str] = []
    confidence = 0.0

    # 1. Byte-level checks
    if raw_bytes:
        if raw_bytes.startswith(b"\xff\xfe\x26\x63\x6c\x73\x0d\x0a\xff\xfe\x0a\x0d"):
            indicators.append("machine1337-double-bom-header")
            confidence += 0.50
        elif raw_bytes.startswith(b"\xff\xfe\x26\x63\x6c\x73\x0d\x0a"):
            indicators.append("batcloak-bom-cls-header")
            confidence += 0.50
        elif raw_bytes.startswith(b"\xff\xfe") and not is_genuine_utf16le(raw_bytes):
            indicators.append("fake-utf16le-bom-masking")
            confidence += 0.40

    # 2. Text-level checks
    # Check for %RANDOM% used inside variable declaration
    if re.search(r'set(?:\s+[^=]*%random%|/[ap]\s*[^=]*%random%)', script_text, re.IGNORECASE):
        indicators.append("random-variable-injection")
        confidence += 0.35

    # Check for hex-scrambled identifiers (_0x[0-9a-f]{4})
    hex_vars = re.findall(r'_0x[0-9a-fA-F]{4,8}\b', script_text)
    if len(hex_vars) >= 2:
        indicators.append(f"hex-scrambled-identifiers({len(hex_vars)})")
        confidence += 0.25

    # Check for PowerShell encoded loader / stager patterns
    if re.search(r'powershell(?:\.exe)?\s+(?:-[a-zA-Z]+\s+)*-enc\b', script_text, re.IGNORECASE):
        indicators.append("powershell-encoded-stager")
        confidence += 0.25

    confidence = min(1.0, round(confidence, 2))
    return {
        "is_batcloak_family": confidence >= 0.35,
        "confidence": confidence,
        "indicators": indicators,
    }


class BatCloakNormalizer:
    """
    Unified BatCloak & Header De-Masking Preprocessor.
    Integrated cleanly with the BatchDeobfuscator multi-pass pipeline.
    """

    def __init__(self, strip_random_vars: bool = True, eliminate_dead_code: bool = True):
        self.strip_random_vars = strip_random_vars
        self.eliminate_dead_code = eliminate_dead_code

    def preprocess_bytes(self, raw_bytes: bytes) -> Tuple[str, Dict[str, Any]]:
        """Normalize raw file bytes neutralizing fake BOMs and header decoys."""
        text, meta = normalize_batcloak_headers(raw_bytes)
        sig = detect_batcloak_signatures(raw_bytes, text)
        meta.update(sig)
        return text, meta

    def preprocess_script(self, script_text: str) -> Tuple[str, Dict[str, Any]]:
        """Normalize text representation, removing BatCloak noise and dead variables."""
        curr = script_text
        removed_random = []
        eliminated_dead = []

        if self.strip_random_vars:
            curr, removed_random = strip_batcloak_random_vars(curr)

        if self.eliminate_dead_code:
            curr, eliminated_dead = eliminate_dead_stores(curr)

        sig = detect_batcloak_signatures(None, script_text)

        report = {
            "batcloak_signatures": sig,
            "removed_random_vars": removed_random,
            "eliminated_dead_stores": eliminated_dead,
        }
        return curr, report
