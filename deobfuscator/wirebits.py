"""
BatchObfuscator-wirebits Evasion Normalization & Radix Escape Decoding Engine.
Specialized heuristics and static normalization for WireBits batch obfuscation:
  1. Base64 payload (//4mY2xzDQo=) and fake UTF-16LE BOM (&cls) header neutralization.
  2. TUI menu, box-drawing characters, and author banner stripping.
  3. Hexadecimal escape decoding (\\xHH, \\u00HH).
  4. Octal escape sequence normalization (\\OOO, \\0OO).
  5. PowerShell character code array and join expression resolution ([char]0xHH, -join).
  6. Non-standard radix arithmetic normalization in set /a (0xHH, 0OO, base#num).
  7. Sequential single-character variable fragment splicing resolution (%_1%%_2%...).
  8. In-memory cryptographic buffer sanitization (zeroize_dict, zeroize_bytes).

Engineered by Maya Thorne.
"""

import re
import base64
from typing import Dict, List, Tuple, Any, Optional, Union

from .normalizers import split_chained_commands, strip_carets

# WireBits signature indicators and banner markers
WIREBITS_BASE64_HEADER = "//4mY2xzDQo="
WIREBITS_RAW_HEADER = b"\xff\xfe&cls\r\n"
WIREBITS_MARKERS = [
    "WireBits",
    "BatchObfuscator",
    "Batch File Obfuscation Tool",
    "+──────────────────────────────────────────────+",
    "+─────────────+",
    "| Operartions |",
    "╰┈➤ Obfuscate a .bat/.cmd file",
    "╰┈➤ Choose Operartion",
    "╰┈➤ File Obfuscated",
    "╰┈➤ [!] Closing the tool",
]

# TUI box-drawing symbols frequently used in WireBits banner
WIREBITS_BOX_GLYPHS = ("╔╗", "╠╩╗", "╚═╝", "╔═╗", "╦ ╦", "╰┈➤", "⮞")

# Spliced variable name pattern (decimal, hex, octal, or tagged)
SPLICED_VAR_DEF_RE = re.compile(
    r'(?:^|[;&@\s])set\s+(?:/[ap]\s+)?\"?(_(?:0x[0-9a-fA-F]+|0[0-7]+|[0-9]+))\s*=\s*([^\"&\r\n]*)\"?',
    re.IGNORECASE
)
SPLICED_VAR_REF_RE = re.compile(
    r'%(_(?:0x[0-9a-fA-F]+|0[0-7]+|[0-9]+))%',
    re.IGNORECASE
)


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
    if not isinstance(target, dict):
        return
    for key in list(target.keys()):
        val = target[key]
        if isinstance(val, dict):
            zeroize_dict(val)
        elif isinstance(val, list):
            for i in range(len(val)):
                val[i] = None
            val.clear()
        elif isinstance(val, set):
            val.clear()
        elif isinstance(val, bytearray):
            zeroize_bytes(val)
        target[key] = None
    target.clear()


def detect_wirebits_signatures(script: Union[str, bytes]) -> Dict[str, Any]:
    """
    Heuristically analyze batch script or binary data for WireBits obfuscation signatures.
    Returns:
        Dict with keys: is_wirebits, confidence, indicators, has_header, has_banner,
                        has_char_splicing, has_hex_escapes, has_octal_escapes,
                        has_powershell_arrays, has_radix_arithmetic
    """
    indicators: List[str] = []
    has_header = False
    has_banner = False
    has_char_splicing = False
    has_hex_escapes = False
    has_octal_escapes = False
    has_powershell_arrays = False
    has_radix_arithmetic = False

    raw_bytes = script if isinstance(script, bytes) else script.encode("utf-8", errors="ignore")
    text = script if isinstance(script, str) else script.decode("utf-8", errors="ignore")

    # 1. Header check (Base64 payload or raw UTF-16LE BOM + &cls)
    if WIREBITS_BASE64_HEADER in text or raw_bytes.startswith(WIREBITS_RAW_HEADER):
        has_header = True
        indicators.append("wirebits-header-bom-cls")
    elif re.match(r'^(?:\ufeff)?&cls[\r\n]+', text):
        has_header = True
        indicators.append("wirebits-cls-preamble")

    # 2. Banner and menu string detection
    banner_hits = [m for m in WIREBITS_MARKERS if m in text]
    if banner_hits:
        has_banner = True
        indicators.append(f"wirebits-banner-markers({len(banner_hits)})")
    if any(glyph in text for glyph in WIREBITS_BOX_GLYPHS):
        has_banner = True
        indicators.append("wirebits-box-drawing-tui")

    # 3. Sequential character fragment splicing (%_1%%_2%... or %_0x01%%_0x02%...)
    splicing_matches = re.findall(r'(?:%_[a-zA-Z0-9]+%){2,}', text)
    splicing_defs = SPLICED_VAR_DEF_RE.findall(text)
    if splicing_matches or len(splicing_defs) >= 3:
        has_char_splicing = True
        indicators.append(f"wirebits-char-splicing(chains={len(splicing_matches)},defs={len(splicing_defs)})")

    # 4. Hexadecimal escape sequences (\\xHH, \\u00HH)
    hex_escapes = re.findall(r'\\[xX][0-9a-fA-F]{2}|\\u00[0-9a-fA-F]{2}', text)
    if len(hex_escapes) >= 2:
        has_hex_escapes = True
        indicators.append(f"wirebits-hex-escapes({len(hex_escapes)})")

    # 5. Octal escape sequences (\\OOO, \\0OO)
    octal_escapes = re.findall(r'\\[0-3][0-7]{2}|\\0[0-7]{2}', text)
    if len(octal_escapes) >= 2:
        has_octal_escapes = True
        indicators.append(f"wirebits-octal-escapes({len(octal_escapes)})")

    # 6. PowerShell character array casting & join expressions
    ps_char_casts = re.findall(r'\[char\](?:0x[0-9a-fA-F]+|\d+)\s*\+\s*\[char\]', text, re.IGNORECASE)
    ps_joins = re.findall(r'-join\s*\(\s*(?:0x[0-9a-fA-F]+|\d+)', text, re.IGNORECASE)
    if ps_char_casts or ps_joins:
        has_powershell_arrays = True
        indicators.append(f"wirebits-powershell-char-arrays(casts={len(ps_char_casts)},joins={len(ps_joins)})")

    # 7. Radix arithmetic in set /a (0xHH, 0OO, base#num)
    radix_matches = re.findall(
        r'set\s+/a\s+[^&|\r\n]*?(?:0x[0-9a-fA-F]+|\b0[0-7]{2,}\b|\b(?:[2-9]|[1-3][0-6])#[0-9a-zA-Z]+)',
        text,
        re.IGNORECASE
    )
    if radix_matches:
        has_radix_arithmetic = True
        indicators.append(f"wirebits-radix-arithmetic({len(radix_matches)})")

    # Calculate confidence score
    confidence = 0.0
    if has_header:
        confidence += 0.45
    if has_banner:
        confidence += 0.40
    if has_char_splicing:
        confidence += 0.35
    if has_hex_escapes:
        confidence += 0.35
    if has_octal_escapes:
        confidence += 0.35
    if has_powershell_arrays:
        confidence += 0.35
    if has_radix_arithmetic:
        confidence += 0.35

    confidence = min(1.0, confidence)
    is_wirebits = (
        confidence >= 0.35
        or has_header
        or has_banner
        or has_char_splicing
        or has_hex_escapes
        or has_octal_escapes
        or has_powershell_arrays
        or has_radix_arithmetic
    )

    return {
        "is_wirebits": is_wirebits,
        "confidence": round(confidence, 2),
        "indicators": indicators,
        "has_header": has_header,
        "has_banner": has_banner,
        "has_char_splicing": has_char_splicing,
        "has_hex_escapes": has_hex_escapes,
        "has_octal_escapes": has_octal_escapes,
        "has_powershell_arrays": has_powershell_arrays,
        "has_radix_arithmetic": has_radix_arithmetic,
    }


def neutralize_wirebits_headers(script: Union[str, bytes]) -> Tuple[str, Dict[str, Any]]:
    """
    Neutralize fake BOM preambles, &cls header tags, and TUI box-drawing banner noise.
    Returns:
        Tuple[clean_script_text, telemetry_dict]
    """
    header_stripped = False
    banner_stripped = False
    stripped_lines = 0

    if isinstance(script, bytes):
        data = script
        if data.startswith(WIREBITS_RAW_HEADER):
            data = data[len(WIREBITS_RAW_HEADER):]
            header_stripped = True
        elif data.startswith(b"\xff\xfe&cls\n"):
            data = data[len(b"\xff\xfe&cls\n"):]
            header_stripped = True
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = data.decode("cp1252")
            except Exception:
                text = data.decode("latin-1", errors="ignore")
    else:
        text = script

    # Strip base64 payload representation if embedded as text
    if WIREBITS_BASE64_HEADER in text:
        text = text.replace(WIREBITS_BASE64_HEADER, "")
        header_stripped = True

    # Strip leading fake UTF-16 BOM or &cls preamble
    cls_match = re.match(r'^(?:\ufeff)?(?:&cls|cls)[\r\n]+', text, re.IGNORECASE)
    if cls_match:
        text = text[cls_match.end():]
        header_stripped = True

    # Neutralize TUI banners and box-drawing menus
    clean_lines: List[str] = []
    in_banner_block = False

    for line in text.splitlines():
        trimmed = line.strip()

        # Detect start of box banner
        if "+───" in trimmed or "╔╗" in trimmed:
            in_banner_block = True
            banner_stripped = True
            stripped_lines += 1
            continue

        if in_banner_block:
            if (
                trimmed.startswith("|")
                or trimmed.startswith("+")
                or "╰┈➤" in trimmed
                or any(g in trimmed for g in WIREBITS_BOX_GLYPHS)
                or any(m in trimmed for m in WIREBITS_MARKERS)
                or trimmed == ""
            ):
                stripped_lines += 1
                banner_stripped = True
                continue
            else:
                in_banner_block = False

        # Single-line banner indicators or prompt decoys
        if any(marker in trimmed for marker in (
            "WireBits", "Batch File Obfuscation Tool", "╰┈➤", "Operartions",
            "File Obfuscated :", "Closing the tool. Goodbye!"
        )):
            banner_stripped = True
            stripped_lines += 1
            continue

        # Skip comment or echo banners with box characters
        if (trimmed.startswith("::") or trimmed.startswith("rem ") or trimmed.startswith("echo ")) and any(
            g in trimmed for g in WIREBITS_BOX_GLYPHS
        ):
            banner_stripped = True
            stripped_lines += 1
            continue

        clean_lines.append(line)

    clean_text = "\n".join(clean_lines).strip()
    return clean_text, {
        "fake_bom_detected": header_stripped,
        "header_stripped": header_stripped,
        "banner_stripped": banner_stripped,
        "stripped_lines": stripped_lines,
    }


def decode_hex_escapes(text: str) -> Tuple[str, int]:
    """
    Decode hexadecimal escape sequences (\\xHH and \\u00HH) into printable ASCII / whitespace.
    Returns:
        Tuple[decoded_text, decode_count]
    """
    count = 0

    def hex_repl(match: re.Match) -> str:
        nonlocal count
        hex_digits = match.group(1) or match.group(2)
        try:
            val = int(hex_digits, 16)
            if 32 <= val <= 126 or val in (9, 10, 13):
                count += 1
                return chr(val)
        except Exception:
            pass
        return match.group(0)

    pattern = re.compile(r'\\(?:x([0-9a-fA-F]{2})|u00([0-9a-fA-F]{2}))')
    result = pattern.sub(hex_repl, text)
    return result, count


def decode_octal_escapes(text: str) -> Tuple[str, int]:
    """
    Decode octal escape sequences (\\OOO and \\0OO) into printable ASCII / whitespace.
    Returns:
        Tuple[decoded_text, decode_count]
    """
    count = 0

    def oct_repl(match: re.Match) -> str:
        nonlocal count
        oct_digits = match.group(1) or match.group(2)
        try:
            val = int(oct_digits, 8)
            if 32 <= val <= 126 or val in (9, 10, 13):
                count += 1
                return chr(val)
        except Exception:
            pass
        return match.group(0)

    pattern = re.compile(r'\\(?:0([0-7]{2})|([0-3][0-7]{2}))')
    result = pattern.sub(oct_repl, text)
    return result, count


def resolve_char_casting_and_arrays(text: str) -> Tuple[str, int]:
    """
    Resolve PowerShell character code casting expressions and join arrays into string literals:
      - [char]0x70+[char]0x6f+... -> "powershell"
      - (-join (0x70,0x6f,...|%{[char]$_})) -> "powershell"
      - [string]::Join('', (0x70,0x6f,...|%{[char]$_})) -> "powershell"
    Returns:
        Tuple[resolved_text, resolution_count]
    """
    count = 0

    # 1. Resolve concatenated [char]0xHH+[char]0xHH... or [char]NN+[char]NN...
    char_chain_re = re.compile(
        r'\(?\s*\[char\](?:0x[0-9a-fA-F]+|\d+)(?:\s*\+\s*\[char\](?:0x[0-9a-fA-F]+|\d+))+\s*\)?',
        re.IGNORECASE
    )

    def char_chain_repl(m: re.Match) -> str:
        nonlocal count
        segment = m.group(0)
        nums = re.findall(r'\[char\](0x[0-9a-fA-F]+|\d+)', segment, re.IGNORECASE)
        chars = []
        try:
            for n in nums:
                val = int(n, 16) if n.lower().startswith("0x") else int(n)
                if 0 <= val <= 0x10FFFF:
                    chars.append(chr(val))
                else:
                    return segment
            count += 1
            return '"' + "".join(chars) + '"'
        except Exception:
            return segment

    text = char_chain_re.sub(char_chain_repl, text)

    # 2. Resolve join arrays: (-join (0xHH, 0xHH... | %{[char]$_}))
    join_array_re = re.compile(
        r'\(-join\s*\(\s*((?:(?:0x[0-9a-fA-F]+|\d+)\s*,\s*)*(?:0x[0-9a-fA-F]+|\d+))\s*\|\s*(?:%|ForEach-Object|ForEach)\s*\{\s*\[char\]\$_?\s*\}\s*\)\)',
        re.IGNORECASE
    )

    def join_array_repl(m: re.Match) -> str:
        nonlocal count
        segment = m.group(0)
        num_str = m.group(1)
        nums = [n.strip() for n in num_str.split(",") if n.strip()]
        chars = []
        try:
            for n in nums:
                val = int(n, 16) if n.lower().startswith("0x") else int(n)
                if 0 <= val <= 0x10FFFF:
                    chars.append(chr(val))
                else:
                    return segment
            count += 1
            return '"' + "".join(chars) + '"'
        except Exception:
            return segment

    text = join_array_re.sub(join_array_repl, text)

    # 3. Resolve [string]::Join('', (0xHH, 0xHH... | %{[char]$_}))
    string_join_re = re.compile(
        r'\[string\]::Join\s*\(\s*[\'"][^\'"]*[\'"]\s*,\s*\(\s*((?:(?:0x[0-9a-fA-F]+|\d+)\s*,\s*)*(?:0x[0-9a-fA-F]+|\d+))\s*\|\s*(?:%|ForEach-Object|ForEach)\s*\{\s*\[char\]\$_?\s*\}\s*\)\s*\)',
        re.IGNORECASE
    )

    def string_join_repl(m: re.Match) -> str:
        nonlocal count
        segment = m.group(0)
        num_str = m.group(1)
        nums = [n.strip() for n in num_str.split(",") if n.strip()]
        chars = []
        try:
            for n in nums:
                val = int(n, 16) if n.lower().startswith("0x") else int(n)
                if 0 <= val <= 0x10FFFF:
                    chars.append(chr(val))
                else:
                    return segment
            count += 1
            return '"' + "".join(chars) + '"'
        except Exception:
            return segment

    text = string_join_re.sub(string_join_repl, text)
    return text, count


def normalize_radix_arithmetic(text: str) -> Tuple[str, int]:
    """
    Normalize non-standard radix numbers in 'set /a' statements:
      - 0xHH (hexadecimal) -> decimal
      - 0OO (octal with leading zero) -> decimal
      - base#num (2#1010, 8#77, 16#FF) -> decimal
    Returns:
        Tuple[normalized_text, normalization_count]
    """
    count = 0
    lines = text.splitlines()
    out_lines: List[str] = []

    set_a_re = re.compile(r'^(.*?\bset\s+/a\s+)(.*)$', re.IGNORECASE)

    for line in lines:
        m = set_a_re.match(line)
        if not m:
            out_lines.append(line)
            continue

        prefix = m.group(1)
        expr = m.group(2)

        # 1. Normalize base#num (e.g. 2#1010, 8#77, 16#FF)
        def base_repl(bm: re.Match) -> str:
            nonlocal count
            base = int(bm.group(1))
            val_str = bm.group(2)
            try:
                dec = int(val_str, base)
                count += 1
                return str(dec)
            except Exception:
                return bm.group(0)

        expr = re.sub(r'\b([2-9]|[1-3][0-6])#([0-9a-zA-Z]+)\b', base_repl, expr)

        # 2. Normalize hex (0xHH)
        def hex_repl(hm: re.Match) -> str:
            nonlocal count
            try:
                dec = int(hm.group(1), 16)
                count += 1
                return str(dec)
            except Exception:
                return hm.group(0)

        expr = re.sub(r'\b0[xX]([0-9a-fA-F]+)\b', hex_repl, expr)

        # 3. Normalize octal (0[0-7]+, e.g. 040 -> 32)
        def oct_repl(om: re.Match) -> str:
            nonlocal count
            oct_str = om.group(1)
            try:
                dec = int(oct_str, 8)
                count += 1
                return str(dec)
            except Exception:
                return om.group(0)

        expr = re.sub(r'(?<![0-9a-zA-Z_#])0([0-7]+)\b', oct_repl, expr)

        out_lines.append(prefix + expr)

    return "\n".join(out_lines), count


def resolve_wirebits_char_splicing(
    text: str, custom_env: Optional[Dict[str, str]] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Harvest sequential single-character variable assignments and resolve
    concatenation chains (%_1%%_2%%_3%... or %_0x01%%_0x02%...).
    Prunes dead stores corresponding to harvested spliced fragments.
    Returns:
        Tuple[clean_text, telemetry_dict]
    """
    spliced_vars: Dict[str, str] = {}
    if custom_env:
        for k, v in custom_env.items():
            if re.match(r'^_(?:0x[0-9a-fA-F]+|0[0-7]+|[0-9]+)$', k, re.IGNORECASE):
                spliced_vars[k.lower()] = v

    # 1. Harvest variable definitions from script
    for m in SPLICED_VAR_DEF_RE.finditer(text):
        vname = m.group(1).lower()
        vval = strip_carets(m.group(2).strip())
        spliced_vars[vname] = vval

    if not spliced_vars:
        return text, {
            "spliced_fragments_resolved": 0,
            "dead_stores_pruned": 0,
            "assembled_tokens": [],
        }

    assembled_tokens: List[str] = []
    fragments_resolved = 0

    # 2. Resolve variable reference chains (%_1%%_2%%_3%... or !_1!!_2!...)
    chain_re = re.compile(r'((?:%_[a-zA-Z0-9]+%){2,}|(?:!_[a-zA-Z0-9]+!){2,})', re.IGNORECASE)

    def chain_repl(cm: re.Match) -> str:
        nonlocal fragments_resolved
        chain_str = cm.group(1)
        is_delayed = chain_str.startswith("!")
        delimiter = "!" if is_delayed else "%"
        var_names = [v.lower() for v in chain_str.split(delimiter) if v]
        assembled_chars = []
        for v in var_names:
            if v in spliced_vars:
                assembled_chars.append(spliced_vars[v])
            else:
                assembled_chars.append(f"{delimiter}{v}{delimiter}")

        unified = "".join(assembled_chars)
        assembled_tokens.append(unified)
        fragments_resolved += len(var_names)
        return unified

    resolved_text = chain_re.sub(chain_repl, text)

    # 3. Prune dead assignment statements that define spliced variables
    dead_stores_pruned = 0
    lines = resolved_text.splitlines()
    clean_lines: List[str] = []

    for line in lines:
        if "&" in line:
            # Multi-statement line: filter out individual set _1=... assignments
            parts = split_chained_commands(line).splitlines() if "\n" in split_chained_commands(line) else line.split("&")
            retained_parts: List[str] = []
            for part in parts:
                p_strip = part.strip()
                def_m = re.match(r'^(?:@\s*)?set\s+(?:/[ap]\s+)?\"?(_(?:0x[0-9a-fA-F]+|0[0-7]+|[0-9]+))\s*=', p_strip, re.IGNORECASE)
                if def_m and def_m.group(1).lower() in spliced_vars:
                    dead_stores_pruned += 1
                else:
                    retained_parts.append(p_strip)
            if retained_parts:
                clean_lines.append("&".join(retained_parts))
        else:
            def_m = re.match(r'^(?:@\s*)?set\s+(?:/[ap]\s+)?\"?(_(?:0x[0-9a-fA-F]+|0[0-7]+|[0-9]+))\s*=', line.strip(), re.IGNORECASE)
            if def_m and def_m.group(1).lower() in spliced_vars:
                dead_stores_pruned += 1
            else:
                clean_lines.append(line)

    final_text = "\n".join([l for l in clean_lines if l.strip()])
    return final_text, {
        "spliced_fragments_resolved": fragments_resolved,
        "dead_stores_pruned": dead_stores_pruned,
        "assembled_tokens": assembled_tokens,
    }


class WireBitsNormalizer:
    """Class wrapper for WireBits signature detection and multi-stage normalization."""

    def __init__(self, custom_env: Optional[Dict[str, str]] = None):
        self.custom_env = dict(custom_env) if custom_env else {}

    def normalize(self, script_text: str) -> Tuple[str, Dict[str, Any]]:
        return normalize_wirebits(script_text, custom_env=self.custom_env)

    def zeroize(self) -> None:
        """Cryptographically sanitize custom env dictionary."""
        zeroize_dict(self.custom_env)

    def __del__(self):
        try:
            self.zeroize()
        except Exception:
            pass


def normalize_wirebits(
    script_text: str, custom_env: Optional[Dict[str, str]] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Execute full normalization pipeline for WireBits batch obfuscation:
      1. Signature heuristic analysis
      2. Header & banner neutralization
      3. Hexadecimal escape decoding (\\xHH, \\u00HH)
      4. Octal escape decoding (\\OOO, \\0OO)
      5. PowerShell character code array and join expression resolution
      6. Non-standard radix arithmetic normalization (0xHH, 0OO, base#num)
      7. Sequential character fragment splicing resolution & dead store elimination
    Returns:
        Tuple[clean_script_text, telemetry_dict]
    """
    sig = detect_wirebits_signatures(script_text)
    curr_text = script_text

    # Step 1: Neutralize headers and TUI banners
    curr_text, header_meta = neutralize_wirebits_headers(curr_text)

    # Step 2: Hexadecimal escape decoding
    curr_text, hex_count = decode_hex_escapes(curr_text)

    # Step 3: Octal escape decoding
    curr_text, oct_count = decode_octal_escapes(curr_text)

    # Step 4: PowerShell character casting and join arrays
    curr_text, ps_count = resolve_char_casting_and_arrays(curr_text)

    # Step 5: Radix arithmetic normalization
    curr_text, radix_count = normalize_radix_arithmetic(curr_text)

    # Step 6: Sequential variable fragment splicing resolution & DSE
    curr_text, splicing_meta = resolve_wirebits_char_splicing(curr_text, custom_env=custom_env)

    # Assemble metadata
    telemetry = {
        "is_wirebits": sig["is_wirebits"],
        "confidence": sig["confidence"],
        "indicators": list(sig["indicators"]),
        "signatures": sig,
        "headers_neutralized": header_meta["header_stripped"],
        "banners_stripped_count": header_meta["stripped_lines"],
        "hex_escapes_decoded": hex_count,
        "octal_escapes_decoded": oct_count,
        "powershell_arrays_resolved": ps_count,
        "radix_arithmetic_normalized": radix_count,
        "spliced_fragments_resolved": splicing_meta["spliced_fragments_resolved"],
        "dead_stores_pruned": splicing_meta["dead_stores_pruned"],
        "assembled_tokens": splicing_meta["assembled_tokens"],
    }

    return curr_text, telemetry
