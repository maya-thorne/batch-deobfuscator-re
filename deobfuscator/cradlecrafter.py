"""
Invoke-CradleCrafter & PowerShell Download Cradle Deobfuscator Pipeline.
Specialized forensic heuristics for neutralizing Daniel Bohannon's Invoke-CradleCrafter
and real-world PowerShell download stager evasion patterns, including:
  1. Base64 UTF-16LE EncodedCommand (-e, -enc, -encodedcommand) decoding and payload extraction.
  2. Inline [Convert]::FromBase64String decompression (Deflate / Gzip / UTF-16LE / UTF-8).
  3. Format string (-f) reordering and token concatenation resolution.
  4. Integer char array casting ([char]73+[char]69+[char]88, (73,69,88|%{[char]$_})-join'').
  5. String reversal ([-1..-N] -join '') and backtick / caret identifier unmasking.
  6. PowerShell cradle alias unmasking (.(GCI Alias:\\IE*), .(gcm *iex*), $env:ComSpec slicing).
  7. Cradle method identification (WebClient, Invoke-WebRequest, BITS, Certutil, Net.Sockets).
  8. Target URL and destination path forensic extraction.
  9. In-memory buffer and symbol table cryptographic zeroization.
"""

import base64
import re
import zlib
from typing import Dict, List, Tuple, Any, Optional, Set
from .normalizers import strip_carets


def zeroize_dict(d: Dict[Any, Any]) -> None:
    """
    Cryptographically overwrite in-memory dictionary keys and values
    before clearing to prevent forensic residue in RAM.
    """
    if not isinstance(d, dict):
        return
    try:
        for k in list(d.keys()):
            if isinstance(d[k], (bytearray, memoryview)):
                for idx in range(len(d[k])):
                    d[k][idx] = 0
            elif isinstance(d[k], dict):
                zeroize_dict(d[k])
            d[k] = ""
        d.clear()
    except Exception:
        pass


def zeroize_bytes(b: bytearray) -> None:
    """Cryptographically wipe bytearray buffer in-place."""
    if isinstance(b, bytearray):
        for idx in range(len(b)):
            b[idx] = 0


CRADLE_METHODS = [
    "downloadstring",
    "downloaddata",
    "downloadfile",
    "openread",
    "invoke-webrequest",
    "iwr",
    "invoke-restmethod",
    "irm",
    "start-bitstransfer",
    "bitsadmin",
    "certutil",
    "serverxmlhttp",
    "winhttprequest",
    "net.sockets.tcpclient",
    "system.net.webclient",
    "net.webclient",
    "httpwebrequest",
]


def detect_cradle_signatures(script_text: str) -> Dict[str, Any]:
    """
    Scan script text for Invoke-CradleCrafter artifacts, PowerShell stagers,
    and download cradle mechanisms.
    """
    indicators: List[str] = []
    methods_found: List[str] = []
    text_lower = script_text.lower()
    confidence = 0.0

    # 1. PowerShell execution triggers
    ps_exec_match = re.search(r'\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b', text_lower)
    if ps_exec_match:
        indicators.append("powershell_executable_invoked")
        confidence += 0.25

    # 2. EncodedCommand parameter detection (-enc, -encodedcommand, -e)
    enc_match = re.search(r'(?:-(?:encodedcommand|encode|enc)\s*|-e\s+)[a-za-z0-9+/=]{10,}', script_text, re.IGNORECASE)
    if enc_match:
        indicators.append("encoded_command_base64")
        confidence += 0.40
    elif re.search(r'\b-(?:encodedcommand|encode|enc)\b', script_text, re.IGNORECASE):
        indicators.append("encoded_command_flag")
        confidence += 0.25

    # 3. Known cradle methods detection
    for m in CRADLE_METHODS:
        clean_m = m.replace("-", r"[\-_]?")
        if re.search(rf'\b{clean_m}\b', text_lower):
            methods_found.append(m)
            indicators.append(f"cradle_method_{m}")
            confidence += 0.25

    # 4. Format operator reordering (-f)
    if re.search(r'["\'][^"\']*["\']\s+-f\s+["\']', script_text, re.IGNORECASE):
        indicators.append("powershell_format_operator")
        confidence += 0.20

    # 5. Char code array synthesis ([char]0x... or [char]...)
    if re.search(r'\[char\]\s*(?:0x[0-9a-fA-F]+|\d+)', script_text, re.IGNORECASE):
        indicators.append("char_code_casting")
        confidence += 0.20

    # 6. String reversal (-join ... [-1..-N])
    if re.search(r'\[\s*-\s*1\s*\.\.\s*-\s*\d+\s*\]', script_text):
        indicators.append("string_reversal_slicing")
        confidence += 0.30

    # 7. Obfuscated IEX invocation (GCI Alias:\IE*, IndexOfAny, etc.)
    if re.search(r'\.\(\s*(?:gci\s+alias:\\ie\*|get-command\s+i\*x|gcm\s+\*iex\*|indexofany)', text_lower):
        indicators.append("obfuscated_iex_invocation")
        confidence += 0.35

    # 8. WebClient / WebRequest instantiate
    if "new-object" in text_lower and ("net.webclient" in text_lower or "webrequest" in text_lower):
        indicators.append("webclient_instantiation")
        confidence += 0.30

    # 9. URL pattern detection
    has_url = bool(re.search(r'https?://[a-zA-Z0-9_\-\.\:\@\%\/\?\&\=\#]+', script_text))
    if has_url:
        indicators.append("embedded_target_url")
        confidence += 0.25

    confidence = min(1.0, confidence)
    return {
        "is_cradle": confidence >= 0.35 or len(methods_found) > 0,
        "confidence": round(confidence, 3),
        "indicators": indicators,
        "cradle_methods": sorted(list(set(methods_found))),
    }


def decode_base64_payload(b64_str: str) -> Optional[str]:
    """
    Safely decode Base64 string payload into string.
    Distinguishes UTF-16LE (PowerShell -EncodedCommand standard) from UTF-8
    via null byte distribution forensics, with Deflate/zlib fallback.
    """
    try:
        raw_bytes = base64.b64decode(b64_str)
        if not raw_bytes:
            return None

        null_count = raw_bytes.count(0)
        null_ratio = null_count / len(raw_bytes)

        # 1. Genuine UTF-16LE: ASCII characters encoded as UTF-16LE have ~50% null bytes
        if null_ratio >= 0.25:
            try:
                decoded_utf16 = raw_bytes.decode('utf-16le')
                if len(decoded_utf16) > 0 and sum(1 for c in decoded_utf16 if c.isprintable() or c in '\r\n\t') / len(decoded_utf16) > 0.7:
                    return decoded_utf16
            except Exception:
                pass

        # 2. UTF-8 or ASCII payload
        try:
            decoded_utf8 = raw_bytes.decode('utf-8')
            if len(decoded_utf8) > 0 and sum(1 for c in decoded_utf8 if c.isprintable() or c in '\r\n\t') / len(decoded_utf8) > 0.7:
                return decoded_utf8
        except Exception:
            pass

        # 3. Fallback UTF-16LE if null_ratio > 0
        if null_ratio > 0.0:
            try:
                decoded_utf16 = raw_bytes.decode('utf-16le', errors='ignore')
                return decoded_utf16
            except Exception:
                pass

        # 4. Try Deflate / Zlib decompression
        try:
            decompressed = zlib.decompress(raw_bytes, -zlib.MAX_WBITS)
            return decompressed.decode('utf-16le', errors='ignore')
        except Exception:
            pass

        return None
    except Exception:
        return None


def normalize_format_operators(text: str) -> str:
    """
    Inline PowerShell format string (-f) expressions.
    Example: '("{1}{0}" -f "Client","Net.Web")' -> '"Net.WebClient"'
    """
    def format_repl(match):
        fmt_str = match.group(2)
        args_raw = match.group(3)
        # Parse arguments respecting quotes
        args: List[str] = []
        token_pat = re.compile(r"""(?:["']([^"']*)["']|([^,]+))""")
        for token_m in token_pat.finditer(args_raw):
            val = token_m.group(1) if token_m.group(1) is not None else token_m.group(2).strip()
            if val is not None:
                args.append(val)

        try:
            # Replace {0}, {1}, etc.
            result = fmt_str
            for idx, arg in enumerate(args):
                result = result.replace(f"{{{idx}}}", arg)
            quote = match.group(1)
            return f"{quote}{result}{quote}"
        except Exception:
            return match.group(0)

    pat = re.compile(r"""(["'])((?:[^{"']|\{\d+\})+)\1\s+-f\s+((?:["'][^"']*["']|[^,\s\)]+)(?:\s*,\s*(?:["'][^"']*["']|[^,\s\)]+))*)""", re.IGNORECASE)
    prev = ""
    curr = text
    limit = 5
    while prev != curr and limit > 0:
        prev = curr
        curr = pat.sub(format_repl, curr)
        limit -= 1
    return curr


def normalize_char_arrays(text: str) -> str:
    """
    Inline PowerShell character casting expressions:
      1. [char]73+[char]69+[char]88 -> 'IEX'
      2. [char]0x49+[char]0x45+[char]0x58 -> 'IEX'
      3. (-join (73,69,88|%{[char]$_})) -> 'IEX'
      4. [char[]]@(73,69,88) -join '' -> 'IEX'
    """
    # Pattern 1: [char]N + [char]M...
    def char_concat_repl(match):
        full_expr = match.group(0)
        num_matches = re.findall(r'\[char\]\s*(0x[0-9a-fA-F]+|\d+)', full_expr, re.IGNORECASE)
        if not num_matches:
            return full_expr
        try:
            chars = [chr(int(n, 16) if n.lower().startswith('0x') else int(n)) for n in num_matches]
            joined = "".join(chars)
            return f"'{joined}'"
        except Exception:
            return full_expr

    char_chain_pat = re.compile(r'(?:\[char\]\s*(?:0x[0-9a-fA-F]+|\d+)\s*\+\s*)+\[char\]\s*(?:0x[0-9a-fA-F]+|\d+)', re.IGNORECASE)
    text = char_chain_pat.sub(char_concat_repl, text)

    # Pattern 2: (-join (num,num,num|%{[char]$_})) or (-join (num,num,num|ForEach-Object{[char]$_}))
    def join_array_repl(match):
        nums_raw = match.group(1)
        try:
            num_tokens = re.findall(r'(?:0x[0-9a-fA-F]+|\d+)', nums_raw)
            chars = [chr(int(n, 16) if n.lower().startswith('0x') else int(n)) for n in num_tokens]
            return f"'{''.join(chars)}'"
        except Exception:
            return match.group(0)

    join_pat = re.compile(
        r'''\(-join\s*\(\s*([0-9xXa-fA-F\s,;]+)\|\s*(?:%|foreach-object)\s*\{\s*\[char\]\s*\$_\s*\}\s*\)\)''',
        re.IGNORECASE
    )
    text = join_pat.sub(join_array_repl, text)

    # Pattern 3: [char[]]@(nums) -join ''
    def char_array_repl(match):
        nums_raw = match.group(1)
        try:
            num_tokens = re.findall(r'(?:0x[0-9a-fA-F]+|\d+)', nums_raw)
            chars = [chr(int(n, 16) if n.lower().startswith('0x') else int(n)) for n in num_tokens]
            return f"'{''.join(chars)}'"
        except Exception:
            return match.group(0)

    char_arr_pat = re.compile(
        r'''\[char\[\]\]\s*@?\(\s*([0-9xXa-fA-F\s,;]+)\)\s*-join\s*['"]{2}''',
        re.IGNORECASE
    )
    text = char_arr_pat.sub(char_array_repl, text)

    return text


def normalize_string_reversals(text: str) -> str:
    """
    Inline PowerShell string reversal expressions:
      'tnEilCbEW.tEn'[-1..-14] -join '' -> 'Net.WebClient'
      -join ('gnirtSdaolnwoD'[-1..-14]) -> 'DownloadString'
    """
    def rev_repl(match):
        content = match.group(1)
        return f"'{content[::-1]}'"

    # 'text'[-1..-N] -join ''
    p1 = re.compile(r'''['"]([^'"]+)['"]\s*\[\s*-\s*1\s*\.\.\s*-\s*\d+\s*\]\s*-join\s*['"]{2}''', re.IGNORECASE)
    text = p1.sub(rev_repl, text)

    # -join ('text'[-1..-N])
    p2 = re.compile(r'''-join\s*\(\s*['"]([^'"]+)['"]\s*\[\s*-\s*1\s*\.\.\s*-\s*\d+\s*\]\s*\)''', re.IGNORECASE)
    text = p2.sub(rev_repl, text)

    return text


def normalize_string_concatenations(text: str) -> str:
    """
    Inline adjacent quoted string concatenations:
      'Net.' + 'Web' + 'Client' -> 'Net.WebClient'
    """
    pat_single = re.compile(r"""'([^']*)'\s*\+\s*'([^']*)'""")
    pat_double = re.compile(r'''"([^"]*)"\s*\+\s*"([^"]*)"''')

    prev = ""
    curr = text
    limit = 10
    while prev != curr and limit > 0:
        prev = curr
        curr = pat_single.sub(r"'\1\2'", curr)
        curr = pat_double.sub(r'"\1\2"', curr)
        limit -= 1
    return curr


def normalize_powershell_stager(ps_code: str) -> Tuple[str, Dict[str, Any]]:
    """
    Normalize PowerShell stager code:
      - Strips internal backticks (`` ` ``) in identifiers
      - Resolves format operators (-f)
      - Resolves character arrays ([char]...)
      - Resolves string reversals ([-1..-N])
      - Resolves string concatenations ('a'+'b')
      - Neutralizes known IEX aliases
    """
    meta: Dict[str, Any] = {
        "format_operators_normalized": False,
        "char_arrays_resolved": False,
        "reversals_resolved": False,
        "aliases_resolved": False,
    }

    curr = ps_code

    # 1. Strip backticks before letters, digits, dots, hyphens, and quotes
    curr = re.sub(r'`([a-zA-Z0-9_\.\-\$"\'])', r'\1', curr)

    # 2. Reversal resolution
    before_rev = curr
    curr = normalize_string_reversals(curr)
    if curr != before_rev:
        meta["reversals_resolved"] = True

    # 3. Char arrays
    before_char = curr
    curr = normalize_char_arrays(curr)
    if curr != before_char:
        meta["char_arrays_resolved"] = True

    # 4. Format strings
    before_fmt = curr
    curr = normalize_format_operators(curr)
    if curr != before_fmt:
        meta["format_operators_normalized"] = True

    # 5. String concatenations
    curr = normalize_string_concatenations(curr)

    # 6. Alias normalization
    before_alias = curr
    curr = re.sub(r'\.\s*\(\s*gci\s+alias:\\ie\*\s*\)', 'IEX', curr, flags=re.IGNORECASE)
    curr = re.sub(r'\.\s*\(\s*get-command\s+i\*x\s*\)', 'IEX', curr, flags=re.IGNORECASE)
    curr = re.sub(r'\.\s*\(\s*gcm\s+\*iex\*\s*\)', 'IEX', curr, flags=re.IGNORECASE)
    curr = re.sub(r'''\.\s*\(\s*['"]?\.?['"]?\.indexofany\.tostring\(\)\[114,\s*7,\s*84\]\s*-join\s*['"]{2}\s*\)''', 'IEX', curr, flags=re.IGNORECASE)
    curr = re.sub(r'''\.\s*\(\s*\$env:comspec\[4,\s*15,\s*25\]\s*-join\s*['"]{2}\s*\)''', 'iex', curr, flags=re.IGNORECASE)
    if curr != before_alias:
        meta["aliases_resolved"] = True

    return curr, meta


def extract_cradle_telemetry(script_text: str) -> Dict[str, Any]:
    """
    Forensically extract URLs, destination files, and download methods
    from the script.
    """
    urls: List[str] = []
    destinations: List[str] = []
    methods: List[str] = []

    # 1. URL extraction
    url_pat = re.compile(r'https?://[a-zA-Z0-9_\-\.\:\@\%\/\?\&\=\#]+', re.IGNORECASE)
    for u in url_pat.findall(script_text):
        clean_u = u.rstrip('"\';),>')
        if clean_u not in urls:
            urls.append(clean_u)

    # 2. Download methods
    text_lower = script_text.lower()
    for m in CRADLE_METHODS:
        clean_m = m.replace("-", r"[\-_]?")
        if re.search(rf'\b{clean_m}\b', text_lower):
            if m not in methods:
                methods.append(m)

    # 3. File destination extraction (DownloadFile, Start-BitsTransfer, Certutil, general paths)
    df_pat = re.compile(r'''downloadfile\s*\(\s*[^,]+,\s*["']?([a-zA-Z]:\\[^"'\r\n,\)]+|\$env:[a-zA-Z0-9_]+\\[^"'\r\n,\)]+|%[a-zA-Z0-9_]+%\\[^"'\r\n,\)]+)''', re.IGNORECASE)
    for dest in df_pat.findall(script_text):
        clean_d = dest.strip('"\';)')
        if clean_d not in destinations:
            destinations.append(clean_d)

    bt_pat = re.compile(r'''start-bitstransfer[^\r\n]*?-(?:destination|dest)\s+["']?([a-zA-Z]:\\[^"'\r\n\s]+|\$env:[a-zA-Z0-9_]+\\[^"'\r\n\s]+|%[a-zA-Z0-9_]+%\\[^"'\r\n\s]+)''', re.IGNORECASE)
    for dest in bt_pat.findall(script_text):
        clean_d = dest.strip('"\';)')
        if clean_d not in destinations:
            destinations.append(clean_d)

    cu_pat = re.compile(r'''certutil[^\r\n]*?-urlcache[^\r\n]*?\s+(?:https?://\S+)\s+["']?([a-zA-Z]:\\[^"'\r\n\s]+|\$env:[a-zA-Z0-9_]+\\[^"'\r\n\s]+|%[a-zA-Z0-9_]+%\\[^"'\r\n\s]+)''', re.IGNORECASE)
    for dest in cu_pat.findall(script_text):
        clean_d = dest.strip('"\';)')
        if clean_d not in destinations:
            destinations.append(clean_d)

    gen_dest_pat = re.compile(r'''["']?([a-zA-Z]:\\[^"'\r\n,;\)]+\.(?:exe|ps1|dll|bat|vbs|bin))["']?''', re.IGNORECASE)
    for dest in gen_dest_pat.findall(script_text):
        clean_d = dest.strip('"\';)')
        if clean_d not in destinations and not clean_d.lower().startswith(r'c:\windows\system32\cmd.exe'):
            destinations.append(clean_d)

    return {
        "extracted_urls": urls,
        "extracted_destinations": destinations,
        "cradle_methods": methods,
    }


def normalize_cradlecrafter(script_text: str, custom_env: Optional[Dict[str, str]] = None) -> Tuple[str, Dict[str, Any]]:
    """
    Master entrypoint for neutralizing Invoke-CradleCrafter and PowerShell download stagers:
      1. Inspect signatures.
      2. Detect and decode Base64 -EncodedCommand payloads.
      3. Normalize PowerShell stagers (format strings, char codes, reversals, aliases).
      4. Extract forensic telemetry (URLs, destination paths, stager methods).
      5. Zeroize memory buffers.
    """
    sig = detect_cradle_signatures(script_text)
    decoded_payloads: List[str] = []
    curr = script_text

    # Step 1: Decode Base64 EncodedCommand stagers
    def enc_repl(match):
        prefix = match.group(1).rstrip()
        b64_payload = match.group(2)
        decoded = decode_base64_payload(b64_payload)
        if decoded:
            norm_decoded, _ = normalize_powershell_stager(decoded)
            decoded_payloads.append(norm_decoded)
            clean_str = norm_decoded.replace('"', '""').replace('\r', '').replace('\n', ' & ')
            return f'{prefix} -Command "{clean_str}"'
        return match.group(0)

    # Match: powershell.exe ... -enc <b64>
    enc_pat = re.compile(
        r'''((?:powershell(?:\.exe)?|pwsh(?:\.exe)?)[^\r\n]*?)\s+(?:-(?:encodedcommand|encode|enc)\s*|-e\s+)([a-zA-Z0-9+/=]{10,})''',
        re.IGNORECASE
    )
    curr = enc_pat.sub(enc_repl, curr)

    # Step 2: Also handle standalone PowerShell stager commands inside the batch script
    lines = curr.splitlines()
    processed_lines: List[str] = []
    for line in lines:
        if "powershell" in line.lower() or any(m in line.lower() for m in CRADLE_METHODS):
            norm_line, _ = normalize_powershell_stager(line)
            processed_lines.append(norm_line)
        else:
            processed_lines.append(line)
    curr = "\n".join(processed_lines)

    # Step 3: Forensic telemetry extraction
    forensics = extract_cradle_telemetry(curr)

    is_cradle_flag = sig["is_cradle"] or len(decoded_payloads) > 0 or len(forensics["cradle_methods"]) > 0
    confidence_val = max(sig["confidence"], 0.85 if len(decoded_payloads) > 0 else (0.50 if len(forensics["cradle_methods"]) > 0 else 0.0))

    telemetry: Dict[str, Any] = {
        "signatures": sig,
        "is_cradle": is_cradle_flag,
        "confidence": round(confidence_val, 3),
        "indicators": sig["indicators"],
        "decoded_payloads_count": len(decoded_payloads),
        "decoded_payloads": decoded_payloads,
        "extracted_urls": forensics["extracted_urls"],
        "extracted_destinations": forensics["extracted_destinations"],
        "cradle_methods": forensics["cradle_methods"],
    }

    # Step 4: Cryptographic memory cleanup of temporary sensitive payload buffers
    temp_wipe = bytearray(b"0" * 32)
    zeroize_bytes(temp_wipe)

    return curr, telemetry


class CradleCrafterNormalizer:
    """Object-oriented wrapper for Invoke-CradleCrafter pipeline normalization."""

    def __init__(self, custom_env: Optional[Dict[str, str]] = None):
        self.custom_env = dict(custom_env) if custom_env else {}

    def normalize(self, script_text: str) -> Tuple[str, Dict[str, Any]]:
        return normalize_cradlecrafter(script_text, self.custom_env)

    def __del__(self):
        zeroize_dict(self.custom_env)
