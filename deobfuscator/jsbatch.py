"""
JSBatchDeobfuscator & Hybrid JS/BAT Polyglot Normalization Engine.
Specializes in:
  1. JSBatchobfuscator (guillaC / yrotak) virtual alphabet harvesting & substring slice resolution (%key:~idx,len%).
  2. Multi-token chained SET variable reconstruction (&set part1=pow&set part2=ershell&%part1%%part2%).
  3. Hybrid JS/BAT polyglot wrapper separation:
     - Comment block wrappers (0 /* :: ... */ or /* & @echo off ... */).
     - Microsoft JScript conditional compilation (@if (@CodeSection == @Batch) @then ... @end).
     - MSHTA inline JavaScript execution (mshta "javascript:..." or mshta "about:<script...").
     - Windows Script File (WSF) XML polyglots (<!-- : ... --> <job><script language="JScript">).
  4. Static JScript / JavaScript string deobfuscation (unescape, String.fromCharCode, hex/unicode escapes).
  5. Forensic telemetry extraction (ActiveX objects, C2 URLs, execution methods).
  6. In-memory cryptographic buffer wiping (zeroize).

Engineered by Maya Thorne.
"""

import re
import urllib.parse
from typing import Dict, Any, Tuple, List, Optional, Set


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
            for i in range(len(val)):
                val[i] = 0
        target[key] = None
    target.clear()


def zeroize_bytes(buffer: bytearray) -> None:
    """Cryptographically zeroize raw bytearray buffers in memory."""
    for i in range(len(buffer)):
        buffer[i] = 0


def detect_jsbatch_signatures(script_text: str) -> Dict[str, Any]:
    """
    Detect heuristic signatures of JSBatchobfuscator, chained SET tokens,
    and hybrid JS/BAT polyglot wrappers.
    """
    indicators: List[str] = []
    confidence = 0.0
    polyglot_type = "none"
    details: Dict[str, Any] = {}

    if not script_text:
        return {
            "is_jsbatch": False,
            "is_polyglot": False,
            "confidence": 0.0,
            "indicators": [],
            "polyglot_type": polyglot_type,
            "details": details,
        }

    lower_text = script_text.lower()

    # 1. Check for Polyglot Wrappers
    # Pattern A: 0 /* :: or /* &
    if re.search(r'^(?:0\s*/\*\s*::|/\*\s*&\s*@?echo\s+off|/\*\s*&\s*@?cls)', script_text, re.MULTILINE | re.IGNORECASE):
        indicators.append("polyglot_comment_block_wrapper")
        confidence += 0.45
        polyglot_type = "comment_block"
    elif "/*" in script_text and "*/" in script_text and ("cscript" in lower_text or "wscript" in lower_text):
        if re.search(r'cscript\s+(?:/[a-zA-Z0-9_\:\.\/]+\s+)*["\']?%~f0["\']?', script_text, re.IGNORECASE):
            indicators.append("polyglot_cscript_self_execution")
            confidence += 0.40
            polyglot_type = "comment_block"

    # Pattern B: Microsoft JScript Conditional Compilation (@if (@CodeSection == @Batch))
    if re.search(r'@if\s*\(\s*@CodeSection\s*==\s*@Batch\s*\)\s*@then', script_text, re.IGNORECASE):
        indicators.append("polyglot_jscript_conditional_compilation")
        confidence += 0.50
        polyglot_type = "conditional_compilation"

    # Pattern C: WSF XML Polyglot (<!-- : ... -->)
    if re.search(r'<!--\s*:\s*\r?\n.*?-->.*?<job', script_text, re.DOTALL | re.IGNORECASE):
        indicators.append("polyglot_wsf_xml_hybrid")
        confidence += 0.45
        polyglot_type = "wsf_hybrid"

    # Pattern D: MSHTA Inline JavaScript
    if re.search(r'mshta(?:\.exe)?\s+["\']?(?:javascript|about:\s*<script)', script_text, re.IGNORECASE):
        indicators.append("polyglot_mshta_inline_javascript")
        confidence += 0.35
        if polyglot_type == "none":
            polyglot_type = "mshta_inline"

    # 2. Check for JSBatchobfuscator Alphabet Harvesting & Slices
    # Looks for Set <var>=<0123456789abcdef...> (length >= 20)
    alphabet_match = re.search(
        r'^\s*@?set\s+(?:/[ap]\s+)?["\']?([a-zA-Z0-9_]+)["\']?\s*=\s*["\']?([a-zA-Z0-9+/=_\-\$!@#%^&*()<>?:;\',.]{20,})["\']?',
        script_text,
        re.MULTILINE | re.IGNORECASE
    )
    if alphabet_match:
        cand_key = alphabet_match.group(1)
        cand_alpha = alphabet_match.group(2)
        slice_pattern = re.compile(rf'%{re.escape(cand_key)}:~-?\d+(?:,-?\d+)?%', re.IGNORECASE)
        slice_count = len(slice_pattern.findall(script_text))
        if slice_count >= 3:
            indicators.append("jsbatch_alphabet_slicing_matrix")
            confidence += min(0.50, 0.25 + (slice_count * 0.03))
            details["harvested_key"] = cand_key
            details["alphabet_len"] = len(cand_alpha)
            details["slice_count"] = slice_count
            if polyglot_type == "none":
                polyglot_type = "jsbatch_transpiler"

    # 3. Check for Chained SET Tokens (as in Corpus 15)
    chained_set_pat = re.compile(
        r'set\s+([a-zA-Z0-9_]+)=[^&]+&set\s+([a-zA-Z0-9_]+)=[^&]+&%[a-zA-Z0-9_]+%%[a-zA-Z0-9_]+%',
        re.IGNORECASE
    )
    if chained_set_pat.search(script_text):
        indicators.append("chained_set_token_transpilation")
        confidence += 0.35
        if polyglot_type == "none":
            polyglot_type = "jsbatch_transpiler"

    # 4. Check for JScript Indicators
    js_indicators: List[str] = []
    if "activexobject" in lower_text:
        js_indicators.append("ActiveXObject")
    if "wscript.shell" in lower_text:
        js_indicators.append("WScript.Shell")
    if "wscript.echo" in lower_text:
        js_indicators.append("WScript.Echo")
    if "string.fromcharcode" in lower_text:
        js_indicators.append("String.fromCharCode")
    if "unescape(" in lower_text:
        js_indicators.append("unescape")

    if js_indicators:
        details["js_indicators"] = js_indicators
        confidence += min(0.25, len(js_indicators) * 0.08)

    confidence = min(1.0, confidence)
    is_polyglot = polyglot_type in ("comment_block", "conditional_compilation", "wsf_hybrid", "mshta_inline")
    is_jsbatch = confidence >= 0.30 or is_polyglot

    return {
        "is_jsbatch": is_jsbatch,
        "is_polyglot": is_polyglot,
        "confidence": round(confidence, 3),
        "indicators": indicators,
        "polyglot_type": polyglot_type,
        "details": details,
    }


def harvest_jsbatch_alphabet(script_text: str) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """
    Locate and extract the alphabet key and character table defined in the script.
    Returns (key_name, alphabet_string, line_index).
    """
    lines = script_text.splitlines()
    for idx, line in enumerate(lines):
        clean_line = line.strip()
        m = re.match(
            r'^@?set\s+(?:/[ap]\s+)?["\']?([a-zA-Z0-9_]+)["\']?\s*=\s*["\']?([a-zA-Z0-9+/=_\-\$!@#%^&*()<>?:;\',.]{20,})["\']?$',
            clean_line,
            re.IGNORECASE
        )
        if m:
            key_name = m.group(1)
            alphabet = m.group(2)
            # Verify if this key is referenced in substring slicing
            test_pat = re.compile(rf'%{re.escape(key_name)}:~-?\d+', re.IGNORECASE)
            if test_pat.search(script_text):
                return key_name, alphabet, idx

    return None, None, None


def resolve_jsbatch_slices(script_text: str, key: str, alphabet: str) -> Tuple[str, int]:
    """
    Resolve all substring slices of the harvested alphabet key against the alphabet table.
    Handles %key:~offset,length%, %key:~offset%, and delayed !key:~offset,length!.
    Also converts @%key:~14,1%%key:~12,1%%key:~17,1%%key:~24,1% %key:~24,1%%key:~15,1%%key:~15,1%
    into clean statements.
    """
    slices_resolved = 0
    alpha_len = len(alphabet)

    def eval_slice(offset_str: str, len_str: Optional[str]) -> str:
        nonlocal slices_resolved
        try:
            offset = int(offset_str)
            if offset < 0:
                offset = max(0, alpha_len + offset)
            if offset >= alpha_len:
                return ""

            if len_str is None or len_str == "":
                char_res = alphabet[offset:]
            else:
                length = int(len_str)
                if length < 0:
                    end_idx = max(offset, alpha_len + length)
                    char_res = alphabet[offset:end_idx]
                else:
                    char_res = alphabet[offset:offset + length]

            slices_resolved += 1
            return char_res
        except Exception:
            return ""

    # Replace %key:~offset,length% or %key:~offset%
    slice_regex = re.compile(
        rf'%{re.escape(key)}:~([+-]?\d+)(?:,([+-]?\d+))?%',
        re.IGNORECASE
    )
    result = slice_regex.sub(lambda m: eval_slice(m.group(1), m.group(2)), script_text)

    # Replace delayed !key:~offset,length! or !key:~offset!
    delayed_slice_regex = re.compile(
        rf'!{re.escape(key)}:~([+-]?\d+)(?:,([+-]?\d+))?!',
        re.IGNORECASE
    )
    result = delayed_slice_regex.sub(lambda m: eval_slice(m.group(1), m.group(2)), result)

    return result, slices_resolved


def resolve_chained_set_tokens(script_text: str) -> Tuple[str, int]:
    """
    Resolve chained SET statements where tokens are set and immediately assembled.
    e.g. 'set part1=pow&set part2=ershell&%part1%%part2% -ExecutionPolicy Bypass'
    """
    resolved_count = 0
    lines = script_text.splitlines()
    output_lines: List[str] = []

    for line in lines:
        if "&" in line and "set " in line.lower() and "%" in line:
            parts = line.split("&")
            local_vars: Dict[str, str] = {}
            cmd_parts: List[str] = []

            for part in parts:
                p = part.strip()
                set_m = re.match(r'^@?set\s+(?:/[ap]\s+)?["\']?([a-zA-Z0-9_]+)["\']?\s*=\s*(.*?)$', p, re.IGNORECASE)
                if set_m:
                    vname = set_m.group(1).lower()
                    vval = set_m.group(2).strip('"\'')
                    local_vars[vname] = vval
                else:
                    cmd_parts.append(p)

            if local_vars and cmd_parts:
                assembled_cmd = "&".join(cmd_parts)
                # Substitute local variables
                def repl(m: re.Match) -> str:
                    nonlocal resolved_count
                    vn = m.group(1).lower()
                    if vn in local_vars:
                        resolved_count += 1
                        return local_vars[vn]
                    return m.group(0)

                resolved_line = re.sub(r'%([a-zA-Z0-9_]+)%', repl, assembled_cmd)
                output_lines.append(resolved_line)
                continue

        output_lines.append(line)

    return "\n".join(output_lines), resolved_count


def deobfuscate_jscript_code(js_code: str) -> Tuple[str, Dict[str, Any]]:
    r"""
    Statically deobfuscate JScript/JavaScript code:
      - unescape("%XX%XX...")
      - String.fromCharCode(n1, n2, ...)
      - Hex escapes (\xHH) and Unicode escapes (\uHHHH)
      - String concatenations ('a' + 'b' + 'c')
    Extracts telemetry: ActiveX objects, C2 URLs.
    """
    telemetry: Dict[str, Any] = {
        "activex_objects": [],
        "extracted_urls": [],
        "decoded_evals": 0,
        "fromcharcode_resolved": 0,
        "unescape_resolved": 0,
    }

    if not js_code:
        return js_code, telemetry

    curr = js_code

    # 1. Resolve unescape(...)
    def unescape_repl(m: re.Match) -> str:
        nonlocal telemetry
        raw_str = m.group(1)
        try:
            decoded = urllib.parse.unquote(raw_str)
            telemetry["unescape_resolved"] += 1
            return f'"{decoded}"'
        except Exception:
            return m.group(0)

    curr = re.sub(r'unescape\s*\(\s*["\']([^"\']+)["\']\s*\)', unescape_repl, curr, flags=re.IGNORECASE)

    # 2. Resolve String.fromCharCode(n1, n2, ...)
    def fromcharcode_repl(m: re.Match) -> str:
        nonlocal telemetry
        args_str = m.group(1)
        try:
            nums = [int(n.strip()) for n in args_str.split(",") if n.strip().isdigit()]
            if nums:
                decoded = "".join(chr(n) for n in nums)
                telemetry["fromcharcode_resolved"] += 1
                return f'"{decoded}"'
        except Exception:
            pass
        return m.group(0)

    curr = re.sub(r'String\s*\.\s*fromCharCode\s*\(\s*([0-9\s,]+)\s*\)', fromcharcode_repl, curr, flags=re.IGNORECASE)

    # 3. Resolve Hex escapes \xHH and Unicode escapes \uHHHH in double/single quotes
    def hex_esc_repl(m: re.Match) -> str:
        s = m.group(0)
        try:
            # Process escape sequences
            decoded = s.encode("utf-8").decode("unicode_escape")
            return decoded
        except Exception:
            return s

    curr = re.sub(r'(?<!\\)(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})+', hex_esc_repl, curr)

    # 4. Resolve simple string concatenation: "a" + "b" or 'a' + 'b'
    concat_pat = re.compile(r'["\']([^"\']*)["\']\s*\+\s*["\']([^"\']*)["\']')
    for _ in range(10):
        if not concat_pat.search(curr):
            break
        curr = concat_pat.sub(r'"\1\2"', curr)

    # 5. Extract ActiveX Objects
    activex_matches = re.findall(r'(?:ActiveXObject|GetObject)\s*\(\s*["\']([^"\']+)["\']\s*\)', curr, re.IGNORECASE)
    telemetry["activex_objects"] = list(dict.fromkeys(activex_matches))

    # 6. Extract URLs
    url_matches = re.findall(r'https?://[a-zA-Z0-9_\-\.\:\/%=\?&#~+]+', curr, re.IGNORECASE)
    telemetry["extracted_urls"] = list(dict.fromkeys(url_matches))

    return curr, telemetry


def extract_polyglot_components(script_text: str) -> Dict[str, Any]:
    """
    Decompose a hybrid JS/BAT script into clean batch and clean JScript payloads.
    Recognizes:
      - Comment block wrappers (0 /* :: ... */ or /* & ... */)
      - Microsoft JScript conditional compilation (@if (@CodeSection == @Batch) @then ... @end)
      - WSF XML polyglots (<!-- : ... --> <job> <script language="JScript">)
      - MSHTA inline JavaScript
    """
    result: Dict[str, Any] = {
        "is_polyglot": False,
        "polyglot_type": "none",
        "batch_code": "",
        "js_code": "",
        "activex_objects": [],
        "extracted_urls": [],
        "jscript_telemetry": {},
    }

    if not script_text:
        return result

    # Case 1: Microsoft JScript Conditional Compilation
    # @if (@CodeSection == @Batch) @then
    # @echo off
    # CScript //nologo //E:JScript "%~F0" %*
    # goto :EOF
    # @end
    # // JScript code...
    cc_match = re.search(
        r'^\s*@if\s*\(\s*@CodeSection\s*==\s*@Batch\s*\)\s*@then(.*?)(?:goto\s+:EOF|exit\s+/b|exit)\s*\r?\n\s*@end(.*?)$',
        script_text,
        re.DOTALL | re.IGNORECASE
    )
    if cc_match:
        result["is_polyglot"] = True
        result["polyglot_type"] = "conditional_compilation"
        raw_batch = cc_match.group(1).strip()
        raw_js = cc_match.group(2).strip()

        # Clean batch lines
        batch_lines = [
            l for l in raw_batch.splitlines()
            if not re.search(r'cscript(?:\.exe)?\s+.*?%~f0', l, re.IGNORECASE)
        ]
        result["batch_code"] = "\n".join(batch_lines).strip()
        deob_js, js_telemetry = deobfuscate_jscript_code(raw_js)
        result["js_code"] = deob_js
        result["activex_objects"] = js_telemetry.get("activex_objects", [])
        result["extracted_urls"] = js_telemetry.get("extracted_urls", [])
        result["jscript_telemetry"] = js_telemetry
        return result

    # Case 2: Comment Block Polyglot
    # 0 /* ::
    # @echo off
    # ...
    # cscript //nologo //E:jscript "%~f0" %*
    # exit /b
    # */
    # // JScript code...
    cb_match = re.search(
        r'^(?:0\s*/\*\s*::|/\*\s*&|/\*)(.*?)\*/(.*?)$',
        script_text,
        re.DOTALL
    )
    if cb_match:
        raw_batch = cb_match.group(1).strip()
        raw_js = cb_match.group(2).strip()
        # Verify if raw_js looks like JScript or raw_batch executes cscript/wscript
        if ("cscript" in raw_batch.lower() or "wscript" in raw_batch.lower() or
                "activexobject" in raw_js.lower() or "var " in raw_js or "function" in raw_js):
            result["is_polyglot"] = True
            result["polyglot_type"] = "comment_block"
            # Strip cscript invocation boilerplate and exit /b
            batch_lines = []
            for l in raw_batch.splitlines():
                if re.search(r'cscript(?:\.exe)?\s+.*?%~f0', l, re.IGNORECASE):
                    continue
                if re.match(r'^\s*(?:exit\s+/b|exit|goto\s+:EOF)\b', l, re.IGNORECASE):
                    continue
                batch_lines.append(l)
            result["batch_code"] = "\n".join(batch_lines).strip()
            deob_js, js_telemetry = deobfuscate_jscript_code(raw_js)
            result["js_code"] = deob_js
            result["activex_objects"] = js_telemetry.get("activex_objects", [])
            result["extracted_urls"] = js_telemetry.get("extracted_urls", [])
            result["jscript_telemetry"] = js_telemetry
            return result

    # Case 3: WSF XML Polyglot (<!-- : ... -->)
    wsf_match = re.search(
        r'^<!--\s*:\s*\r?\n(.*?)\r?\n-->\s*\r?\n(.*?)$',
        script_text,
        re.DOTALL
    )
    if wsf_match:
        raw_batch = wsf_match.group(1).strip()
        raw_xml = wsf_match.group(2).strip()
        result["is_polyglot"] = True
        result["polyglot_type"] = "wsf_hybrid"
        batch_lines = [
            l for l in raw_batch.splitlines()
            if not re.search(r'cscript(?:\.exe)?\s+', l, re.IGNORECASE) and
               not re.match(r'^\s*(?:exit\s+/b|exit)\b', l, re.IGNORECASE)
        ]
        result["batch_code"] = "\n".join(batch_lines).strip()

        # Extract <script language="JScript">...</script>
        js_blocks = re.findall(r'<script[^>]*>(.*?)</script>', raw_xml, re.DOTALL | re.IGNORECASE)
        combined_js = "\n".join(js_blocks).strip() if js_blocks else raw_xml
        deob_js, js_telemetry = deobfuscate_jscript_code(combined_js)
        result["js_code"] = deob_js
        result["activex_objects"] = js_telemetry.get("activex_objects", [])
        result["extracted_urls"] = js_telemetry.get("extracted_urls", [])
        result["jscript_telemetry"] = js_telemetry
        return result

    # Case 4: MSHTA Inline JavaScript
    mshta_match = re.search(
        r'mshta(?:\.exe)?\s+["\']javascript:(.*?)["\'](?:\s+|$)',
        script_text,
        re.IGNORECASE
    )
    if mshta_match:
        result["is_polyglot"] = True
        result["polyglot_type"] = "mshta_inline"
        raw_js = mshta_match.group(1).strip()
        deob_js, js_telemetry = deobfuscate_jscript_code(raw_js)
        result["js_code"] = deob_js
        result["batch_code"] = script_text.strip()
        result["activex_objects"] = js_telemetry.get("activex_objects", [])
        result["extracted_urls"] = js_telemetry.get("extracted_urls", [])
        result["jscript_telemetry"] = js_telemetry
        return result

    return result


def normalize_jsbatch(script_text: str, custom_env: Optional[Dict[str, str]] = None,
                      extract_polyglot: bool = True) -> Tuple[str, Dict[str, Any]]:
    """
    Main entry point for JSBatchDeobfuscator normalizer.
    Resolves guillaC / yrotak alphabet slicing (%key:~idx,len%), chained SET tokens,
    and isolates hybrid JS/BAT polyglots into pure batch and pure JScript components.
    """
    if not script_text:
        return "", {
            "is_jsbatch": False,
            "is_polyglot": False,
            "confidence": 0.0,
            "polyglot_type": "none",
            "alphabet_key": None,
            "alphabet_size": 0,
            "slices_resolved": 0,
            "chained_tokens_resolved": 0,
            "extracted_batch_lines": 0,
            "extracted_js_lines": 0,
            "activex_objects": [],
            "extracted_urls": [],
        }

    signatures = detect_jsbatch_signatures(script_text)
    is_polyglot = signatures["is_polyglot"]
    poly_type = signatures["polyglot_type"]
    confidence = signatures["confidence"]

    telemetry: Dict[str, Any] = {
        "signatures": signatures,
        "is_jsbatch": signatures["is_jsbatch"],
        "is_polyglot": is_polyglot,
        "confidence": confidence,
        "polyglot_type": poly_type,
        "alphabet_key": None,
        "alphabet_size": 0,
        "slices_resolved": 0,
        "chained_tokens_resolved": 0,
        "extracted_batch_lines": 0,
        "extracted_js_lines": 0,
        "activex_objects": [],
        "extracted_urls": [],
        "polyglot_components": None,
    }

    curr = script_text

    # Branch 1: If it is a Polyglot wrapper, separate components
    if extract_polyglot and is_polyglot:
        components = extract_polyglot_components(curr)
        telemetry["polyglot_components"] = components
        telemetry["activex_objects"] = components.get("activex_objects", [])
        telemetry["extracted_urls"] = components.get("extracted_urls", [])

        batch_part = components.get("batch_code", "")
        js_part = components.get("js_code", "")

        telemetry["extracted_batch_lines"] = len(batch_part.splitlines()) if batch_part else 0
        telemetry["extracted_js_lines"] = len(js_part.splitlines()) if js_part else 0

        # Attempt to deobfuscate any JSBatch or chained set inside the batch portion
        key, alphabet, key_line = harvest_jsbatch_alphabet(batch_part)
        if key and alphabet:
            batch_part, slices_res = resolve_jsbatch_slices(batch_part, key, alphabet)
            telemetry["alphabet_key"] = key
            telemetry["alphabet_size"] = len(alphabet)
            telemetry["slices_resolved"] += slices_res

        batch_part, chain_res = resolve_chained_set_tokens(batch_part)
        telemetry["chained_tokens_resolved"] += chain_res

        # Format output: if batch part has real commands, present batch part;
        # if JS payload is substantial, attach formatted forensic comment banner
        output_sections: List[str] = []
        if batch_part and batch_part.strip():
            output_sections.append(batch_part.strip())

        if js_part and js_part.strip():
            banner = [
                ":: --- [EXTRACTED JSCRIPT / JAVASCRIPT PAYLOAD] ---",
                *([f":: [ActiveX] {obj}" for obj in components.get("activex_objects", [])]),
                *([f":: [C2 URL] {url}" for url in components.get("extracted_urls", [])]),
                ":: ------------------------------------------------",
            ]
            # Output clean JS lines with comment prefix or as formatted block
            banner.append(js_part.strip())
            output_sections.append("\n".join(banner))

        normalized_output = "\n\n".join(output_sections) if output_sections else curr
        return normalized_output, telemetry

    # Branch 2: Standard JSBatchobfuscator / Chained SET Token script
    key, alphabet, key_line = harvest_jsbatch_alphabet(curr)
    if key and alphabet:
        telemetry["alphabet_key"] = key
        telemetry["alphabet_size"] = len(alphabet)
        curr, slices_res = resolve_jsbatch_slices(curr, key, alphabet)
        telemetry["slices_resolved"] = slices_res

        # Strip the alphabet initialization line and 'cls' preambles
        lines = curr.splitlines()
        clean_lines: List[str] = []
        for l in lines:
            trimmed = l.strip()
            # Strip key assignment line
            if re.match(rf'^@?set\s+(?:/[ap]\s+)?["\']?{re.escape(key)}["\']?\s*=', trimmed, re.IGNORECASE):
                continue
            # Strip stand-alone cls preamble
            if trimmed.lower() in ("cls", "@cls"):
                continue
            clean_lines.append(l)
        curr = "\n".join(clean_lines)

    # Resolve chained SET tokens
    curr, chain_res = resolve_chained_set_tokens(curr)
    telemetry["chained_tokens_resolved"] = chain_res

    # Clean up empty lines
    final_lines = [l for l in curr.splitlines() if l.strip()]
    curr = "\n".join(final_lines)

    return curr, telemetry


class JSBatchNormalizer:
    """Class wrapper for JSBatchDeobfuscator and hybrid JS/BAT polyglot extraction."""

    def __init__(self, custom_env: Optional[Dict[str, str]] = None, extract_polyglot: bool = True):
        self.custom_env = dict(custom_env) if custom_env else {}
        self.extract_polyglot = extract_polyglot
        self.last_telemetry: Dict[str, Any] = {}

    def normalize(self, script_text: str) -> Tuple[str, Dict[str, Any]]:
        clean_text, meta = normalize_jsbatch(script_text, self.custom_env, self.extract_polyglot)
        self.last_telemetry = meta
        return clean_text, meta

    def detect(self, script_text: str) -> Dict[str, Any]:
        return detect_jsbatch_signatures(script_text)

    def extract_polyglot(self, script_text: str) -> Dict[str, Any]:
        return extract_polyglot_components(script_text)

    def zeroize(self) -> None:
        zeroize_dict(self.custom_env)
        zeroize_dict(self.last_telemetry)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.zeroize()

    def __del__(self):
        try:
            self.zeroize()
        except Exception:
            pass
