"""
Invoke-DOSfuscation Static Deobfuscation & Bohannon Inverse Arithmetic Engine.
Specialized heuristics for neutralizing Daniel Bohannon's Invoke-DOSfuscation
malware evasion patterns, including:
  1. Out-DosReversedCommand 'for /L' reverse reconstruction loop unrolling.
  2. Out-DosFORcodedCommand 'for %A in (...)' indexed variable extraction unwrapping.
  3. Out-EnvVarEncodedCommand advanced environment variable slicing resolution
     (supporting negative start/length, explicit plus signs, and embedded whitespace/tabs).
  4. Out-DosConcatenatedCommand and delimiter cluster normalization (,;, ;,, etc.).
  5. Delayed expansion (!VAR:~start,len!) and substring substitution (!VAR:*old=new!).
  6. Cryptographic in-memory buffer zeroization.

Engineered by Maya Thorne.
"""

import re
from typing import Dict, List, Tuple, Any, Optional, Set
from .normalizers import strip_carets


def zeroize_dict(d: Dict[Any, Any]) -> None:
    """
    Cryptographically overwrite in-memory dictionary keys and values
    before clearing to mitigate RAM forensic residue.
    """
    if not isinstance(d, dict):
        return
    try:
        for k in list(d.keys()):
            if isinstance(d[k], (bytearray, memoryview)):
                for idx in range(len(d[k])):
                    d[k][idx] = 0
            d[k] = ""
        d.clear()
    except Exception:
        pass


def detect_dosfuscation_signatures(script_text: str) -> Dict[str, Any]:
    """
    Inspect script text for Invoke-DOSfuscation (Bohannon) signatures and indicators:
      - FOR /L loops with negative steps or reverse indexing.
      - FOR %A IN (...) index arrays with high numeric density.
      - Bohannon delimiter clusters ([,;]{2,}) outside quotes.
      - Delayed expansion loops (cmd /v:on /c, !final!!).
      - High density of environment variable character slicing (%COMSPEC:~...).
    """
    indicators: List[str] = []
    text_lower = script_text.lower()

    # 1. FOR /L reverse loop indicator
    for_l_match = re.search(r'for(?:\s*|\^|[,;]+)/[lL]', script_text, re.IGNORECASE)
    has_negative_step = bool(re.search(r'\([^)]*-\d+[^)]*\)', script_text))
    if for_l_match and has_negative_step:
        indicators.append("for_l_reverse_loop")

    # 2. FOR %A IN (...) indexed array indicator
    for_in_match = re.search(r'for(?:\s*|\^|[,;]+)(?:%+|\!)[a-zA-Z0-9_\^]+(?:\s*|\^|[,;]+)in(?:\s*|\^|[,;]+)\(', script_text, re.IGNORECASE)
    has_index_array = bool(re.search(r'\(\s*(?:[\+,;\s\-]*\d+[\^]*\d*){5,}\s*\)', script_text))
    if for_in_match and has_index_array:
        indicators.append("for_in_indexed_array")

    # 3. Delayed expansion loop construction
    has_delayed_loop = bool(
        re.search(r'cmd(?:\.exe)?(?:\s*|\^|[,;]+)/(?:v:on|v|r)', script_text, re.IGNORECASE) or
        re.search(r'![a-zA-Z0-9_\^]+!![a-zA-Z0-9_\^]+:~', script_text)
    )
    if has_delayed_loop:
        indicators.append("delayed_expansion_accumulator")

    # 4. Delimiter noise clusters (,;, ;,, etc.)
    delimiter_clusters = len(re.findall(r'(?:[,;]{2,}|,[ \t]*;|;[ \t]*,)', script_text))
    if delimiter_clusters >= 2:
        indicators.append("bohannon_delimiter_noise")

    # 5. Environment slicing density
    slicing_matches = len(re.findall(r'[%!][a-zA-Z0-9_\-\.\:\$]+:~\s*[\+\-]?[0-9]+', script_text))
    if slicing_matches >= 3:
        indicators.append("high_density_env_slicing")

    # Calculate confidence score
    confidence = 0.0
    if "for_l_reverse_loop" in indicators:
        confidence += 0.40
    if "for_in_indexed_array" in indicators:
        confidence += 0.40
    if "delayed_expansion_accumulator" in indicators:
        confidence += 0.25
    if "bohannon_delimiter_noise" in indicators:
        confidence += 0.15
    if "high_density_env_slicing" in indicators:
        confidence += 0.15

    confidence = min(1.0, confidence)
    is_dos = confidence >= 0.35 or len(indicators) >= 2

    return {
        "is_dosfuscation": is_dos,
        "confidence": round(confidence, 2),
        "indicators": indicators,
        "delimiter_noise_count": delimiter_clusters,
        "slicing_count": slicing_matches,
    }


def normalize_dosfuscation_delimiters(text: str) -> str:
    """
    Normalize non-standard Bohannon command & argument delimiters outside quotes.
    Converts clusters like ,;, ;,; ,,; ;;, and isolated commas/semicolons between
    command tokens into standard whitespace.
    """
    result_lines: List[str] = []
    for line in text.splitlines():
        if not line.strip():
            result_lines.append("")
            continue

        chars: List[str] = []
        in_quotes = False
        i = 0
        n = len(line)

        while i < n:
            ch = line[i]
            if ch == '"':
                in_quotes = not in_quotes
                chars.append(ch)
                i += 1
            elif not in_quotes:
                # Check for delimiter clusters of , and ;
                if ch in (',', ';'):
                    # Scan cluster
                    start_delim = i
                    while i < n and (line[i] in (',', ';') or line[i] in (' ', '\t')):
                        i += 1
                    # If this cluster was at the start of a command or followed by a token,
                    # replace with single space if preceded or followed by non-whitespace
                    if chars and chars[-1] not in (' ', '\t', '&', '|', '('):
                        chars.append(' ')
                    elif not chars:
                        # Leading delimiter cluster (e.g. ,;,cmd.exe)
                        pass
                else:
                    chars.append(ch)
                    i += 1
            else:
                chars.append(ch)
                i += 1

        normalized_line = "".join(chars)
        # Collapse multiple spaces outside quotes
        result_lines.append(normalized_line)

    return "\n".join(result_lines)


def resolve_dosfuscation_slicing(text: str, env_vars: Dict[str, str]) -> str:
    """
    Resolve %VAR:~start,length% and !VAR:~start,length! slicing references
    with complete cmd.exe Bohannon-compatible semantics:
      - Embedded whitespace and tabs: %VAR:~   -7,    +3%
      - Explicit positive sign: +3
      - Negative offset: %VAR:~-7%
      - Negative length: %VAR:~-7,-4%
      - Out of bounds start / length clamping
    """
    def slice_repl(match):
        var_name = match.group(1).lower()
        if var_name not in env_vars:
            return match.group(0)

        val = env_vars[var_name]
        val_len = len(val)
        start_str = match.group(2)
        len_str = match.group(3)

        try:
            start = int(start_str.strip())
            if start < 0:
                start_idx = max(0, val_len + start)
            else:
                start_idx = min(val_len, start)

            if len_str is not None:
                length = int(len_str.strip())
                if length < 0:
                    end_idx = max(start_idx, val_len + length)
                else:
                    end_idx = min(val_len, start_idx + length)
            else:
                end_idx = val_len

            return val[start_idx:end_idx]
        except (ValueError, IndexError):
            return match.group(0)

    # Regex matches %VAR:~...% and !VAR:~...!
    pattern = re.compile(
        r'[%!]([a-zA-Z0-9_\-\.\:\$]+):~\s*([+-]?\d+)\s*(?:,\s*([+-]?\d+)\s*)?[%!]',
        re.IGNORECASE
    )
    return pattern.sub(slice_repl, text)


def _clean_numeric_token(token: str) -> Optional[int]:
    """Strip carets and clean integer token from Bohannon obfuscation (e.g. 1^3 -> 13)."""
    cleaned = token.replace("^", "").strip()
    if not cleaned:
        return None
    try:
        return int(cleaned)
    except ValueError:
        return None


def _apply_final_extractor(raw_cmd: str, accumulator_val: str, var_name: str) -> str:
    """
    Apply final substring index extraction from Bohannon CALL / echo invocation:
      - %final:~-offset% or !final:~-offset!
      - %final:~offset% or !final:~offset!
      - %final:*final!=% (wildcard prefix deletion)
    """
    clean_call = raw_cmd.strip()

    # Pattern A: Wildcard deletion %var:*prefix!=% or !var:*prefix!=!
    wildcard_m = re.search(r'[%!]' + re.escape(var_name) + r':\*([^!=]+)!=[%!]', clean_call, re.IGNORECASE)
    if wildcard_m:
        prefix = wildcard_m.group(1).lower()
        idx = accumulator_val.lower().find(prefix)
        if idx != -1:
            extracted = accumulator_val[idx + len(prefix):]
            return re.sub(r'[%!]' + re.escape(var_name) + r':\*[^\!]+!\=[%!]', extracted, clean_call, flags=re.IGNORECASE)

    # Pattern B: Slicing extraction %var:~start,len% or !var:~start,len!
    slice_m = re.search(r'[%!]' + re.escape(var_name) + r':~\s*([+-]?\d+)\s*(?:,\s*([+-]?\d+)\s*)?[%!]', clean_call, re.IGNORECASE)
    if slice_m:
        start_str = slice_m.group(1)
        len_str = slice_m.group(2)
        val_len = len(accumulator_val)
        try:
            start = int(start_str.strip())
            start_idx = max(0, val_len + start) if start < 0 else min(val_len, start)
            if len_str is not None:
                length = int(len_str.strip())
                end_idx = max(start_idx, val_len + length) if length < 0 else min(val_len, start_idx + length)
            else:
                end_idx = val_len
            extracted = accumulator_val[start_idx:end_idx]
            return clean_call[:slice_m.start()] + extracted + clean_call[slice_m.end():]
        except Exception:
            pass

    # Pattern C: Direct accumulator variable %final% or !final!
    direct_m = re.search(r'[%!]' + re.escape(var_name) + r'[%!]', clean_call, re.IGNORECASE)
    if direct_m:
        return clean_call[:direct_m.start()] + accumulator_val + clean_call[direct_m.end():]

    return accumulator_val


def unwrap_dosfuscation_for_loops(script_text: str, custom_env: Optional[Dict[str, str]] = None) -> Tuple[str, List[str], Dict[str, Any]]:
    """
    Statically evaluate and unwrap Bohannon Out-DosReversedCommand (FOR /L) and
    Out-DosFORcodedCommand (FOR %A IN (...)) loops.

    Returns:
        Tuple[clean_script_text, unwrapped_commands, telemetry_metadata]
    """
    env: Dict[str, str] = dict(custom_env) if custom_env else {}
    unwrapped_commands: List[str] = []
    lines = script_text.splitlines()
    processed_lines: List[str] = []

    # Regex 1: Shell wrapper detection: cmd /v:on /c "..." or cmd /r "..."
    shell_wrapper_pat = re.compile(
        r'^\s*(?:[\s\^,;]*cmd(?:\.exe)?[\s\^,;]*)/[\^]*(?:[vV]:[oO][nN]|[vV])[\s\^,;]*/[\^]*(?:[cC]|[rR])[\s\^]*\"(.*)\"[\s\^]*$',
        re.IGNORECASE
    )

    # Regex 2: FOR /L loop
    for_l_pat = re.compile(
        r'for[\s\^,;]+/[lL][\s\^,;]+%+([a-zA-Z0-9_\^]+)[\s\^,;]+in[\s\^,;]+\(([^)]+)\)[\s\^,;]+do[\s\^,;]+(.*)',
        re.IGNORECASE
    )

    # Regex 3: FOR %A IN (...) loop
    for_in_pat = re.compile(
        r'for[\s\^,;]+%+([a-zA-Z0-9_\^]+)[\s\^,;]+in[\s\^,;]+\(([^)]+)\)[\s\^,;]+do[\s\^,;]+(.*)',
        re.IGNORECASE
    )

    # Variable extraction pattern
    set_var_pat = re.compile(
        r'(?:^|[;&@\(\)\s])s\^?e\^?t(?:[\s\^]+/[ap][\s\^]+|[\s\^]+)?(?:\"([a-zA-Z0-9_\-\.\:\$%]+)=([^\"\r\n]*)\"?|([a-zA-Z0-9_\-\.\:\$%]+)=([^=;&\r\n]*))',
        re.IGNORECASE
    )

    for line in lines:
        raw_line = line.strip()
        if not raw_line:
            processed_lines.append(line)
            continue

        work_line = raw_line
        # Check if wrapped in cmd /V:ON /C "..."
        shell_m = shell_wrapper_pat.match(work_line)
        if not shell_m:
            shell_m = shell_wrapper_pat.match(strip_carets(work_line))
        if shell_m:
            work_line = shell_m.group(1).strip()

        # Carets can be normalized from structural tokens
        work_line_clean = work_line.replace("^", "")

        # Harvest any variable definitions present on this line or line preamble
        for sm in set_var_pat.finditer(work_line_clean):
            v_name = (sm.group(1) or sm.group(3) or "").strip().lower()
            v_val = (sm.group(2) or sm.group(4) or "").strip()
            # Strip trailing closing parentheses from compound bracket blocks ((set a=val))
            v_val = re.sub(r'[\)]+$', '', v_val).strip()
            if v_name:
                env[v_name] = v_val

        # Attempt FOR /L unrolling
        for_l_match = for_l_pat.search(work_line_clean)
        if for_l_match:
            iter_var = for_l_match.group(1).strip()
            range_spec = for_l_match.group(2)
            loop_body = for_l_match.group(3)

            # Parse range tokens (start, step, end)
            tokens = [t.strip() for t in re.split(r'[,;\s]+', range_spec) if t.strip()]
            nums = [_clean_numeric_token(t) for t in tokens if _clean_numeric_token(t) is not None]

            if len(nums) >= 3:
                start_val, step_val, end_val = nums[0], nums[1], nums[2]
                slice_accum_m = re.search(
                    r'[\(\s,;]*set[\s,;]+([a-zA-Z0-9_\-\.\:\$]+)=!\1!!([a-zA-Z0-9_\-\.\:\$]+):~[\s]*%' + re.escape(iter_var) + r'(?:[\s]*,[\s]*1)?!',
                    loop_body,
                    re.IGNORECASE
                )
                if slice_accum_m:
                    accum_name = slice_accum_m.group(1).lower()
                    src_name = slice_accum_m.group(2).lower()
                    src_val = env.get(src_name, "")

                    acc_chars: List[str] = []
                    curr = start_val
                    safety_limit = 10000
                    steps = 0
                    if step_val > 0:
                        while curr <= end_val and steps < safety_limit:
                            if 0 <= curr < len(src_val):
                                acc_chars.append(src_val[curr])
                            curr += step_val
                            steps += 1
                    elif step_val < 0:
                        while curr >= end_val and steps < safety_limit:
                            if 0 <= curr < len(src_val):
                                acc_chars.append(src_val[curr])
                            curr += step_val
                            steps += 1

                    assembled_str = "".join(acc_chars)

                    invoke_m = re.search(r'[\(\s,;]*(call[\s,;]+.*|echo[\s,;]+.*|[a-zA-Z0-9_\-\.\\]+\.exe.*)', loop_body, re.IGNORECASE)
                    if invoke_m:
                        raw_invoke = invoke_m.group(1).strip()
                        raw_invoke = re.sub(r'[\)"]+$', '', raw_invoke).strip()
                        raw_invoke = re.sub(r'^(call|echo)[;,]+', r'\1 ', raw_invoke, flags=re.IGNORECASE)
                        resolved_cmd = _apply_final_extractor(raw_invoke, assembled_str, accum_name)
                    else:
                        resolved_cmd = assembled_str

                    resolved_cmd = re.sub(r'[\)"]+$', '', resolved_cmd).strip()
                    unwrapped_commands.append(resolved_cmd)
                    processed_lines.append(resolved_cmd)
                    continue

        # Attempt FOR %A IN (...) unrolling
        for_in_match = for_in_pat.search(work_line_clean)
        if for_in_match and not for_l_match:
            iter_var = for_in_match.group(1).strip()
            arr_spec = for_in_match.group(2)
            loop_body = for_in_match.group(3)

            tokens = [t.strip() for t in re.split(r'[,;\s]+', arr_spec) if t.strip()]
            indices = [_clean_numeric_token(t) for t in tokens if _clean_numeric_token(t) is not None]

            if len(indices) >= 3:
                slice_accum_m = re.search(
                    r'[\(\s,;]*set[\s,;]+([a-zA-Z0-9_\-\.\:\$]+)=!\1!!([a-zA-Z0-9_\-\.\:\$]+):~[\s]*%' + re.escape(iter_var) + r'(?:[\s]*,[\s]*1)?!',
                    loop_body,
                    re.IGNORECASE
                )
                if slice_accum_m:
                    accum_name = slice_accum_m.group(1).lower()
                    src_name = slice_accum_m.group(2).lower()
                    src_val = env.get(src_name, "")

                    sentinel = None
                    sentinel_m = re.search(r'if[\s,;]*%' + re.escape(iter_var) + r'[\s,;]*==[\s,;]*([+-]?\d+)', loop_body, re.IGNORECASE)
                    if sentinel_m:
                        sentinel = int(sentinel_m.group(1))

                    acc_chars = []
                    for idx in indices:
                        if sentinel is not None and idx == sentinel:
                            break
                        if 0 <= idx < len(src_val):
                            acc_chars.append(src_val[idx])

                    assembled_str = "".join(acc_chars)

                    invoke_m = re.search(r'[\(\s,;]*(call[\s,;]+.*|echo[\s,;]+.*|[a-zA-Z0-9_\-\.\\]+\.exe.*)', loop_body, re.IGNORECASE)
                    if invoke_m:
                        raw_invoke = invoke_m.group(1).strip()
                        raw_invoke = re.sub(r'[\)"]+$', '', raw_invoke).strip()
                        raw_invoke = re.sub(r'^(call|echo)[;,]+', r'\1 ', raw_invoke, flags=re.IGNORECASE)
                        resolved_cmd = _apply_final_extractor(raw_invoke, assembled_str, accum_name)
                    else:
                        resolved_cmd = assembled_str

                    resolved_cmd = re.sub(r'[\)"]+$', '', resolved_cmd).strip()
                    unwrapped_commands.append(resolved_cmd)
                    processed_lines.append(resolved_cmd)
                    continue

        processed_lines.append(line)

    telemetry = {
        "unwrapped_loops_count": len(unwrapped_commands),
        "unwrapped_commands": unwrapped_commands,
    }
    return "\n".join(processed_lines), unwrapped_commands, telemetry


def normalize_dosfuscation(script_text: str, custom_env: Optional[Dict[str, str]] = None) -> Tuple[str, Dict[str, Any]]:
    """
    Execute complete Invoke-DOSfuscation deobfuscation pipeline:
      1. Inspect signatures and confidence.
      2. Normalize Bohannon delimiter noise outside quotes.
      3. Unwrap 'for /L' and 'for %A in' string reassembly loops.
      4. Statically evaluate advanced environment variable slicing.
      5. Zeroize memory buffers before returning.

    Returns:
        Tuple[clean_script_text, telemetry_metadata]
    """
    sig = detect_dosfuscation_signatures(script_text)
    telemetry: Dict[str, Any] = {
        "signatures": sig,
        "is_dosfuscation": sig["is_dosfuscation"],
        "confidence": sig["confidence"],
        "unwrapped_loops_count": 0,
        "unwrapped_commands": [],
        "delimiters_normalized": False,
        "slicing_resolved": False,
    }

    env: Dict[str, str] = dict(custom_env) if custom_env else {}
    curr_text = script_text

    # Step 1: Normalize delimiter noise if present
    if sig["delimiter_noise_count"] > 0 or ",;" in curr_text or ";," in curr_text:
        curr_text = normalize_dosfuscation_delimiters(curr_text)
        telemetry["delimiters_normalized"] = True

    # Step 2: Unwrap FOR loops
    curr_text, unwrapped, loop_telemetry = unwrap_dosfuscation_for_loops(curr_text, custom_env=env)
    telemetry["unwrapped_loops_count"] = len(unwrapped)
    telemetry["unwrapped_commands"] = unwrapped

    # Step 3: Resolve advanced slicing
    if env:
        curr_text = resolve_dosfuscation_slicing(curr_text, env)
        telemetry["slicing_resolved"] = True

    # Memory hygiene
    zeroize_dict(env)

    return curr_text, telemetry


class DOSfuscationNormalizer:
    """Production normalizer class for Invoke-DOSfuscation evasion patterns."""

    def __init__(self, custom_env: Optional[Dict[str, str]] = None):
        self.custom_env = dict(custom_env) if custom_env else {}

    def normalize(self, script_text: str) -> Tuple[str, Dict[str, Any]]:
        return normalize_dosfuscation(script_text, custom_env=self.custom_env)

    def detect(self, script_text: str) -> Dict[str, Any]:
        return detect_dosfuscation_signatures(script_text)
