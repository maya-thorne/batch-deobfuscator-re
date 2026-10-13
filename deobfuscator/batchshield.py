"""
BatchShield Virtual Symbol Table & Compound Environment Variable Deobfuscation Module.
Reverses high-entropy virtual symbol dictionaries, compound environment variable chains,
static OS variable indexing, and uninitialized dummy noise variables.
Part of batch-deobfuscator-re toolchain.
"""

import math
import re
from typing import Dict, Any, Tuple, List, Set, Optional

from .normalizers import DYNAMIC_SYSTEM_VARS

# Standard Windows OS environment variables used for static indexing in BatchShield
DEFAULT_OS_ENV: Dict[str, str] = {
    "comspec": r"C:\Windows\system32\cmd.exe",
    "systemroot": r"C:\Windows",
    "windir": r"C:\Windows",
    "programdata": r"C:\ProgramData",
    "public": r"C:\Users\Public",
    "allusersprofile": r"C:\ProgramData",
    "commonprogramfiles": r"C:\Program Files\Common Files",
    "commonprogramfiles(x86)": r"C:\Program Files (x86)\Common Files",
    "commonprogramw6432": r"C:\Program Files\Common Files",
    "programfiles": r"C:\Program Files",
    "programfiles(x86)": r"C:\Program Files (x86)",
    "driverdata": r"C:\Windows\System32\Drivers\DriverData",
    "path": r"C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem",
    "pathext": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
    "temp": r"C:\Users\Administrator\AppData\Local\Temp",
    "tmp": r"C:\Users\Administrator\AppData\Local\Temp",
    "appdata": r"C:\Users\Administrator\AppData\Roaming",
    "localappdata": r"C:\Users\Administrator\AppData\Local",
    "userprofile": r"C:\Users\Administrator",
    "username": "Administrator",
    "os": "Windows_NT",
    "systemdrive": "C:",
    "__appdir__": "C:\\Windows\\system32\\",
    "__cd__": "C:\\Windows\\system32\\",
    "computername": "DESKTOP-ENV",
    "processor_architecture": "AMD64",
    "homedrive": "C:",
    "homepath": r"\Users\Administrator",
}


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


def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy for an identifier or token string."""
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    n = len(text)
    for cnt in counts.values():
        p = cnt / n
        entropy -= p * math.log2(p)
    return entropy


def eval_batch_slice(val: str, start_raw: str, len_raw: Optional[str] = None) -> str:
    """
    Evaluate Windows batch substring slice syntax: %VAR:~start,length%.
    Accurately handles negative offsets, negative lengths, explicit positive signs, and clamps safely.
    """
    if not val:
        return ""
    try:
        start_str = start_raw.strip().lstrip("+")
        start = int(start_str) if start_str else 0
    except ValueError:
        return val

    n = len(val)
    actual_start = max(0, n + start) if start < 0 else min(n, start)

    if len_raw is None or not len_raw.strip():
        return val[actual_start:]

    try:
        length_str = len_raw.strip().lstrip("+")
        length = int(length_str) if length_str else 0
    except ValueError:
        return val[actual_start:]

    if length < 0:
        actual_end = max(actual_start, n + length)
        return val[actual_start:actual_end]
    else:
        actual_end = min(n, actual_start + length)
        return val[actual_start:actual_end]


def eval_batch_subst(val: str, old_raw: str, new_raw: str) -> str:
    """
    Evaluate Windows batch string substitution syntax: %VAR:old=new%.
    Case-insensitive, supports prefix wildcard *old=new matching cmd.exe semantics.
    """
    if not val or not old_raw:
        return val
    if old_raw.startswith("*"):
        match_pattern = old_raw[1:]
        if not match_pattern:
            return new_raw + val
        idx = val.lower().find(match_pattern.lower())
        if idx != -1:
            return new_raw + val[idx + len(match_pattern):]
        return val
    else:
        escaped_old = re.escape(old_raw)
        return re.sub(escaped_old, lambda _: new_raw, val, flags=re.IGNORECASE)


def detect_batchshield_signatures(script_text: str) -> Dict[str, Any]:
    """
    Detect signature indicators for BatchShield and high-entropy symbol table obfuscation.
    Returns:
        Dict with keys: is_batchshield, confidence, indicators, symbols_count, os_index_count, chains_count
    """
    indicators: List[str] = []
    confidence = 0.0

    # 1. Check for static OS variable indexing (%COMSPEC:~-7,3%, %PATH:~0,1%, etc.)
    os_idx_pat = re.compile(
        r'%(' + '|'.join(re.escape(k) for k in DEFAULT_OS_ENV.keys()) + r'):~\s*[+-]?\d+(?:\s*,\s*[+-]?\d+)?%',
        re.IGNORECASE
    )
    os_indices = os_idx_pat.findall(script_text)
    if os_indices:
        indicators.append(f"Static OS variable indexing detected ({len(os_indices)} instances)")
        confidence += min(0.60, len(os_indices) * 0.35)

    # 2. Check for high-entropy variable declarations
    set_pat = re.compile(
        r'(?:^|[;&@\(\)\s])set(?:\s+(?:/[ap]\s+)?|/[ap]\s*)["\']?([a-zA-Z0-9_#$@\-]+)=([^"\r\n;&]*)',
        re.IGNORECASE
    )
    var_defs = set_pat.findall(script_text)
    high_entropy_vars: List[str] = []
    chained_defs: List[str] = []

    for var_name, var_val in var_defs:
        v_clean = var_name.strip()
        if len(v_clean) >= 5 and calculate_shannon_entropy(v_clean) >= 2.3:
            high_entropy_vars.append(v_clean)
        if re.search(r'%[a-zA-Z0-9_#$@\-]+%', var_val):
            chained_defs.append(v_clean)

    if high_entropy_vars:
        indicators.append(f"High-entropy variable names detected ({len(high_entropy_vars)} vars)")
        confidence += min(0.40, len(high_entropy_vars) * 0.15)

    if chained_defs and len(chained_defs) >= 2:
        indicators.append(f"Chained variable references in definitions ({len(chained_defs)} chains)")
        confidence += min(0.30, len(chained_defs) * 0.10)

    # 3. Dense variable concatenation (%a%%b%%c%%d%)
    concat_pat = re.compile(r'(?:%[a-zA-Z0-9_#$@\-]+%){3,}')
    dense_concats = concat_pat.findall(script_text)
    if dense_concats:
        indicators.append(f"Dense token concatenation clusters ({len(dense_concats)} occurrences)")
        confidence += min(0.30, len(dense_concats) * 0.15)

    # 4. Uninitialized dummy variable noise patterns (%junk% embedded in words)
    dummy_noise_pat = re.compile(r'[a-zA-Z0-9_]%[a-zA-Z0-9_]{3,12}%[a-zA-Z0-9_]')
    dummy_matches = dummy_noise_pat.findall(script_text)
    if dummy_matches:
        indicators.append(f"Interleaved dummy variable noise detected ({len(dummy_matches)} tokens)")
        confidence += min(0.25, len(dummy_matches) * 0.10)

    confidence = min(1.0, round(confidence, 3))
    # BatchShield is specifically indicated by:
    # (a) Static OS variable indexing (e.g. %COMSPEC:~-7,3%)
    # OR (b) High-entropy variable names (e.g. set a8f9c2=...)
    # OR (c) Interleaved dummy variable noise
    # AND confidence >= 0.35
    is_batchshield = (len(os_indices) > 0 or len(high_entropy_vars) > 0 or len(dummy_matches) > 0) and confidence >= 0.35

    return {
        "is_batchshield": is_batchshield,
        "confidence": confidence,
        "indicators": indicators,
        "symbols_count": len(var_defs),
        "high_entropy_count": len(high_entropy_vars),
        "os_index_count": len(os_indices),
        "chains_count": len(chained_defs),
        "dummy_noise_count": len(dummy_matches),
    }


def harvest_batchshield_symbols(
    script_text: str, custom_env: Optional[Dict[str, str]] = None
) -> Tuple[Dict[str, str], List[str]]:
    """
    Extract virtual symbol definitions and iteratively resolve compound variable chains.
    Combines DEFAULT_OS_ENV, custom_env, and script-defined variables.
    Returns:
        Tuple[resolved_symbol_table, definition_lines]
    """
    env: Dict[str, str] = {k.lower(): v for k, v in DEFAULT_OS_ENV.items()}
    if custom_env:
        env.update({k.lower(): v for k, v in custom_env.items()})

    raw_symbols: Dict[str, str] = {}
    definition_lines: List[str] = []

    # Regex matching set statements anywhere in line
    set_line_pat = re.compile(
        r'(?:^|[;&@\(\)\s])set(?:\s+(?:/[ap]\s+)?|/[ap]\s*)(?:(?:"([^"=]+)=([^"]*)")|([^"=;\r\n\(\)]+)=([^;&\r\n\(\)]*))',
        re.IGNORECASE
    )

    for line in script_text.splitlines():
        for match in set_line_pat.finditer(line):
            var_name = match.group(1) or match.group(3)
            var_val = match.group(2) if match.group(1) else match.group(4)
            if var_name is not None and var_val is not None:
                cleaned_name = var_name.strip()
                cleaned_val = var_val.strip()
                raw_symbols[cleaned_name.lower()] = cleaned_val
                definition_lines.append(line)

    # Iterative multi-pass resolution for chained definitions (topological convergence)
    resolved_symbols: Dict[str, str] = dict(env)
    for k, v in raw_symbols.items():
        resolved_symbols[k] = v

    slice_pat = re.compile(r'%([a-zA-Z0-9_#$@\-]+):~([+-]?\s*\d+)(?:,([+-]?\s*\d+))?%', re.IGNORECASE)
    subst_pat = re.compile(r'%([a-zA-Z0-9_#$@\-]+):([^=%]+)=([^%]*)%', re.IGNORECASE)
    var_pat = re.compile(r'%([a-zA-Z0-9_#$@\-]+)%', re.IGNORECASE)

    max_chain_depth = 25
    for _ in range(max_chain_depth):
        changed = False
        for sym_name, sym_val in list(raw_symbols.items()):
            curr_val = resolved_symbols.get(sym_name, sym_val)
            new_val = curr_val

            # 1. Resolve slicing expressions in symbol value
            def _replace_slice(m: re.Match) -> str:
                vname = m.group(1).lower()
                off = m.group(2)
                length = m.group(3)
                if vname in resolved_symbols:
                    return eval_batch_slice(resolved_symbols[vname], off, length)
                return m.group(0)

            new_val = slice_pat.sub(_replace_slice, new_val)

            # 2. Resolve substitution expressions in symbol value
            def _replace_subst(m: re.Match) -> str:
                vname = m.group(1).lower()
                old_part = m.group(2)
                new_part = m.group(3)
                if vname in resolved_symbols:
                    return eval_batch_subst(resolved_symbols[vname], old_part, new_part)
                return m.group(0)

            new_val = subst_pat.sub(_replace_subst, new_val)

            # 3. Resolve direct variable references in symbol value
            def _replace_var(m: re.Match) -> str:
                vname = m.group(1).lower()
                if vname in resolved_symbols and vname != sym_name:
                    return resolved_symbols[vname]
                return m.group(0)

            new_val = var_pat.sub(_replace_var, new_val)

            if new_val != curr_val:
                resolved_symbols[sym_name] = new_val
                changed = True

        if not changed:
            break

    # Extract only symbols defined in script
    script_only_symbols = {k: resolved_symbols[k] for k in raw_symbols if k in resolved_symbols}
    return script_only_symbols, definition_lines


def resolve_batchshield_env_chains(
    script_text: str,
    symbol_table: Dict[str, str],
    custom_env: Optional[Dict[str, str]] = None
) -> Tuple[str, int]:
    """
    Resolve all chained variable references, slicing, and substitutions across the script.
    Returns:
        Tuple[resolved_script_text, total_resolutions_count]
    """
    merged_env: Dict[str, str] = {k.lower(): v for k, v in DEFAULT_OS_ENV.items()}
    if custom_env:
        merged_env.update({k.lower(): v for k, v in custom_env.items()})
    merged_env.update({k.lower(): v for k, v in symbol_table.items()})

    slice_pat = re.compile(r'%([a-zA-Z0-9_#$@\-]+):~([+-]?\s*\d+)(?:,([+-]?\s*\d+))?%', re.IGNORECASE)
    subst_pat = re.compile(r'%([a-zA-Z0-9_#$@\-]+):([^=%]+)=([^%]*)%', re.IGNORECASE)
    var_pat = re.compile(r'%([a-zA-Z0-9_#$@\-]+)%', re.IGNORECASE)

    current_text = script_text
    total_resolutions = 0

    for _ in range(15):
        pass_resolutions = 0

        # Pass A: Slicing
        def _slice_sub(m: re.Match) -> str:
            nonlocal pass_resolutions
            vname = m.group(1).lower()
            if vname in merged_env:
                pass_resolutions += 1
                return eval_batch_slice(merged_env[vname], m.group(2), m.group(3))
            return m.group(0)

        current_text = slice_pat.sub(_slice_sub, current_text)

        # Pass B: Substitutions
        def _subst_sub(m: re.Match) -> str:
            nonlocal pass_resolutions
            vname = m.group(1).lower()
            if vname in merged_env:
                pass_resolutions += 1
                return eval_batch_subst(merged_env[vname], m.group(2), m.group(3))
            return m.group(0)

        current_text = subst_pat.sub(_subst_sub, current_text)

        # Pass C: Direct variables
        def _var_sub(m: re.Match) -> str:
            nonlocal pass_resolutions
            vname = m.group(1).lower()
            if vname in merged_env:
                pass_resolutions += 1
                return merged_env[vname]
            return m.group(0)

        current_text = var_pat.sub(_var_sub, current_text)

        total_resolutions += pass_resolutions
        if pass_resolutions == 0:
            break

    return current_text, total_resolutions


def strip_batchshield_dummy_noise(
    script_text: str, known_symbols: Set[str]
) -> Tuple[str, int]:
    """
    Selectively strip undefined high-entropy / dummy noise variables (%random_chaff%)
    interleaved in commands, while strictly protecting:
      - Real defined variables in known_symbols
      - Standard dynamic system variables (random, errorlevel, cd, date, time)
      - Batch parameters (%0..%9, %*, %~dp0)
      - Loop variables (%%i, %i)
      - Literal percent signs (%%)
    Returns:
        Tuple[clean_script_text, stripped_count]
    """
    known_lower = {k.lower() for k in known_symbols}
    known_lower.update({k.lower() for k in DEFAULT_OS_ENV.keys()})
    known_lower.update(DYNAMIC_SYSTEM_VARS)

    lines = script_text.splitlines()
    clean_lines: List[str] = []
    stripped_count = 0

    # Pattern for single %var% matching alphanumeric and underscore tokens
    # Avoid matching %% or %~ or digits %0-%9
    var_token_pat = re.compile(r'(?<!%)(%)((?:~[a-zA-Z0-9$:]+)?[a-zA-Z0-9_#$@\-]+)(%)(?!%)')

    for line in lines:
        def _noise_sub(m: re.Match) -> str:
            nonlocal stripped_count
            token_body = m.group(2)
            # Check if this is a parameter like %1 or %~dp0
            if re.match(r'^(?:~[a-zA-Z0-9$:]*)?\d$', token_body) or token_body == "*":
                return m.group(0)
            token_lower = token_body.lower()
            if token_lower in known_lower:
                return m.group(0)
            # Token is undefined noise; eliminate it
            stripped_count += 1
            return ""

        clean_line = var_token_pat.sub(_noise_sub, line)
        clean_lines.append(clean_line)

    return "\n".join(clean_lines), stripped_count


def eliminate_batchshield_chaff(
    script_text: str, symbol_table: Dict[str, str]
) -> Tuple[str, List[str]]:
    """
    Eliminate definition lines for variables that were used purely as virtual symbol tables
    once all references in execution commands have been resolved.
    Preserves lines with chained commands or non-set statements.
    Returns:
        Tuple[clean_script_text, eliminated_variables]
    """
    sym_keys = {k.lower() for k in symbol_table.keys()}
    lines = script_text.splitlines()
    clean_lines: List[str] = []
    eliminated_vars: List[str] = []

    set_pure_pat = re.compile(
        r'^\s*set(?:\s+(?:/[ap]\s+)?|/[ap]\s*)(?:(?:"([^"=]+)=[^"]*")|([^"=]+)=.*)$',
        re.IGNORECASE
    )

    for line in lines:
        m = set_pure_pat.match(line)
        if m:
            var_name = (m.group(1) or m.group(2)).strip().lower()
            if var_name in sym_keys:
                eliminated_vars.append(var_name)
                continue
        clean_lines.append(line)

    return "\n".join(clean_lines), eliminated_vars


class BatchShieldNormalizer:
    """
    Object-oriented normalizer for BatchShield virtual symbol table and compound env deobfuscation.
    """

    def __init__(
        self,
        custom_env: Optional[Dict[str, str]] = None,
        strip_noise: bool = True,
        eliminate_chaff: bool = True
    ):
        self.custom_env = dict(custom_env) if custom_env else {}
        self.strip_noise = strip_noise
        self.eliminate_chaff = eliminate_chaff

    def normalize(self, script_text: str) -> Tuple[str, Dict[str, Any]]:
        """Execute full BatchShield normalizer pipeline on input script text."""
        signatures = detect_batchshield_signatures(script_text)
        if not signatures["is_batchshield"]:
            return script_text, {
                "signatures": signatures,
                "is_batchshield": False,
                "confidence": signatures["confidence"],
                "indicators": signatures["indicators"],
                "symbols_resolved_count": 0,
                "chains_resolved_count": 0,
                "noise_stripped_count": 0,
                "chaff_eliminated_count": 0,
                "eliminated_chaff": [],
            }

        symbols, _ = harvest_batchshield_symbols(script_text, self.custom_env)

        curr_text = script_text
        stripped_noise_count = 0

        # Step 1: Strip uninitialized dummy noise ONLY if dummy noise was detected
        if self.strip_noise and signatures["dummy_noise_count"] > 0:
            curr_text, stripped_noise_count = strip_batchshield_dummy_noise(
                curr_text, set(symbols.keys())
            )

        # Step 2: Resolve compound environment chains and virtual symbols
        curr_text, chains_resolved_count = resolve_batchshield_env_chains(
            curr_text, symbols, self.custom_env
        )

        # Step 3: Eliminate dead symbol table definitions only if chaff elimination is requested
        eliminated_chaff: List[str] = []
        if self.eliminate_chaff and symbols:
            curr_text, eliminated_chaff = eliminate_batchshield_chaff(curr_text, symbols)

        telemetry: Dict[str, Any] = {
            "signatures": signatures,
            "is_batchshield": signatures["is_batchshield"],
            "confidence": signatures["confidence"],
            "indicators": signatures["indicators"],
            "symbols_resolved_count": len(symbols),
            "chains_resolved_count": chains_resolved_count,
            "noise_stripped_count": stripped_noise_count,
            "chaff_eliminated_count": len(eliminated_chaff),
            "eliminated_chaff": eliminated_chaff,
        }

        # Memory wiping
        zeroize_dict(symbols)

        return curr_text, telemetry


def normalize_batchshield(
    script_text: str,
    custom_env: Optional[Dict[str, str]] = None,
    strip_noise: bool = True,
    eliminate_chaff: bool = True
) -> Tuple[str, Dict[str, Any]]:
    """
    Convenience function to run BatchShield deobfuscation on script text.
    Returns:
        Tuple[clean_script_text, telemetry_metadata]
    """
    normalizer = BatchShieldNormalizer(
        custom_env=custom_env,
        strip_noise=strip_noise,
        eliminate_chaff=eliminate_chaff
    )
    return normalizer.normalize(script_text)
