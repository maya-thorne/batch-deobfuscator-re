"""
simple-batch-obfuscator Deobfuscator & Advanced Undefined Variable Noise Preprocessor.
Specializes in:
  1. Character-level random variable fragment infiltration stripping (%RAND_A%p%RAND_B%o...).
  2. Obfuscated delayed execution string normalization (setlocal enabledelayedexpansion).
  3. Dynamic 'set' keyword alias resolution (set "v1=s", set "v2=t", set "alias=!v1!e!v2!").
  4. Dynamic statement invocation dispatch (!alias! "var=chunk").
  5. Variable chunk harvesting and concatenation line reordering (%chunk1%%chunk2%...).
  6. Base64 UTF-16LE PowerShell stager extraction and forensic payload decoding.
  7. Multi-pass undefined variable noise elimination while preserving environment, dynamic,
     and batch argument variables.
  8. In-memory cryptographic memory buffer wiping (zeroize).
"""

import re
import base64
from typing import Dict, Any, Tuple, List, Set, Optional


DYNAMIC_SYSTEM_VARS = {
    "errorlevel",
    "cd",
    "random",
    "date",
    "time",
    "cmdextversion",
    "cmdcmdline",
    "highestnumanodenumber",
    "__cd__",
    "__appdir__",
}

DEFAULT_OS_VARS = {
    "comspec", "systemroot", "windir", "programdata", "public",
    "allusersprofile", "commonprogramfiles", "commonprogramfiles(x86)",
    "commonprogramw6432", "programfiles", "programfiles(x86)",
    "driverdata", "path", "pathext", "temp", "tmp", "appdata",
    "localappdata", "userprofile", "username", "os", "systemdrive",
    "computername", "processor_architecture", "homedrive", "homepath",
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


def detect_simple_obfuscator_signatures(script_text: str) -> Dict[str, Any]:
    """
    Detect markers and heuristic signatures of simple-batch-obfuscator and character-level
    undefined variable noise dispersion.
    """
    indicators: List[str] = []
    confidence = 0.0
    details: Dict[str, Any] = {}

    if not script_text:
        return {
            "is_simple_obfuscator": False,
            "confidence": 0.0,
            "indicators": [],
            "details": details,
        }

    # Guard: 0xidiz3r zero-literal bootstrap exclusion
    lower_script = script_text.lower()
    if (
        ("set s=set" in lower_script or "s^e^t \"setvar=set\"" in lower_script)
        and ("%eq%" in lower_script or "%eqvar%" in lower_script or "eq===" in lower_script)
    ):
        return {
            "is_simple_obfuscator": False,
            "confidence": 0.0,
            "indicators": [],
            "details": details,
        }

    # Indicator 1: Character-level undefined variable infiltration (%var%c%var%h%var%a...)
    # Search for patterns where at least 3 single letters in a row are separated by percent variables
    char_infilt_pat = re.compile(r'(?:%[a-zA-Z0-9_]+%[a-zA-Z0-9]){3,}')
    infilt_matches = len(char_infilt_pat.findall(script_text))
    details["char_infiltration_matches"] = infilt_matches
    if infilt_matches >= 1:
        indicators.append("character_level_variable_infiltration")
        confidence += min(0.40, 0.20 + (infilt_matches * 0.05))

    # Indicator 2: Delayed execution string noise (fragmented setlocal enabledelayedexpansion)
    has_delayed = False
    for line in script_text.splitlines():
        s = line.strip()
        if s.startswith("%") and s.endswith("%") and len(s) > 40:
            collapsed = re.sub(r'%[a-zA-Z0-9_]+%', '', s).strip().lower()
            if collapsed == "setlocal enabledelayedexpansion":
                has_delayed = True
                break
    if not has_delayed:
        delayed_noise_pat = re.compile(
            r'(?:%[a-zA-Z0-9_]+%)+s(?:%[a-zA-Z0-9_]+%)+e(?:%[a-zA-Z0-9_]+%)+t(?:%[a-zA-Z0-9_]+%)+l(?:%[a-zA-Z0-9_]+%)+o(?:%[a-zA-Z0-9_]+%)+c(?:%[a-zA-Z0-9_]+%)+a(?:%[a-zA-Z0-9_]+%)+l',
            re.IGNORECASE
        )
        if delayed_noise_pat.search(script_text):
            has_delayed = True

    if has_delayed:
        indicators.append("delayed_execution_string_noise")
        confidence += 0.35
        details["has_delayed_execution_noise"] = True

    # Indicator 3: Dynamic 'set' keyword synthesis (set "v1=s", set "v2=t", set "alias=!v1!e!v2!")
    dynamic_set_pat = re.compile(
        r'set\s+[\"\']?([a-zA-Z0-9_]+)=[!%][a-zA-Z0-9_]+[!%]e[!%][a-zA-Z0-9_]+[!%][\"\']?',
        re.IGNORECASE
    )
    if dynamic_set_pat.search(script_text):
        indicators.append("dynamic_set_keyword_synthesis")
        confidence += 0.25
        details["has_dynamic_set_synthesis"] = True

    # Indicator 4: Dynamic statement dispatch lines (!alias! "var=chunk")
    dispatch_pat = re.compile(r'^\s*![a-zA-Z0-9_]+!\s+[\"\'][a-zA-Z0-9_]+=.*[\"\']', re.MULTILINE)
    dispatch_count = len(dispatch_pat.findall(script_text))
    details["dynamic_dispatch_count"] = dispatch_count
    if dispatch_count >= 3:
        indicators.append("dynamic_statement_dispatch_clustering")
        confidence += min(0.35, 0.20 + (dispatch_count * 0.005))

    # Indicator 5: Chunk definitions correlated with concatenation line
    chunk_assign_pat = re.compile(
        r'^\s*(?:set\s+[\"\']?|![a-zA-Z0-9_]+!\s+[\"\'])([a-zA-Z0-9_]+)=([^\"\r\n]*)',
        re.MULTILINE | re.IGNORECASE
    )
    assigned_chunks = set()
    for m in chunk_assign_pat.finditer(script_text):
        vval = m.group(2)
        if "%" not in vval and "!" not in vval:
            assigned_chunks.add(m.group(1))

    details["assigned_chunks_count"] = len(assigned_chunks)

    concat_found = False
    pure_concat = False
    if len(assigned_chunks) >= 2:
        for line in script_text.splitlines():
            l = line.strip()
            if not l or l.startswith("::") or l.lower().startswith("rem"):
                continue
            percent_vars = re.findall(r'%([a-zA-Z0-9_]+)%', l)
            bang_vars = re.findall(r'!([a-zA-Z0-9_]+)!', l)
            vars_in_line = percent_vars if len(percent_vars) >= len(bang_vars) else bang_vars
            if len(vars_in_line) >= 2:
                matching = [v for v in vars_in_line if v in assigned_chunks]
                if len(matching) >= max(2, int(len(vars_in_line) * 0.7)):
                    concat_found = True
                    if re.match(r'^\s*(?:%[a-zA-Z0-9_]+%|![a-zA-Z0-9_]+!)+\s*$', l):
                        pure_concat = True
                    break

    if concat_found:
        indicators.append("variable_chunk_concatenation_line")
        confidence += 0.40
        details["has_chunk_concatenation_line"] = True
        details["pure_concat"] = pure_concat

    confidence = min(1.0, confidence)
    # A true simple-batch-obfuscator requires char infiltration, delayed execution noise, dynamic dispatch, or chunk concatenation
    has_ps_stager = any(kw in lower_script for kw in ["powershell", "-enc", "-encodedcommand", "downloadstring"])
    is_simple_obfuscator = (
        "character_level_variable_infiltration" in indicators
        or "delayed_execution_string_noise" in indicators
        or "dynamic_statement_dispatch_clustering" in indicators
        or ("dynamic_set_keyword_synthesis" in indicators and "variable_chunk_concatenation_line" in indicators)
        or ("variable_chunk_concatenation_line" in indicators and (has_ps_stager or (details.get("pure_concat", False) and len(assigned_chunks) >= 5)))
        or (confidence >= 0.50 and len(indicators) >= 2 and (has_ps_stager or details.get("pure_concat", False)))
    )

    return {
        "is_simple_obfuscator": is_simple_obfuscator,
        "confidence": round(confidence, 4),
        "indicators": indicators,
        "details": details,
    }


def normalize_delayed_execution_string(text: str) -> Tuple[str, bool]:
    """
    Detect and normalize obfuscated 'setlocal enabledelayedexpansion' string,
    where every character is surrounded by undefined random variable tokens.
    """
    pattern = re.compile(
        r'(?:%[a-zA-Z0-9_]+%s%[a-zA-Z0-9_]+%e%[a-zA-Z0-9_]+%t%[a-zA-Z0-9_]+%l%[a-zA-Z0-9_]+%o%[a-zA-Z0-9_]+%c%[a-zA-Z0-9_]+%a%[a-zA-Z0-9_]+%l%[a-zA-Z0-9_]+%\s*%[a-zA-Z0-9_]+%e%[a-zA-Z0-9_]+%n%[a-zA-Z0-9_]+%a%[a-zA-Z0-9_]+%b%[a-zA-Z0-9_]+%l%[a-zA-Z0-9_]+%e%[a-zA-Z0-9_]+%d%[a-zA-Z0-9_]+%e%[a-zA-Z0-9_]+%l%[a-zA-Z0-9_]+%a%[a-zA-Z0-9_]+%y%[a-zA-Z0-9_]+%e%[a-zA-Z0-9_]+%d%[a-zA-Z0-9_]+%e%[a-zA-Z0-9_]+%x%[a-zA-Z0-9_]+%p%[a-zA-Z0-9_]+%a%[a-zA-Z0-9_]+%n%[a-zA-Z0-9_]+%s%[a-zA-Z0-9_]+%i%[a-zA-Z0-9_]+%o%[a-zA-Z0-9_]+%n%[a-zA-Z0-9_]+%)',
        re.IGNORECASE
    )
    if pattern.search(text):
        clean_text = pattern.sub("setlocal enabledelayedexpansion", text)
        return clean_text, True

    # Generic variation: line containing mostly 's','e','t','l','o','c','a','l'... interleaved with %var%
    lines = text.splitlines()
    modified = False
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("%") and stripped.endswith("%") and len(stripped) > 50:
            # Strip all %...% and test if remaining is setlocal enabledelayedexpansion
            collapsed = re.sub(r'%[a-zA-Z0-9_]+%', '', stripped)
            if collapsed.strip().lower() == "setlocal enabledelayedexpansion":
                new_lines.append("setlocal enabledelayedexpansion")
                modified = True
                continue
        new_lines.append(line)

    return "\n".join(new_lines), modified


def resolve_dynamic_set_aliases(text: str) -> Tuple[str, Set[str]]:
    """
    Identify variable assignments that dynamically construct 'set':
      set "var_s=s"
      set "var_t=t"
      set "alias=!var_s!e!var_t!"  (or %var_s%e%var_t%)
    Returns updated script text with '!alias!' and '%alias%' unmasked to 'set',
    and set of discovered alias names.
    """
    aliases: Set[str] = set()

    # Track simple character assignments
    char_vars: Dict[str, str] = {}
    for m in re.finditer(r'set\s+[\"\']?([a-zA-Z0-9_]+)=([^\"\r\n]+)[\"\']?', text, re.IGNORECASE):
        vname = m.group(1).lower()
        vval = m.group(2).strip()
        if len(vval) == 1:
            char_vars[vname] = vval

    # Search for alias definition
    alias_pat = re.compile(
        r'set\s+[\"\']?([a-zA-Z0-9_]+)=([!%])([a-zA-Z0-9_]+)\2e([!%])([a-zA-Z0-9_]+)\4[\"\']?',
        re.IGNORECASE
    )
    for m in alias_pat.finditer(text):
        alias_name = m.group(1)
        v1 = m.group(3).lower()
        v2 = m.group(5).lower()
        val1 = char_vars.get(v1, "")
        val2 = char_vars.get(v2, "")
        if (val1 == "s" and val2 == "t") or (v1 == "s" and v2 == "t"):
            aliases.add(alias_name)

    # Direct synthesis: set "alias=set"
    direct_pat = re.compile(r'set\s+[\"\']?([a-zA-Z0-9_]+)=set[\"\']?', re.IGNORECASE)
    for m in direct_pat.finditer(text):
        aliases.add(m.group(1))

    if not aliases:
        return text, aliases

    # Replace invocations at start of lines or statements
    lines = text.splitlines()
    new_lines = []
    for line in lines:
        l = line
        for alias in aliases:
            # Replace !alias! at start of line
            l = re.sub(rf'^\s*!{re.escape(alias)}!\s+', 'set ', l)
            # Replace %alias% at start of line
            l = re.sub(rf'^\s*%{re.escape(alias)}%\s+', 'set ', l)
            # Replace after command delimiters
            l = re.sub(rf'([;&@]\s*)!{re.escape(alias)}!\s+', r'\1set ', l)
            l = re.sub(rf'([;&@]\s*)%{re.escape(alias)}%\s+', r'\1set ', l)
        new_lines.append(l)

    return "\n".join(new_lines), aliases


def strip_undefined_variable_noise(
    text: str,
    custom_env: Optional[Dict[str, str]] = None,
    preserve_known: bool = True
) -> Tuple[str, List[str]]:
    """
    Advanced multi-pass undefined variable cleaner.
    Safely eliminates random variable noise interleaved within tokens, keywords,
    and between characters, while strictly preserving:
      - Slicing and substitution expressions (%VAR:~start,len%, %VAR:old=new%)
      - Legitimate script variables declared via 'set'
      - Standard Windows OS environment variables
      - Dynamic OS pseudo-variables (%random%, %errorlevel%, %cd%, %date%, etc.)
      - Batch script parameters (%0..%9, %*, %~dp0, %~f0, etc.)
      - For-loop variables (%%a, %%i, %a, %i)
    """
    known_vars: Set[str] = set(DEFAULT_OS_VARS) | set(DYNAMIC_SYSTEM_VARS)
    if custom_env:
        known_vars.update(k.lower() for k in custom_env.keys())

    if preserve_known:
        # Harvest variables defined in script
        for m in re.finditer(r'set\s+(?:/[ap]\s+)?[\"\']?([a-zA-Z0-9_]+)=', text, re.IGNORECASE):
            known_vars.add(m.group(1).lower())

    stripped_vars: List[str] = []

    def var_repl(match):
        full = match.group(0)
        name = match.group(1)
        name_lower = name.lower()

        # Check if known
        if name_lower in known_vars:
            return full

        # Check for batch argument or parameter patterns: e.g. ~dp0, ~f0, 0..9
        if re.match(r'^(?:~[a-zA-Z]*\d|\d|\*)$', name):
            return full

        stripped_vars.append(name)
        return ""

    # Replace %VAR% (only pure identifier names without :, ~, =, etc. to protect slicing/substitution)
    result = re.sub(r'%([a-zA-Z0-9_]+)%', var_repl, text)

    # Replace !VAR! (delayed expansion noise)
    def del_var_repl(match):
        full = match.group(0)
        name = match.group(1)
        name_lower = name.lower()

        if name_lower in known_vars:
            return full
        if re.match(r'^(?:~[a-zA-Z]*\d|\d|\*)$', name):
            return full

        stripped_vars.append(name)
        return ""

    result = re.sub(r'!([a-zA-Z0-9_]+)!', del_var_repl, result)

    return result, stripped_vars


def extract_and_assemble_chunks(
    text: str,
    aliases: Set[str]
) -> Tuple[str, Dict[str, str], int, Optional[str], Optional[str]]:
    """
    Harvest variable chunks from statements:
      set "var_name=chunk_value"
    Identify the reassembly concatenation line (%var1%%var2%... or !var1!!var2!...),
    reconstruct the full command, optionally decode Base64 UTF-16LE PowerShell payload,
    and remove intermediate noise lines.
    """
    chunk_map: Dict[str, str] = {}
    lines = text.splitlines()
    chunk_line_indices: Set[int] = set()

    # Pattern for chunk assignment: set "VAR_NAME=CHUNK"
    chunk_assign_pat = re.compile(r'^\s*set\s+[\"\']?([a-zA-Z0-9_]+)=([^\"\r\n]*)[\"\']?\s*$', re.IGNORECASE)

    for idx, line in enumerate(lines):
        m = chunk_assign_pat.match(line)
        if m:
            vname = m.group(1)
            vval = m.group(2)
            if "%" in vval or "!" in vval:
                continue
            chunk_map[vname] = vval
            chunk_line_indices.add(idx)

    if len(chunk_map) < 3:
        return text, chunk_map, 0, None, None

    # Find the concatenation line (usually at or near the end)
    concat_line_idx: Optional[int] = None
    ordered_chunks: List[str] = []

    for idx in range(len(lines) - 1, -1, -1):
        line = lines[idx].strip()
        if not line or line.startswith("::") or line.lower().startswith("rem"):
            continue
        # Check if line consists of %var% or !var! references
        percent_vars = re.findall(r'%([a-zA-Z0-9_]+)%', line)
        bang_vars = re.findall(r'!([a-zA-Z0-9_]+)!', line)
        vars_in_line = percent_vars if len(percent_vars) >= len(bang_vars) else bang_vars

        if len(vars_in_line) >= 3:
            # Check overlap with chunk_map
            matching = [v for v in vars_in_line if v in chunk_map]
            if len(matching) >= len(vars_in_line) * 0.7:
                concat_line_idx = idx
                ordered_chunks = vars_in_line
                break

    if concat_line_idx is None or not ordered_chunks:
        return text, chunk_map, 0, None, None

    # Assemble the full command string by substituting chunk variables in the concatenation line
    raw_concat_line = lines[concat_line_idx]
    assembled_cmd = raw_concat_line
    for v in ordered_chunks:
        if v in chunk_map:
            assembled_cmd = assembled_cmd.replace(f"%{v}%", chunk_map[v])
            assembled_cmd = assembled_cmd.replace(f"!{v}!", chunk_map[v])
    assembled_cmd = assembled_cmd.strip()

    # Check for PowerShell Base64 EncodedCommand
    decoded_payload: Optional[str] = None
    b64_match = re.search(r'-EncodedCommand\s+([A-Za-z0-9+/=]+)', assembled_cmd, re.IGNORECASE)
    if not b64_match:
        b64_match = re.search(r'-enc\s+([A-Za-z0-9+/=]+)', assembled_cmd, re.IGNORECASE)

    if b64_match:
        raw_b64 = b64_match.group(1)
        try:
            pad = len(raw_b64) % 4
            if pad:
                raw_b64 += "=" * (4 - pad)
            decoded_bytes = base64.b64decode(raw_b64)
            # Try UTF-16LE then UTF-8
            try:
                decoded_payload = decoded_bytes.decode("utf-16le")
            except UnicodeDecodeError:
                decoded_payload = decoded_bytes.decode("utf-8", errors="replace")
        except Exception:
            decoded_payload = None

    # Reconstruct cleaned script:
    # Retain non-chunk lines, replace concatenation line with clean assembled command
    new_lines = []
    # Identify lines to prune: chunk assignments, delayed expansion line, dynamic set definitions
    lines_to_prune = set(chunk_line_indices)
    lines_to_prune.add(concat_line_idx)

    # Also prune dynamic set setup lines
    setup_pat = re.compile(r'^\s*set\s+[\"\']?([a-zA-Z0-9_]+)=[st!%]', re.IGNORECASE)
    for idx, line in enumerate(lines):
        if idx in lines_to_prune:
            continue
        if setup_pat.match(line) and any(alias in line for alias in aliases):
            lines_to_prune.add(idx)

    for idx, line in enumerate(lines):
        if idx == concat_line_idx:
            new_lines.append(assembled_cmd)
        elif idx not in lines_to_prune:
            new_lines.append(line)

    clean_text = "\n".join(new_lines).strip()
    return clean_text, chunk_map, len(ordered_chunks), assembled_cmd, decoded_payload


def normalize_simple_obfuscator(
    script_text: str,
    custom_env: Optional[Dict[str, str]] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Main entrypoint for simple-batch-obfuscator deobfuscation and undefined variable
    noise normalization.
    """
    meta: Dict[str, Any] = {
        "is_simple_obfuscator": False,
        "confidence": 0.0,
        "indicators": [],
        "delayed_expansion_normalized": False,
        "dynamic_set_aliases": [],
        "chunks_harvested_count": 0,
        "chunks_assembled_count": 0,
        "assembled_command": None,
        "decoded_powershell": None,
        "undefined_vars_stripped_count": 0,
        "stripped_variable_names": [],
    }

    sig = detect_simple_obfuscator_signatures(script_text)
    meta["is_simple_obfuscator"] = sig["is_simple_obfuscator"]
    meta["confidence"] = sig["confidence"]
    meta["indicators"] = list(sig["indicators"])

    curr_text = script_text

    # If simple-batch-obfuscator signatures are not present, do not modify script
    if not sig["is_simple_obfuscator"]:
        return curr_text, meta

    # Step 1: Normalize delayed execution string
    if sig.get("details", {}).get("has_delayed_execution_noise"):
        curr_text, delayed_norm = normalize_delayed_execution_string(curr_text)
        meta["delayed_expansion_normalized"] = delayed_norm

    # Step 2: Resolve dynamic 'set' aliases
    if sig.get("details", {}).get("has_dynamic_set_synthesis") or sig.get("details", {}).get("dynamic_dispatch_count", 0) > 0:
        curr_text, aliases = resolve_dynamic_set_aliases(curr_text)
        meta["dynamic_set_aliases"] = sorted(list(aliases))
    else:
        aliases = set()

    # Step 3: Extract chunks and reassemble concatenation line
    if (
        sig.get("details", {}).get("has_chunk_concatenation_line")
        or sig.get("details", {}).get("concatenation_line_count", 0) > 0
        or sig.get("details", {}).get("dynamic_dispatch_count", 0) > 0
    ):
        curr_text, chunk_map, assembled_count, assembled_cmd, decoded_ps = extract_and_assemble_chunks(
            curr_text, aliases
        )
        meta["chunks_harvested_count"] = len(chunk_map)
        meta["chunks_assembled_count"] = assembled_count
        meta["assembled_command"] = assembled_cmd
        meta["decoded_powershell"] = decoded_ps
        zeroize_dict(chunk_map)

    # Step 4: Multi-pass undefined variable noise elimination
    # Strip character-level undefined variable noise if character infiltration was detected
    if sig.get("details", {}).get("char_infiltration_matches", 0) >= 1 or "character_level_variable_infiltration" in sig["indicators"]:
        curr_text, stripped_vars = strip_undefined_variable_noise(curr_text, custom_env=custom_env)
        meta["undefined_vars_stripped_count"] = len(stripped_vars)
        meta["stripped_variable_names"] = sorted(list(set(stripped_vars)))

    return curr_text, meta


class SimpleObfuscatorNormalizer:
    """Object-oriented wrapper with context manager and cryptographic zeroization."""

    def __init__(self, custom_env: Optional[Dict[str, str]] = None):
        self.custom_env = dict(custom_env) if custom_env else {}
        self.last_telemetry: Dict[str, Any] = {}

    def normalize(self, script_text: str) -> Tuple[str, Dict[str, Any]]:
        clean_text, meta = normalize_simple_obfuscator(script_text, self.custom_env)
        self.last_telemetry = meta
        return clean_text, meta

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
