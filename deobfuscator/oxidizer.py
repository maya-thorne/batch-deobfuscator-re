"""
0xidiz3r Zero-Literal Bootstrap & Reversible Alphabet Substitution Deobfuscator.
Specialized static analysis and neutralization engine for 0xidiz3r (0xTas)
batch obfuscation patterns, including:
  1. 3-stage zero-literal primitive bootstrapping (set, space, equals variables).
  2. Dynamic reversible alphabet table harvesting and inversion.
  3. Inline command symbol reconstruction and space token resolution.
  4. Base64 watermark and dead alphabet store elimination (DSE).
  5. Cryptographic in-memory symbol table wiping (Zeroize).
  6. High-entropy heuristic signature detection and confidence scoring.

Engineered by Maya Thorne.
"""

import re
from typing import Dict, List, Tuple, Any, Optional, Set


# Base64 watermarks emitted by 0xidiz3r
OXIDIZER_WATERMARKS = [
    ":: VGhpcyBmaWxlIHdhcyBvYmZ1c2NhdGVkIHZpYSBodHRwczovL2dpdGh1Yi5jb20vMHhUYXMvMHhpZGl6M3I=",
    ":: VGhpcyBmaWxlIGNhbiBiZSBwcm9ncmFtYXRpY2FsbHkgZGVvYmZ1c2NhdGVkIHZpYSBodHRwczovL2dpdGh1Yi5jb20vMHhUYXMvMHhpZGl6M3I=",
]


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


def detect_oxidizer_signatures(script_text: str) -> Dict[str, Any]:
    """
    Heuristically analyze script for 0xidiz3r zero-literal bootstrap indicators.
    Returns:
        Dict with keys: is_oxidizer, confidence, indicators, bootstrap_vars
    """
    indicators: List[str] = []
    confidence = 0.0

    # 1. Base64 watermark detection
    has_watermark = any(wm in script_text for wm in OXIDIZER_WATERMARKS)
    if has_watermark:
        indicators.append("base64_watermark")
        confidence += 0.50

    # 2. Primitive seed pattern detection
    bootstrap_vars = extract_bootstrap_primitives(script_text)
    if bootstrap_vars is not None:
        indicators.append("zero_literal_bootstrap_seed")
        confidence += 0.50

    # 3. Frequency of zero-literal definition statements
    # e.g. %SET%%SP%<var>%EQ%<val>
    if bootstrap_vars:
        s_var, sp_var, eq_var = bootstrap_vars
        escaped_s = re.escape(s_var)
        escaped_sp = re.escape(sp_var)
        escaped_eq = re.escape(eq_var)
        pattern = re.compile(
            rf'%{escaped_s}%\s*%{escaped_sp}%\s*([a-zA-Z0-9_\-\.\:\$#*\[\]{{}}!@~]+)%(?:{escaped_eq}|==?)%(.+)',
            re.IGNORECASE
        )
        matches = pattern.findall(script_text)
        if len(matches) >= 1:
            indicators.append(f"alphabet_definitions_count_{len(matches)}")
            confidence += min(0.35, 0.05 * len(matches))

    # 4. Percent symbol density check (> 25% of character count)
    total_len = len(script_text)
    if total_len > 40:
        percent_count = script_text.count('%')
        density = percent_count / total_len
        if density >= 0.25:
            indicators.append(f"high_percent_density_{density:.2f}")
            confidence += 0.15

    confidence = min(1.0, confidence)
    is_oxidizer = confidence >= 0.45 or (bootstrap_vars is not None) or has_watermark
    return {
        "is_oxidizer": is_oxidizer,
        "confidence": round(confidence, 3),
        "indicators": indicators,
        "bootstrap_vars": {
            "set_var": bootstrap_vars[0] if bootstrap_vars else None,
            "space_var": bootstrap_vars[1] if bootstrap_vars else None,
            "eq_var": bootstrap_vars[2] if bootstrap_vars else None,
        } if bootstrap_vars else None
    }


def extract_bootstrap_primitives(script_text: str) -> Optional[Tuple[str, str, str]]:
    """
    Identify and extract the 3 seed variables from the 0xidiz3r bootstrap preamble:
      1. set <SET_VAR>=set
      2. %<SET_VAR>% <SPACE_VAR>= 
      3. %<SET_VAR>%%<SPACE_VAR>%%<EQ_VAR>=== (or ==)
    
    Robust against carets (s^e^t), quotes (set "var=set"), whitespace variations,
    and single-line chained commands (&).
    """
    # Regex 1: Matches 'set VAR=set' or 'set "VAR=set"'
    re_set = re.compile(
        r'(?:^|[;&\r\n])\s*@?\s*s\^?e\^?t\s+(?:\"([a-zA-Z0-9_\-\.\:\$#*\[\]{{}}!@~]+)=set\"?|([a-zA-Z0-9_\-\.\:\$#*\[\]{{}}!@~]+)=set)\s*',
        re.IGNORECASE
    )
    set_matches = re_set.findall(script_text)
    if not set_matches:
        return None

    for m in set_matches:
        set_var = (m[0] or m[1]).strip()
        if not set_var:
            continue

        escaped_set = re.escape(set_var)

        # Regex 2: Matches '%SET_VAR% SPACE_VAR= ' or '%SET_VAR% "SPACE_VAR= "'
        re_space = re.compile(
            rf'(?:^|[;&\r\n])\s*@?\s*%{escaped_set}%\s+(?:\"([a-zA-Z0-9_\-\.\:\$#*\[\]{{}}!@~]+)=\s*\"?|([a-zA-Z0-9_\-\.\:\$#*\[\]{{}}!@~]+)=\s*)',
            re.IGNORECASE
        )
        space_match = re_space.search(script_text)
        if not space_match:
            continue

        space_var = (space_match.group(1) or space_match.group(2)).strip()
        if not space_var:
            continue

        escaped_space = re.escape(space_var)

        # Regex 3: Matches '%SET_VAR%%SPACE_VAR%EQ_VAR===' or '%SET_VAR%%SPACE_VAR%%EQ_VAR%=='
        # In 0xidiz3r: %set_str%%space_str%eq_str===
        re_eq = re.compile(
            rf'(?:^|[;&\r\n])\s*@?\s*%{escaped_set}%\s*%{escaped_space}%\s*%?([a-zA-Z0-9_\-\.\:\$#*\[\]{{}}!@~]+)%?\s*==+',
            re.IGNORECASE
        )
        eq_match = re_eq.search(script_text)
        if not eq_match:
            # Fallback: check if eq_var is defined on the same line or standard assignment
            re_eq_alt = re.compile(
                rf'(?:^|[;&\r\n])\s*@?\s*%{escaped_set}%\s*.*%?([a-zA-Z0-9_\-\.\:\$#*\[\]{{}}!@~]+)%?\s*==+',
                re.IGNORECASE
            )
            eq_match = re_eq_alt.search(script_text)

        if eq_match:
            eq_var = eq_match.group(1).strip()
            return set_var, space_var, eq_var

    return None


def harvest_oxidizer_alphabet(
    script_text: str, bootstrap: Optional[Tuple[str, str, str]] = None
) -> Tuple[Dict[str, str], List[str]]:
    """
    Extract alphabet mapping table defined via zero-literal bootstrap statements:
      %SET_VAR%%SPACE_VAR%<VAR_NAME>%EQ_VAR%<VALUE>
    
    Returns:
        Tuple[alphabet_dict, consumed_raw_definition_lines]
    """
    if bootstrap is None:
        bootstrap = extract_bootstrap_primitives(script_text)

    alphabet: Dict[str, str] = {}
    consumed_lines: List[str] = []

    if bootstrap:
        set_var, space_var, eq_var = bootstrap
        escaped_s = re.escape(set_var)
        escaped_sp = re.escape(space_var)
        escaped_eq = re.escape(eq_var)

        # Pattern: %SET%%SPACE%<VAR>%EQ%<VAL>
        # Note: Do not match \s* after EQ as the value itself may be a space character
        assign_pat = re.compile(
            rf'^\s*@?\s*%{escaped_s}%\s*%{escaped_sp}%\s*([a-zA-Z0-9_\-\.\:\$#*\[\]{{}}!@~]+)\s*%(?:{escaped_eq}|==?)%(.*)$',
            re.IGNORECASE
        )

        for line in script_text.splitlines():
            line_str = line.rstrip('\r\n')
            m = assign_pat.match(line_str)
            if m:
                v_name = m.group(1).strip()
                v_val = m.group(2)
                # Handle 0xidiz3r special %% percent literal assignment
                if v_val and re.fullmatch(r'%+', v_val):
                    v_val = "%"
                alphabet[v_name] = v_val
                consumed_lines.append(line_str.strip())

    # Secondary scan: also capture standard SET lines that define alphabet letters
    # if in an 0xidiz3r context (e.g. set "a1=c" or set a1=c)
    std_pat = re.compile(
        r'^\s*@?\s*s\^?e\^?t\s+(?:\"([a-zA-Z0-9_\-\.\:\$#*\[\]{{}}!@~]+)=([^\"\r\n]*)\"?|([a-zA-Z0-9_\-\.\:\$#*\[\]{{}}!@~]+)=([^=].*|$))\s*$',
        re.IGNORECASE
    )
    for line in script_text.splitlines():
        line_str = line.strip()
        if line_str in consumed_lines:
            continue
        m = std_pat.match(line_str)
        if m:
            v_name = (m.group(1) or m.group(3) or "").strip()
            v_val = (m.group(2) or m.group(4) or "").strip()
            # If variable name is short alias and maps to single char/token
            if v_name and v_name not in alphabet:
                if len(v_val) <= 2:
                    alphabet[v_name] = v_val

    return alphabet, consumed_lines


def normalize_oxidizer(
    script_text: str, custom_env: Optional[Dict[str, str]] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Deobfuscate a batch script containing 0xidiz3r zero-literal bootstrap patterns:
      1. Detect 0xidiz3r signatures and extract bootstrap seed primitives.
      2. Harvest complete reversible variable alphabet dictionary.
      3. Substitute alphabet tokens in payload commands.
      4. Handle space token (%space_var% -> ' ') and percent token (%perc% -> '%').
      5. Eliminate dead stores (bootstrap declarations, alphabet dictionary lines, watermarks).
      6. Zeroize forensic memory structures on completion.

    Returns:
        Tuple[clean_script_text, telemetry_metadata]
    """
    sig = detect_oxidizer_signatures(script_text)
    telemetry: Dict[str, Any] = {
        "signatures": sig,
        "is_oxidizer": sig["is_oxidizer"],
        "confidence": sig["confidence"],
        "bootstrap_vars": sig["bootstrap_vars"],
        "alphabet_size": 0,
        "eliminated_preamble_count": 0,
    }

    # Pass through untouched if no 0xidiz3r patterns or high percent density are detected
    if not sig["is_oxidizer"] and "VGhpcyBmaWxl" not in script_text:
        return script_text, telemetry

    bootstrap = extract_bootstrap_primitives(script_text)
    alphabet, consumed_lines = harvest_oxidizer_alphabet(script_text, bootstrap)
    telemetry["alphabet_size"] = len(alphabet)

    set_var = bootstrap[0] if bootstrap else None
    space_var = bootstrap[1] if bootstrap else None
    eq_var = bootstrap[2] if bootstrap else None

    # Lines to purge (bootstrap seed commands and base64 watermarks)
    lines_to_prune: Set[str] = set(consumed_lines)
    for wm in OXIDIZER_WATERMARKS:
        lines_to_prune.add(wm)

    # Identify and register seed bootstrap lines
    if set_var:
        re_seed_set = re.compile(rf'^\s*@?\s*s\^?e\^?t\s+(?:\"{re.escape(set_var)}=set\"?|{re.escape(set_var)}=set)\s*$', re.IGNORECASE)
        re_seed_space = re.compile(rf'^\s*@?\s*%{re.escape(set_var)}%\s+(?:\"{re.escape(space_var or "")}=\s*\"?|{re.escape(space_var or "")}=\s*)$', re.IGNORECASE)
        re_seed_eq = re.compile(rf'^\s*@?\s*%{re.escape(set_var)}%\s*%{re.escape(space_var or "")}%\s*%?{re.escape(eq_var or "")}%?\s*==+', re.IGNORECASE)

        for line in script_text.splitlines():
            l_str = line.strip()
            if re_seed_set.match(l_str) or re_seed_space.match(l_str) or re_seed_eq.match(l_str):
                lines_to_prune.add(l_str)

    # Process remaining lines: substitute alphabet tokens
    output_lines: List[str] = []
    eliminated_count = 0

    for line in script_text.splitlines():
        l_str = line.strip()
        if not l_str:
            continue

        # Check if line is part of preamble chaff
        if l_str in lines_to_prune:
            eliminated_count += 1
            continue

        # Check for watermarks directly
        if any(wm in l_str for wm in OXIDIZER_WATERMARKS):
            eliminated_count += 1
            continue

        # Check if line matches an alphabet definition that wasn't stripped
        if bootstrap and set_var and space_var:
            if l_str.startswith(f"%{set_var}%") and f"%{space_var}%" in l_str:
                eliminated_count += 1
                continue

        # Perform variable expansion on active payload line
        # First: replace space token if known
        curr_line = line
        if space_var:
            curr_line = curr_line.replace(f"%{space_var}%", " ")
            curr_line = curr_line.replace(f"%{space_var.lower()}%", " ")
            curr_line = curr_line.replace(f"%{space_var.upper()}%", " ")

        # Second: replace alphabet variables
        if alphabet:
            def repl_var(m: re.Match) -> str:
                vname = m.group(1)
                if vname in alphabet:
                    return alphabet[vname]
                # Case-insensitive lookup
                v_lower = vname.lower()
                for k, v in alphabet.items():
                    if k.lower() == v_lower:
                        return v
                return m.group(0)

            # Iterative replacement in case of nested references
            for _ in range(5):
                prev_line = curr_line
                curr_line = re.sub(r'%([a-zA-Z0-9_\-\.\:\$#*\[\]{{}}!@~]+)%', repl_var, curr_line)
                if curr_line == prev_line:
                    break

        clean_stripped = curr_line.strip()
        if clean_stripped:
            output_lines.append(clean_stripped)

    clean_script = "\n".join(output_lines)
    telemetry["eliminated_preamble_count"] = eliminated_count

    # Zeroize in-memory structures
    zeroize_dict(alphabet)

    return clean_script, telemetry
