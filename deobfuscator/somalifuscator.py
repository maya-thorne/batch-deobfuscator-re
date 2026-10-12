"""
Somalifuscator Caesar Cipher Inversion & Array Normalization Engine.
Specialized heuristics for neutralizing Somalifuscator (KDot227 / Somali)
malware evasion patterns, including:
  1. Automated Caesar shift cipher rotation detection and inverse arithmetic solver.
  2. Full alphabet completion from partial variable substitution matrices.
  3. Single-pass 'for /l' wrapper loop decomposition and symbol extraction.
  4. Shuffled character array (KDOT) slicing resolution and space normalization.
  5. Scramble marker (%TO_SCRAMBLE_PLZ%) and anti-triage decoy preamble elimination.
  6. Caesar alphabet dead-store elimination (DSE) after payload inlining.
  7. In-memory forensic dictionary and buffer zeroization.

Engineered by Maya Thorne.
"""

import re
import string
from collections import Counter
from typing import Dict, List, Tuple, Any, Optional, Set


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


def solve_caesar_rotation(pairs: List[Tuple[str, str]]) -> Optional[int]:
    """
    Mathematically solve the Caesar rotation value k in [0, 25] by statistical
    consensus voting across candidate (variable_name, target_character) pairs.

    Somalifuscator generates pairs:
      - Lowercase: set "<rotated_letter>=<original_letter>"
      - Uppercase: set "<rotated_letter>1=<original_letter>" or s^et "<rotated_letter>1=..."

    Rotation formula:
      k = (ord(rotated) - ord(original)) % 26
    """
    votes: Counter = Counter()

    for var_name, char_val in pairs:
        clean_var = var_name.strip()
        clean_val = char_val.strip()

        # Lowercase mapping: 'd' -> 'a' (rotation = 3)
        if (
            len(clean_var) == 1
            and clean_var.isascii()
            and clean_var.isalpha()
            and clean_var.islower()
            and len(clean_val) == 1
            and clean_val.isascii()
            and clean_val.isalpha()
            and clean_val.islower()
        ):
            rot_k = (ord(clean_var) - ord(clean_val)) % 26
            votes[rot_k] += 1
            continue

        # Uppercase mapping: 'd1' -> 'A' (rotation = 3)
        if (
            len(clean_var) == 2
            and clean_var[1] == "1"
            and clean_var[0].isascii()
            and clean_var[0].isalpha()
            and len(clean_val) == 1
            and clean_val.isascii()
            and clean_val.isalpha()
            and clean_val.isupper()
        ):
            rot_k = (ord(clean_var[0].lower()) - ord(clean_val.lower())) % 26
            votes[rot_k] += 1
            continue

    if not votes:
        return None

    # Determine highest-voted rotation value
    winner, vote_count = votes.most_common(1)[0]
    # Minimum confidence threshold: at least 2 consistent votes
    if vote_count >= 2:
        return winner
    return None


def build_caesar_table(rotation_value: int) -> Dict[str, str]:
    """
    Construct the complete bidirectional Caesar cipher substitution dictionary
    for both lowercase and uppercase variants given rotation value k.
    """
    table: Dict[str, str] = {}
    lower_alpha = list(string.ascii_lowercase)
    upper_alpha = list(string.ascii_uppercase)

    k = rotation_value % 26
    rotated_lower = lower_alpha[k:] + lower_alpha[:k]
    rotated_upper = upper_alpha[k:] + upper_alpha[:k]

    # Lowercase mappings: rotated -> original
    for rot, orig in zip(rotated_lower, lower_alpha):
        table[rot] = orig

    # Uppercase mappings: rotated + "1" -> original (case-insensitive keys for batch)
    for rot, orig in zip(rotated_upper, upper_alpha):
        table[f"{rot.lower()}1"] = orig

    return table


def infer_and_complete_caesar_table(harvested: Dict[str, str]) -> Tuple[Dict[str, str], Optional[int]]:
    """
    Inspect a partially harvested dictionary of variables, detect the underlying
    Caesar shift value k, and synthesize the full 52-character alphabet substitution table.
    """
    pairs = [(k, v) for k, v in harvested.items()]
    rot_k = solve_caesar_rotation(pairs)
    if rot_k is not None:
        full_table = build_caesar_table(rot_k)
        # Preserve any existing harvested mappings
        full_table.update(harvested)
        return full_table, rot_k
    return {}, None


def unwrap_somalifuscator_loops(script_text: str) -> Tuple[str, Dict[str, str], List[str]]:
    """
    Detect and decompose Somalifuscator single-pass 'for /l' wrapper loops:
      for /l %%<var> in (<n>, <n>, <n>) do ( set "<rot>=<val>" )
      for /l %%r in (10, 10, 10) do ( s^et "d1=A" )
    Extracts the inner variable assignments into a symbol table and removes
    the wrapper loop lines to eliminate dead code.

    Returns:
        Tuple[clean_script_text, extracted_assignments, unwrapped_lines]
    """
    lines = script_text.splitlines()
    clean_lines: List[str] = []
    extracted: Dict[str, str] = {}
    unwrapped: List[str] = []

    # Regex matching 'for /l ... in (...) do ( set ... )' or similar single-line constructs
    for_loop_pat = re.compile(
        r'^\s*@?\s*for(?:\s+/[lf]\s+)?%%[a-zA-Z0-9_]+\s+in\s*\([^\)]*\)\s+do\s*\(\s*'
        r'(@?\s*s\^?e\^?t(?:\s+/[ap]\s+|\s+)?.*)\s*\)\s*$',
        re.IGNORECASE
    )

    assign_pat = re.compile(
        r'^\s*@?\s*s\^?e\^?t(?:\s+/[ap]\s+|\s+)?(?:\"([a-zA-Z0-9_\-\.\:\$%]+)=([^\"\r\n]*)\"?|([a-zA-Z0-9_\-\.\:\$%]+)=([^=].*|$))\s*$',
        re.IGNORECASE
    )

    for line in lines:
        stripped = line.strip()
        m_for = for_loop_pat.match(stripped)
        if m_for:
            inner_set = m_for.group(1).strip()
            # Clean carets from inner_set command keyword
            m_assign = assign_pat.match(inner_set)
            if m_assign:
                var_name = (m_assign.group(1) or m_assign.group(3) or "").strip().lower()
                var_val = (m_assign.group(2) or m_assign.group(4) or "").strip()
                # Remove inline carets from value if any
                var_val = var_val.replace("^", "")
                if var_name:
                    extracted[var_name] = var_val
                    unwrapped.append(stripped)
                    continue  # Loop line removed from active script

        clean_lines.append(line)

    return "\n".join(clean_lines), extracted, unwrapped


def extract_kdot_shuffled_array(script_text: str) -> Tuple[str, Optional[str]]:
    """
    Extract the shuffled character array variable 'set KDOT=<chars>' generated by Somalifuscator.
    Returns:
        Tuple[clean_script_text, kdot_value]
    """
    kdot_pat = re.compile(
        r'^\s*@?\s*set\s+[\"\']?kdot=([^\"\'\r\n]+)[\"\']?\s*$',
        re.IGNORECASE
    )

    lines = script_text.splitlines()
    clean_lines: List[str] = []
    kdot_value: Optional[str] = None

    for line in lines:
        m = kdot_pat.match(line.strip())
        if m:
            kdot_value = m.group(1).strip()
            clean_lines.append(line)
        else:
            clean_lines.append(line)

    return "\n".join(clean_lines), kdot_value


def resolve_kdot_slicing(text: str, kdot_val: str) -> str:
    """
    Resolve %KDOT:~<index>,<len>% and %KDOT:~<index>, 1% references directly against
    the extracted shuffled array string.
    """
    if not kdot_val:
        return text

    def repl(m):
        idx_str = m.group(1).strip()
        len_str = m.group(2).strip() if m.group(2) else "1"
        try:
            start = int(idx_str)
            length = int(len_str)
            val_len = len(kdot_val)
            if start < 0:
                start_idx = max(0, val_len + start)
            else:
                start_idx = min(val_len, start)
            end_idx = min(val_len, start_idx + length)
            return kdot_val[start_idx:end_idx]
        except (ValueError, IndexError):
            return m.group(0)

    pattern = re.compile(r'%kdot:~\s*(-?\d+)\s*(?:,\s*(-?\d+)\s*)?%', re.IGNORECASE)
    return pattern.sub(repl, text)


def strip_somalifuscator_chaff(
    script_text: str,
    caesar_vars: Set[str],
    kdot_found: bool = False
) -> Tuple[str, List[str]]:
    """
    Perform targeted Dead Store Elimination (DSE) for Somalifuscator dictionary assignments.
    Once Caesar variables (e.g. 'd', 'e', ..., 'd1', 'e1') and 'KDOT' are inlined into
    active commands, the 52+ standalone assignment lines become redundant dead stores.
    """
    lines = script_text.splitlines()
    clean_lines: List[str] = []
    eliminated: List[str] = []

    assign_pat = re.compile(
        r'^\s*@?\s*s\^?e\^?t(?:\s+/[ap]\s+|\s+)?(?:\"([a-zA-Z0-9_\-\.\:\$%]+)=([^\"\r\n]*)\"?|([a-zA-Z0-9_\-\.\:\$%]+)=([^=].*|$))\s*$',
        re.IGNORECASE
    )

    targets = {v.lower() for v in caesar_vars}
    if kdot_found:
        targets.add("kdot")

    decoy_patterns = [
        re.compile(r'^>nul\s+2>&1(?:\s*&&\s*exit.*)?$', re.IGNORECASE),
        re.compile(r'^exit\s+>nul\s+2>&1(?:\s*\|\|\s*cls)?$', re.IGNORECASE),
        re.compile(r'^chcp\s+65001(?:\s*>.*)?$', re.IGNORECASE),
        re.compile(r'^%to_scramble_plz%$', re.IGNORECASE),
        re.compile(r'^::\s*made by k\.dot', re.IGNORECASE),
    ]

    for line in lines:
        stripped = line.strip().lower()

        # Prune decoy preamble line if present
        if any(p.match(stripped) for p in decoy_patterns):
            eliminated.append(line.strip())
            continue

        # Prune dead Caesar / KDOT assignments
        m = assign_pat.match(line.strip())
        if m:
            var_name = (m.group(1) or m.group(3) or "").strip().lower()
            if var_name in targets:
                eliminated.append(var_name)
                continue

        clean_lines.append(line)

    return "\n".join(clean_lines), eliminated


def detect_somalifuscator_signatures(script_text: str) -> Dict[str, Any]:
    """
    Inspect script text for Somalifuscator architectural signatures and heuristics.
    Returns:
        Structured forensic telemetry dictionary.
    """
    indicators: List[str] = []
    text_lower = script_text.lower()

    # 1. Somalifuscator author/project markers
    if "somalifuscator" in text_lower or "k.dot" in text_lower or "kdot" in text_lower:
        indicators.append("somalifuscator-marker")

    # 2. Scramble directives
    if "%to_scramble_plz%" in text_lower:
        indicators.append("to-scramble-plz-markers")

    # 3. KDOT character table declaration or slicing
    if re.search(r'\bset\s+["\']?kdot=', text_lower) or "%kdot:~" in text_lower:
        indicators.append("kdot-alphabet-indexing")

    # 4. Caesar loop assignments (for /l %%... do ( set ... ))
    if re.search(r'for\s+/[lf]\s+%%[a-z0-9_]+\s+in\s*\([^\)]*\)\s+do\s*\(\s*s\^?e\^?t', text_lower):
        indicators.append("caesar-for-loop-table")

    # 5. Density of letter1 variables (e.g. %a1%, %b1%, %c1%)
    upper_caesar_matches = len(re.findall(r'%[a-z]1%', text_lower))
    if upper_caesar_matches >= 3:
        indicators.append("uppercase-caesar-variable-density")

    # 6. Anti-triage decoy header
    if ">nul 2>&1 && exit >nul 2>&1 || cls" in script_text:
        indicators.append("anti-triage-exit-cls-decoy")

    confidence = min(1.0, len(indicators) * 0.25)
    is_somalifuscator = confidence >= 0.45 or ("somalifuscator-marker" in indicators and len(indicators) >= 2)

    return {
        "is_somalifuscator": is_somalifuscator,
        "confidence": round(confidence, 2),
        "indicators": indicators,
    }


def normalize_somalifuscator(
    script_text: str,
    custom_env: Optional[Dict[str, str]] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Comprehensive Somalifuscator normalization and Caesar inversion pass:
      1. Detects Somalifuscator indicators.
      2. Neutralizes %TO_SCRAMBLE_PLZ% placeholders.
      3. Unwraps 'for /l' wrapper loop assignments into symbol definitions.
      4. Dissects and solves the Caesar rotation value k via consensus voting.
      5. Completes the full 52-character substitution dictionary.
      6. Resolves KDOT shuffled alphabet slicing.
      7. Prunes dead Caesar dictionary tables and helper chaff.
      8. Zeroizes internal decryption tables on completion.

    Returns:
        Tuple[clean_script_text, telemetry_metadata]
    """
    sig = detect_somalifuscator_signatures(script_text)
    telemetry: Dict[str, Any] = {
        "signatures": sig,
        "rotation_value": None,
        "unwrapped_loops_count": 0,
        "kdot_detected": False,
        "caesar_symbols_count": 0,
        "eliminated_chaff_count": 0,
    }

    # If script contains no Somalifuscator indicators, loops, or markers, pass through untouched
    if not sig["is_somalifuscator"] and "for" not in script_text.lower() and "kdot" not in script_text.lower() and "%to_scramble_plz%" not in script_text.lower():
        return script_text, telemetry

    curr_text = script_text

    # Step 1: Strip %TO_SCRAMBLE_PLZ% markers
    curr_text = curr_text.replace("%TO_SCRAMBLE_PLZ%", "")
    curr_text = curr_text.replace("%to_scramble_plz%", "")

    # Step 2: Unwrap 'for /l' loops and extract variable assignments
    curr_text, loop_extracted, unwrapped_lines = unwrap_somalifuscator_loops(curr_text)
    telemetry["unwrapped_loops_count"] = len(unwrapped_lines)

    # Step 3: Harvest standard 'set' statements in script
    assign_pat = re.compile(
        r'^\s*@?\s*s\^?e\^?t(?:\s+/[ap]\s+|\s+)?(?:\"([a-zA-Z0-9_\-\.\:\$%]+)=([^\"\r\n]*)\"?|([a-zA-Z0-9_\-\.\:\$%]+)=([^=].*|$))\s*$',
        re.IGNORECASE
    )

    harvested_vars: Dict[str, str] = dict(loop_extracted)
    for line in curr_text.splitlines():
        m = assign_pat.match(line.strip())
        if m:
            var_name = (m.group(1) or m.group(3) or "").strip().lower()
            var_val = (m.group(2) or m.group(4) or "").strip().replace("^", "")
            if var_name:
                harvested_vars[var_name] = var_val

    # Step 4: Solve Caesar shift value and construct complete table
    caesar_table, rot_k = infer_and_complete_caesar_table(harvested_vars)
    telemetry["rotation_value"] = rot_k
    telemetry["caesar_symbols_count"] = len(caesar_table)

    # Step 5: Extract KDOT shuffled array
    curr_text, kdot_val = extract_kdot_shuffled_array(curr_text)
    if kdot_val:
        telemetry["kdot_detected"] = True
        curr_text = resolve_kdot_slicing(curr_text, kdot_val)

    # Step 6: In-place substitution of Caesar variables into script
    # Matches %var% and %var1% where var is in caesar_table
    if caesar_table:
        def caesar_repl(m):
            v_name = m.group(1).lower()
            if v_name in caesar_table:
                return caesar_table[v_name]
            return m.group(0)

        # Apply Caesar substitutions across text
        curr_text = re.sub(r'%([a-zA-Z0-9_\-\.\:\$]+)%', caesar_repl, curr_text)

    # Step 7: Prune dead Caesar store statements and decoy preamble if confirmed Somalifuscator/Caesar
    if rot_k is not None or kdot_val or loop_extracted or sig["is_somalifuscator"]:
        caesar_keys = set(caesar_table.keys())
        curr_text, eliminated = strip_somalifuscator_chaff(
            curr_text, caesar_keys, kdot_found=bool(kdot_val)
        )
        telemetry["eliminated_chaff_count"] = len(eliminated)

    # Clean empty lines resulting from chaff pruning
    lines = [l for l in curr_text.splitlines() if l.strip()]
    curr_text = "\n".join(lines)

    # Cryptographic memory hygiene: wipe tables
    zeroize_dict(caesar_table)
    zeroize_dict(harvested_vars)
    zeroize_dict(loop_extracted)

    return curr_text, telemetry
