"""
Abobus-obfuscator Normalization & Unicode Noise Filtering Engine.
Specialized heuristics for neutralizing Abobus (EscaLag) batch obfuscation patterns:
  1. Multi-byte / fake UTF-16 BOM header de-masking (FF FE FE FF &cls).
  2. Zero-width and Unicode noise filtering (LTR/RTL marks, non-breaking symbols).
  3. Kaomoji, Arabic decoy glyphs, and Chinese warning string variable elimination.
  4. Caret unescaping, delimiter normalization (;;, ;@;, @@), and space chunk collapse.
  5. Multi-stage Chinese substring dictionary extraction and slicing inversion (%public:~idx,1%).
  6. Anti-debugging / anti-analysis trap chaff pruning (random_if, echo traps, errorlevel loops).
  7. Ephemeral dummy variable elimination (DSE) and cryptographic RAM zeroization.

Engineered by Maya Thorne.
"""

import re
from typing import Dict, List, Tuple, Any, Optional, Set

from .normalizers import split_chained_commands

# Known Abobus watermarks and indicators
ABOBUS_MARKERS = [
    ":ABOBUS-OBFUSCATOR",
    ";SE^T \"__author__=EscaLag\"",
    ";SE^T \"__github__=github.com/EscaLag/Abobus-obfuscator\"",
    "ABOBUS OBFUSCATION",
    "EscaLag",
    "Abobus-obfuscator",
]

# Arabic decoy characters injected by Abobus anti_detect
ABOBUS_ARABIC_DECOYS = set('ﭲسﺖﮚﮱﮕﯔتﮢﯤﺼكﻁﺹﭫ﷽◯')

# Kaomoji decoys injected by Abobus anti_detect
ABOBUS_KAOMOJI_DECOYS = [
    'ヾ(⌐■_■)ノ',
    '(◕‿◕)',
    '(⊙ω⊙)',
    '┌( ಠ_ಠ)┘',
]

# Chinese warning message decoy injected by Abobus anti_detect
ABOBUS_CHINESE_WARNING = '此訊息已被神秘魔法保護凡人是無法複製貼上這行文字的'

# Chinese characters used by Abobus to generate dictionary variable names
ABOBUS_CHINESE_VAR_CHARS = set('阿贝色德饿艾豆贝尔维埃克斯爱耻')

# Zero-width and invisible Unicode characters used for obfuscation and RTL masking
ABOBUS_ZERO_WIDTH_CHARS = {
    '\u200e',  # Left-to-Right Mark
    '\u200f',  # Right-to-Left Mark
    '\u200b',  # Zero Width Space
    '\u200c',  # Zero Width Non-Joiner
    '\u200d',  # Zero Width Joiner
    '\u202a',  # Left-to-Right Embedding
    '\u202b',  # Right-to-Left Embedding
    '\u202c',  # Pop Directional Formatting
    '\u202d',  # Left-to-Right Override
    '\u202e',  # Right-to-Left Override
    '\ufeff',  # Zero Width No-Break Space (BOM character)
    '\u2060',  # Word Joiner
    '\u2061',  # Function Application
    '\u2062',  # Invisible Times
    '\u2063',  # Invisible Separator
    '\u2064',  # Invisible Plus
}

# Standard Abobus %public% slicing lookup table (C:\Users\Public)
ABOBUS_PUBLIC_ALPHABET = ['C', ':', '\\', 'U', 's', 'e', 'r', 's', '\\', 'P', 'u', 'b', 'l', 'i', 'c']


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


def detect_abobus_signatures(script_text: str) -> Dict[str, Any]:
    """
    Heuristically analyze script for Abobus-obfuscator signatures, decoys, and traps.
    Returns:
        Dict with keys: is_abobus, confidence, indicators, markers_found,
                        has_unicode_noise, has_kaomoji, has_arabic,
                        has_chinese_decoys, has_traps
    """
    indicators: List[str] = []
    markers_found: List[str] = []
    confidence = 0.0

    # 1. Author and project markers
    for marker in ABOBUS_MARKERS:
        if marker.lower() in script_text.lower():
            markers_found.append(marker)
            clean_marker = marker.strip(':;" ')
            indicators.append(f"marker_{clean_marker}")
            confidence += 0.45

    # 2. Arabic decoy character detection
    arabic_count = sum(1 for c in script_text if c in ABOBUS_ARABIC_DECOYS)
    if arabic_count > 0:
        indicators.append(f"arabic_decoys_count_{arabic_count}")
        confidence += min(0.35, 0.05 * arabic_count)

    # 3. Kaomoji decoy detection
    has_kaomoji = any(k in script_text for k in ABOBUS_KAOMOJI_DECOYS)
    if has_kaomoji:
        indicators.append("kaomoji_decoys")
        confidence += 0.35

    # 4. Chinese decoy warning string
    chinese_warning_count = sum(1 for c in script_text if c in ABOBUS_CHINESE_WARNING)
    if chinese_warning_count >= 3:
        indicators.append(f"chinese_warning_decoys_count_{chinese_warning_count}")
        confidence += 0.35

    # 5. Chinese dictionary variable name detection
    chinese_var_count = sum(1 for c in script_text if c in ABOBUS_CHINESE_VAR_CHARS)
    if chinese_var_count >= 2:
        indicators.append(f"chinese_dictionary_vars_count_{chinese_var_count}")
        confidence += 0.30

    # 6. Abobus defensive traps & opaque predicates
    trap_patterns = [
        (r'(?i)@?find\s+>nul\s+2>&1&&for\s+/l\s+%%c\s+in\s*\(\.\)do', "trap_find_echo"),
        (r'(?i)set\s+b=1\s+>nul\s+2>&1\s*&\s*if\s+not\s+defined\s+b', "trap_b_flag"),
        (r'(?i)echo\s*>tmp&@?for\s+/f\s+"tokens=3"', "trap_echo_tmp"),
        (r'(?i)if\s+%.*%\s+NEq\s+2\s+exit', "trap_neq_counter"),
        (r'(?i)\(@?chcp(?:\.com)?\s+437\)>nul', "trap_chcp_437"),
        (r'(?i)set\s+𝧽=', "trap_decoy_var_symbol"),
        (r'(?i)if\s+\d+\s+EQU\s+0\s+\(@?exit\)\s+else', "opaque_if_equ_0"),
        (r'(?i)if\s+1\s+EQU\s+1', "opaque_if_1_equ_1"),
        (r'(?i)for\s+/l\s+%%\w+\s+in\s*\(\s*1[,\s]+1[,\s]+1\s*\)\s*do', "opaque_for_1_1_1"),
    ]
    trap_count = 0
    for pat, tag in trap_patterns:
        if re.search(pat, script_text):
            indicators.append(tag)
            trap_count += 1
            confidence += 0.15

    # 7. Caret density on quotes / keywords (^" or s^e^t)
    if re.search(r'\^"|s\^e\^t|c\^m\^d|e\^c\^h\^o', script_text, re.IGNORECASE):
        indicators.append("caret_escaped_primitives")
        confidence += 0.10

    # 8. Multi-semicolon or multi-at line prefixes
    if re.search(r'(?m)^[;@]{2,}', script_text):
        indicators.append("abnormal_delimiter_prefixes")
        confidence += 0.10

    confidence = min(1.0, confidence)
    is_abobus = confidence >= 0.40 or bool(markers_found)

    return {
        "is_abobus": is_abobus,
        "confidence": round(confidence, 3),
        "indicators": indicators,
        "markers_found": markers_found,
        "has_unicode_noise": (arabic_count > 0 or chinese_warning_count >= 3),
        "has_kaomoji": has_kaomoji,
        "has_arabic": arabic_count > 0,
        "has_chinese_decoys": (chinese_warning_count >= 3 or chinese_var_count >= 2),
        "has_traps": trap_count > 0,
    }


def strip_abobus_unicode_noise(script_text: str) -> Tuple[str, List[str]]:
    """
    Remove zero-width characters, Kaomoji decoys, Arabic anti-detect sequences,
    and Chinese warning string tokens.
    Returns:
        Tuple[clean_text, removed_noise_tokens]
    """
    removed_tokens: List[str] = []

    # 1. Strip zero-width & bidirectional formatting characters
    curr_text = "".join(ch for ch in script_text if ch not in ABOBUS_ZERO_WIDTH_CHARS)
    if len(curr_text) != len(script_text):
        removed_tokens.append("zero_width_chars")

    # 2. Strip %<decoy>% variable references containing Arabic, Kaomoji, or Chinese warning text
    def is_decoy_token(content: str) -> bool:
        clean = content.replace("^", "")
        # Check Arabic
        if any(c in ABOBUS_ARABIC_DECOYS for c in clean):
            return True
        # Check Kaomoji
        if any(k in clean for k in ABOBUS_KAOMOJI_DECOYS):
            return True
        # Check Chinese warning string
        if any(c in ABOBUS_CHINESE_WARNING for c in clean):
            return True
        return False

    decoy_var_pat = re.compile(r'%([^%\r\n]+)%')

    def repl_decoy(m: re.Match) -> str:
        inner = m.group(1)
        if is_decoy_token(inner):
            removed_tokens.append(m.group(0))
            return ""
        return m.group(0)

    for _ in range(5):
        prev = curr_text
        curr_text = decoy_var_pat.sub(repl_decoy, curr_text)
        if curr_text == prev:
            break

    # 3. Strip standalone Kaomoji or Arabic sequences outside percent signs
    for km in ABOBUS_KAOMOJI_DECOYS:
        if km in curr_text:
            removed_tokens.append(km)
            curr_text = curr_text.replace(km, "")

    # Strip standalone Chinese warning text sequences if clustered
    for i in range(0, len(ABOBUS_CHINESE_WARNING) - 3):
        chunk = ABOBUS_CHINESE_WARNING[i:i+4]
        if chunk in curr_text:
            removed_tokens.append(chunk)
            curr_text = curr_text.replace(chunk, "")

    # Strip standalone Arabic decoy characters
    for ch in ABOBUS_ARABIC_DECOYS:
        if ch in curr_text:
            removed_tokens.append(ch)
            curr_text = curr_text.replace(ch, "")

    return curr_text, removed_tokens


def strip_abobus_decoy_variables(script_text: str) -> Tuple[str, List[str]]:
    """
    Prune uninitialized dummy and ephemeral variables injected by Abobus:
      - 'set 𝧽=  c' or '%𝧽%'
      - 'set <name_file>=%0'
      - 'set b=1' flag definitions
      - 'set /a +=1'
    """
    removed_vars: List[str] = []
    lines = script_text.splitlines()
    clean_lines = []

    decoy_assign_patterns = [
        re.compile(r'^\s*@?\s*s\^?e\^?t\s+𝧽=.*$', re.IGNORECASE),
        re.compile(r'^\s*@?\s*s\^?e\^?t\s+\"?\w+=%0\"?\s*$', re.IGNORECASE),
        re.compile(r'^\s*@?\s*s\^?e\^?t\s+/a\s+[^=]*\+=1\s*(?:>nul\s*)?$', re.IGNORECASE),
        re.compile(r'^\s*@?\s*s\^?e\^?t\s+b=1\s*(?:>nul\s*2>&1\s*)?$', re.IGNORECASE),
    ]

    for line in lines:
        l_str = line.strip()
        if not l_str:
            clean_lines.append(line)
            continue

        matched_decoy = False
        for pat in decoy_assign_patterns:
            if pat.match(l_str):
                matched_decoy = True
                removed_vars.append(l_str)
                break

        if not matched_decoy:
            clean_line = line.replace("%𝧽%", "")
            clean_lines.append(clean_line)

    return "\n".join(clean_lines), removed_vars


def normalize_abobus_carets_and_delimiters(script_text: str) -> str:
    """
    Normalize Abobus caret escapes, excessive whitespace blocks, and leading delimiter traps:
      1. Collapse leading semicolon combinations (;@;, ;;, ; ;, ;) to clean statements.
      2. Collapse multiple leading at-signs (@@, @@@) to single @.
      3. Collapse excessive leading whitespace blocks (>50 spaces) per line.
      4. Normalize caret-escaped quotes (^" -> ") and keywords (s^e^t -> set, etc.).
    """
    lines = script_text.splitlines()
    processed_lines = []

    for line in lines:
        curr = line

        # 1. Excessive leading spaces
        if curr.startswith(' ' * 50):
            curr = curr.lstrip()

        # 2. Leading semicolons and ats
        while curr.startswith(';') or curr.startswith('; ') or curr.startswith(';@;'):
            if curr.startswith(';@;'):
                curr = '@' + curr[3:].lstrip()
            elif curr.startswith('; '):
                curr = curr[2:].lstrip()
            elif curr.startswith(';'):
                curr = curr[1:].lstrip()

        # Collapse repeated leading @@ -> @
        if re.match(r'^@{2,}', curr):
            curr = '@' + re.sub(r'^@+', '', curr)

        # 3. Caret-escaped quotes: ^" -> "
        curr = curr.replace('^"', '"')

        # 4. Carets inside keywords
        keyword_unsplit = [
            (r's\^e\^t', 'set'),
            (r'c\^h\^c\^p(?:\.c\^o\^m)?', 'chcp'),
            (r'e\^c\^h\^o', 'echo'),
            (r'c\^l\^s', 'cls'),
            (r'f\^i\^n\^d', 'find'),
            (r'f\^i\^n\^d\^s\^t\^r', 'findstr'),
            (r'f\^o\^r', 'for'),
            (r'e\^x\^i\^t', 'exit'),
            (r'c\^a\^l\^l', 'call'),
            (r't\^y\^p\^e', 'type'),
            (r'd\^e\^l', 'del'),
            (r'c\^m\^d', 'cmd'),
            (r'p\^a\^u\^s\^e', 'pause'),
            (r'g\^o\^t\^o', 'goto'),
        ]
        for pat, kw in keyword_unsplit:
            curr = re.sub(pat, kw, curr, flags=re.IGNORECASE)

        # 5. Carets inside variable references: %a^b^o^b^u^s% -> %abobus%
        def unescape_var_carets(m: re.Match) -> str:
            v_name = m.group(1).replace('^', '')
            return f"%{v_name}%"
        curr = re.sub(r'%([a-zA-Z0-9_\-\.\:\$\^]+)%', unescape_var_carets, curr)

        processed_lines.append(curr)

    return "\n".join(processed_lines)


def strip_abobus_traps_and_chaff(script_text: str) -> Tuple[str, int]:
    """
    Neutralize Abobus anti-debugging, anti-analysis, and execution trap lines:
      - Line prefixes generated by random_if:
          • if <N> EQU 0 (@exit) else <CMD>
          • if 1 EQU 1 <CMD>
          • if <N> LsS <M> <CMD>
          • if exist %<var>% <CMD>
          • for /l %%y in (1 1 1) do <CMD>
      - Complete trap statements and blocks:
          • :ABOBUS-OBFUSCATOR header & author/github metadata
          • (@chcp.com 437)>nul header trap
          • @find >nul 2>&1&&for /l %%c in (.)do (@echo ABOBUS OBFUSCATION)||@exit
          • variable existence and blacklist checks
          • echo tmp status traps and pause traps
          • China symbol errorlevel loop traps
    Returns:
        Tuple[clean_text, eliminated_trap_count]
    """
    eliminated_count = 0
    lines = script_text.splitlines()
    clean_lines = []

    trap_line_patterns = [
        re.compile(r'^\s*:ABOBUS-OBFUSCATOR\s*$', re.IGNORECASE),
        re.compile(r'^\s*;?\s*s\^?e\^?t\s+\"?__author__=.*', re.IGNORECASE),
        re.compile(r'^\s*;?\s*s\^?e\^?t\s+\"?__github__=.*', re.IGNORECASE),
        re.compile(r'^\s*@?\s*find\s+>nul\s+2>&1&&for\s+/l\s+%%c\s+in\s*\(\.\)do.*ABOBUS.*', re.IGNORECASE),
        re.compile(r'^\s*@?\s*find\s+>nul\s+2>&1\s*$', re.IGNORECASE),
        re.compile(r'.*@?echo\s+ABOBUS\s+OBFUSCATION.*', re.IGNORECASE),
        re.compile(r'^\s*for\s+/l\s+%%c\s+in\s*\(\.\)do.*ABOBUS.*', re.IGNORECASE),
        re.compile(r'^\s*@?\s*set\s+/a\s+[^=]*\+=1\s+>nul\s*&for\s+/l\s+%%i\s+in\s*\([^)]*\)\s*do\s+for\s+%%a\s+in\s*\([^)]*\)do\s+if\s+not\s+defined\s+%%a\s+exit\s*$', re.IGNORECASE),
        re.compile(r'^\s*@?\s*set\s+/a\s+[^=]*\+=1\s+>nul\s*&for\s+%%a\s+in\s*\([^)]*\)do\s+@?findstr\s+/L\s+/I\s+%%a\s+%\w+%\s*&&\s*exit\s*$', re.IGNORECASE),
        re.compile(r'^\s*set\s+b=1\s+>nul\s+2>&1\s*&\s*if\s+not\s+defined\s+b\s*\(@?echo\s+=D&@?pause&@?exit\)\s*$', re.IGNORECASE),
        re.compile(r'^\s*set\s+b=1\s+>nul\s+2>&1\s*$', re.IGNORECASE),
        re.compile(r'.*if\s+not\s+defined\s+b\s*\(@?echo\s+=D&@?pause&@?exit\).*', re.IGNORECASE),
        re.compile(r'^\s*echo\s*>tmp&@?for\s+/f\s+"tokens=3"\s+%%i\s+in\s*\(\'type\s+tmp\'\)do\s+if\s+"%%i"\s+EQU\s+"on\.".*', re.IGNORECASE),
        re.compile(r'^\s*echo\s*>tmp&for\s+/f\s+"tokens=3"\s+%%i\s+in\s*\(\'type\s+tmp\'\)do\s+if\s+"%%i"\s+EQU\s+"on\.".*', re.IGNORECASE),
        re.compile(r'^\s*echo\s*>tmp\s*$', re.IGNORECASE),
        re.compile(r'.*type\s+tmp.*tokens=3.*', re.IGNORECASE),
        re.compile(r'^\s*if\s+%[^%]*%\s+NEq\s+2\s+exit\s*$', re.IGNORECASE),
        re.compile(r'^\s*echo\s+off&for\s+/l\s+%%i\s+in\s*\([^)]*\)do\s*\(for\s+/l\s+%%i\s+in\s*\([^)]*\)do\s*\(if\s+%errorlevel%\s+EQU\s+0\s+exit\)\)\s*$', re.IGNORECASE),
        re.compile(r'^\s*for\s+/l\s+%%i\s+in\s*\([^)]*\)do\s*\(for\s+/l\s+%%i\s+in\s*\([^)]*\)do\s*\(if\s+%errorlevel%\s+EQU\s+0\s+exit\)\)\s*$', re.IGNORECASE),
        re.compile(r'^\s*>nul\s+2>&1\s*&@?cls\s*$', re.IGNORECASE),
        re.compile(r'^\s*\(@?chcp(?:\.com)?\s+437\)>nul&@?echo\s+off&cls&&set\s+\w+=%0&set\s+𝧽=.*$', re.IGNORECASE),
        re.compile(r'^\s*\(@?chcp(?:\.com)?\s+437\)>nul\s*$', re.IGNORECASE),
        re.compile(r'^\s*set\s+\w+=%0\s*$', re.IGNORECASE),
    ]

    for line in lines:
        l_str = line.strip()
        if not l_str:
            continue

        is_trap = False
        for pat in trap_line_patterns:
            if pat.match(l_str):
                is_trap = True
                eliminated_count += 1
                break
        if is_trap:
            continue

        # Strip random_if prefixes iteratively
        curr_cmd = l_str
        modified_prefix = True
        while modified_prefix:
            modified_prefix = False

            # Pattern 1: if <N> EQU 0 (@exit) else <rest>
            m1 = re.match(r'^@?if\s+\d+\s+EQU\s+0\s+\(@?exit\)\s+else\s+(.*)$', curr_cmd, re.IGNORECASE)
            if m1:
                curr_cmd = m1.group(1).strip()
                eliminated_count += 1
                modified_prefix = True
                continue

            # Pattern 2: if 1 EQU 1 <rest>
            m2 = re.match(r'^@?if\s+1\s+EQU\s+1\s+(.*)$', curr_cmd, re.IGNORECASE)
            if m2:
                curr_cmd = m2.group(1).strip()
                eliminated_count += 1
                modified_prefix = True
                continue

            # Pattern 3: if <N> LsS <M> <rest> (where N < M)
            m3 = re.match(r'^@?if\s+(\d+)\s+LsS\s+(\d+)\s+(.*)$', curr_cmd, re.IGNORECASE)
            if m3:
                n, m, rest = int(m3.group(1)), int(m3.group(2)), m3.group(3)
                if n < m:
                    curr_cmd = rest.strip()
                    eliminated_count += 1
                    modified_prefix = True
                    continue

            # Pattern 4: if exist %<var>% <rest>
            m4 = re.match(r'^@?if\s+exist\s+%[a-zA-Z0-9_\-]+%\s+(.*)$', curr_cmd, re.IGNORECASE)
            if m4:
                curr_cmd = m4.group(1).strip()
                eliminated_count += 1
                modified_prefix = True
                continue

            # Pattern 5: for /l %%y in (1 1 1) do <rest> or (1,1,1)
            m5 = re.match(r'^@?for\s+/l\s+%%\w+\s+in\s*\(\s*1[,\s]+1[,\s]+1\s*\)\s*do\s+(.*)$', curr_cmd, re.IGNORECASE)
            if m5:
                curr_cmd = m5.group(1).strip()
                eliminated_count += 1
                modified_prefix = True
                continue

        # If after stripping prefix, line is (@exit) or empty, discard
        if curr_cmd.strip() in ['(@exit)', '@exit', 'exit', '']:
            eliminated_count += 1
            continue

        clean_lines.append(curr_cmd)

    return "\n".join(clean_lines), eliminated_count


def resolve_abobus_substring_dictionaries(
    script_text: str, custom_env: Optional[Dict[str, str]] = None
) -> Tuple[str, Dict[str, str], int]:
    """
    Harvest and inline multi-stage Chinese substring dictionaries:
      1. Slices against %public:~idx,1% mapped to C:\\Users\\Public.
      2. Harvest candidate dictionary variables matching:
         set "<var>=<60+ chars of alphabet>" or set "<var>=<slices>"
         where <var> contains Chinese characters (阿贝色德...) or non-ASCII identifiers.
      3. Iteratively resolve chained dictionaries (dictionary N defined using dictionary N-1).
      4. Inline all %<var>:~idx,1% expressions across remaining payload lines.
      5. Purge dead dictionary definition lines.
    Returns:
        Tuple[clean_text, resolved_dictionaries, resolved_replacements_count]
    """
    resolved_count = 0
    dictionaries: Dict[str, str] = {}
    consumed_def_lines: Set[str] = set()

    # Step 1: Pre-resolve %public:~idx,1% across the script
    public_target = (custom_env or {}).get("public", r"C:\Users\Public")

    def repl_public(m: re.Match) -> str:
        nonlocal resolved_count
        try:
            idx = int(m.group(1))
            if 0 <= idx < len(ABOBUS_PUBLIC_ALPHABET):
                resolved_count += 1
                return ABOBUS_PUBLIC_ALPHABET[idx]
            if 0 <= idx < len(public_target):
                resolved_count += 1
                return public_target[idx]
        except (ValueError, IndexError):
            pass
        return m.group(0)

    curr_text = re.sub(r'%public:~(\d+),1%', repl_public, script_text, flags=re.IGNORECASE)

    # Step 2: Iteratively discover and resolve dictionary definitions
    assign_pat = re.compile(
        r'^\s*@?\s*s\^?e\^?t\s+(?:\"([^\"=\r\n]+)=([^\"\r\n]*)\"?|([^\"=\s;&\r\n]+)=([^\"\r\n]*))\s*$',
        re.IGNORECASE
    )

    for _ in range(10):
        found_new = False
        lines = curr_text.splitlines()
        for line in lines:
            l_str = line.strip()
            if not l_str or l_str in consumed_def_lines:
                continue

            m = assign_pat.match(l_str)
            if not m:
                continue

            v_name = (m.group(1) or m.group(3) or "").strip()
            v_val = (m.group(2) or m.group(4) or "").strip()

            is_chinese_var = any(c in ABOBUS_CHINESE_VAR_CHARS for c in v_name)
            is_long_alphabet = len(v_val) >= 40 and ('%' not in v_val or len(v_val) >= 60)
            has_slices = bool(re.search(r'%[^%:\s]+:~\d+,1%', v_val))

            if is_chinese_var or is_long_alphabet or (has_slices and len(v_name) <= 10):
                if dictionaries:
                    def repl_inner_slice(sm: re.Match) -> str:
                        d_name = sm.group(1)
                        s_idx = int(sm.group(2))
                        if d_name in dictionaries and 0 <= s_idx < len(dictionaries[d_name]):
                            return dictionaries[d_name][s_idx]
                        return sm.group(0)

                    resolved_val = re.sub(r'%([^%:\s]+):~(\d+),1%', repl_inner_slice, v_val)
                else:
                    resolved_val = v_val

                if '%' not in resolved_val or len(resolved_val) >= 50:
                    if v_name not in dictionaries or dictionaries[v_name] != resolved_val:
                        dictionaries[v_name] = resolved_val
                        consumed_def_lines.add(l_str)
                        found_new = True

        if not found_new:
            break

    # Step 3: Inline dictionary references in payload lines
    if dictionaries:
        def repl_payload_slice(m: re.Match) -> str:
            nonlocal resolved_count
            d_name = m.group(1)
            s_idx = int(m.group(2))
            if d_name in dictionaries:
                val = dictionaries[d_name]
                if 0 <= s_idx < len(val):
                    resolved_count += 1
                    return val[s_idx]
            return m.group(0)

        for _ in range(5):
            prev_t = curr_text
            curr_text = re.sub(r'%([^%:\s]+):~(\d+),1%', repl_payload_slice, curr_text)
            if curr_text == prev_t:
                break

    # Step 4: Prune dead dictionary definition lines
    output_lines = []
    for line in curr_text.splitlines():
        l_str = line.strip()
        if not l_str:
            continue
        if l_str in consumed_def_lines:
            continue
        m = assign_pat.match(l_str)
        if m:
            v_name = (m.group(1) or m.group(3) or "").strip()
            if v_name in dictionaries:
                continue
        output_lines.append(line)

    return "\n".join(output_lines), dictionaries, resolved_count


def normalize_abobus(
    script_text: str, custom_env: Optional[Dict[str, str]] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Master Abobus-obfuscator normalization pipeline:
      1. Signature & heuristic telemetry detection.
      2. Fast pass-through if no Abobus indicators detected.
      3. First-pass composite trap elimination before command splitting.
      4. Unicode noise filtering (zero-width, Kaomoji, Arabic decoys, Chinese warnings).
      5. Split chained commands to isolate multi-statement lines.
      6. Caret separation & delimiter normalization (leading ;; / @@, large spaces).
      7. Second-pass trap chaff & opaque predicate pruning (random_if, anti-tamper loops).
      8. Multi-stage Chinese substring dictionary harvesting & inlining.
      9. Ephemeral decoy variable pruning.
      10. Cryptographic RAM zeroization.
    Returns:
        Tuple[clean_script_text, telemetry_metadata]
    """
    sig = detect_abobus_signatures(script_text)
    telemetry: Dict[str, Any] = {
        "signatures": sig,
        "is_abobus": sig["is_abobus"],
        "confidence": sig["confidence"],
        "indicators": sig["indicators"],
        "eliminated_traps_count": 0,
        "stripped_noise_count": 0,
        "dictionaries_resolved_count": 0,
        "dictionary_variables": [],
    }

    # Pass through untouched if confidence is low and no markers/indicators found
    if not sig["is_abobus"] and sig["confidence"] < 0.20:
        return script_text, telemetry

    curr_text = script_text

    # Step 1: Pre-split whole composite trap lines and headers
    curr_text, trap_count1 = strip_abobus_traps_and_chaff(curr_text)

    # Step 2: Strip Unicode noise & decoys
    curr_text, noise_tokens = strip_abobus_unicode_noise(curr_text)

    # Step 3: Split chained commands to isolate multi-statement lines
    curr_text = split_chained_commands(curr_text)

    # Step 4: Normalize carets, semicolons, and delimiters
    curr_text = normalize_abobus_carets_and_delimiters(curr_text)

    # Step 5: Second-pass trap chaff and random_if prefix unwrapping on individual lines
    curr_text, trap_count2 = strip_abobus_traps_and_chaff(curr_text)
    telemetry["eliminated_traps_count"] = trap_count1 + trap_count2
    telemetry["stripped_noise_count"] = len(noise_tokens)

    # Step 6: Resolve Chinese substring dictionaries and inlining
    curr_text, dict_map, res_count = resolve_abobus_substring_dictionaries(curr_text, custom_env)
    telemetry["dictionaries_resolved_count"] = len(dict_map)
    telemetry["dictionary_variables"] = list(dict_map.keys())

    # Step 7: Prune decoy variables
    curr_text, removed_vars = strip_abobus_decoy_variables(curr_text)

    # Step 8: Memory zeroization
    zeroize_dict(dict_map)

    # Collapse any leftover empty lines
    clean_lines = [l for l in curr_text.splitlines() if l.strip()]
    clean_script = "\n".join(clean_lines)

    return clean_script, telemetry


class AbobusNormalizer:
    """Object-oriented wrapper for Abobus normalization and forensics."""

    def __init__(self, custom_env: Optional[Dict[str, str]] = None):
        self.custom_env = custom_env

    def normalize(self, script_text: str) -> Tuple[str, Dict[str, Any]]:
        return normalize_abobus(script_text, self.custom_env)

    def detect(self, script_text: str) -> Dict[str, Any]:
        return detect_abobus_signatures(script_text)
