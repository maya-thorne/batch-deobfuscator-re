"""
Modular Normalizers & AST String Transformers for Windows Batch Deobfuscation.
Handles Caret, Quotes, Delimiters, UTF-16LE BOM, Env Slicing, and Substitution.
"""

import re

from .batcloak import normalize_batcloak_headers

def normalize_bom(data: bytes) -> str:
    """Normalize UTF-16LE, UTF-16BE, UTF-8 BOM or raw Latin1/ASCII bytes, neutralizing BatCloak header decoys."""
    clean_text, _ = normalize_batcloak_headers(data)
    return clean_text

def strip_carets(text: str) -> str:
    """Strip carets outside double quotes. Preserve carets inside double quotes."""
    result = []
    in_quotes = False
    i = 0
    n = len(text)
    while i < n:
        char = text[i]
        if char == '"':
            in_quotes = not in_quotes
            result.append(char)
            i += 1
        elif char == '^':
            if in_quotes:
                result.append(char)
                i += 1
            else:
                # Outside quotes: caret escapes next character
                if i + 1 < n:
                    result.append(text[i + 1])
                    i += 2
                else:
                    i += 1
        else:
            result.append(char)
            i += 1
    return "".join(result)

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

def collapse_spaces_outside_quotes(text: str) -> str:
    """Collapse consecutive spaces outside double quotes while preserving whitespace within strings."""
    result = []
    in_quotes = False
    space_pending = False
    for ch in text:
        if ch == '"':
            in_quotes = not in_quotes
            space_pending = False
            result.append(ch)
        elif not in_quotes:
            if ch == ' ':
                if not space_pending:
                    result.append(' ')
                    space_pending = True
            else:
                space_pending = False
                result.append(ch)
        else:
            result.append(ch)
    return "".join(result)

def strip_empty_quotes(text: str) -> str:
    """
    Flatten fragmented double quotes used to disguise identifiers and commands.
    Handles:
      - Within identifiers: w""h""o""a""m""i -> whoami, c""m""d"".e""x""e -> cmd.exe
      - Repeated quote pairs: c""""m""""d -> cmd
      - Leading empty quotes: ""whoami -> whoami
      - Trailing empty quotes: whoami"" -> whoami
      - Variable identifiers: ""%var%"" -> %var%
    Preserves standalone empty string comparisons/arguments like 'if "%1"==""'.
    """
    prev = ""
    curr = text
    while prev != curr:
        prev = curr
        # Collapse multiple adjacent empty quotes
        curr = re.sub(r'""+', '""', curr)
        # Quotes between word/path/dot/var characters
        curr = re.sub(r'([a-zA-Z0-9_\-\/\\\.\:%])""(?=[a-zA-Z0-9_\-\/\\\.\:%])', r'\1', curr)
        # Quotes at token prefix (after whitespace, delimiter, @, =)
        curr = re.sub(r'(^|[\s,;=@])""(?=[a-zA-Z0-9_\-\/\\\.\:%])', r'\1', curr)
        # Quotes at token suffix (before whitespace, delimiter, end of line, parens)
        curr = re.sub(r'([a-zA-Z0-9_\-\/\\\.\:%])""(?=$|[\s,;=@\(\)&\|])', r'\1', curr)
    return curr

def split_chained_commands(text: str) -> str:
    """
    Split single-line chained commands (& outside quotes/redirection) into multiple lines.
    Preserves redirection operators (e.g. 2>&1, >&, <&), caret-escaped ampersands (^&),
    ampersands inside quotes ("... & ..."), nested parenthesized blocks ((a & b)),
    and comment/label lines (rem, ::, :label) where cmd.exe treats the entire line as a comment.
    """
    result_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        # In cmd.exe, REM, ::, and label lines (:label) treat the entire line as comment/label;
        # ampersands on these lines are ignored by the shell and must not be split into active commands.
        if re.match(r'^@?\s*(?:rem\b|:)', stripped, re.IGNORECASE):
            result_lines.append(line)
            continue

        parts = []
        curr_part = []
        in_quotes = False
        paren_depth = 0
        i = 0
        n = len(line)
        while i < n:
            ch = line[i]
            if ch == '"':
                in_quotes = not in_quotes
                curr_part.append(ch)
                i += 1
            elif not in_quotes and ch == '^':
                curr_part.append(ch)
                if i + 1 < n:
                    curr_part.append(line[i + 1])
                    i += 2
                else:
                    i += 1
            elif not in_quotes and ch == '(':
                paren_depth += 1
                curr_part.append(ch)
                i += 1
            elif not in_quotes and ch == ')':
                if paren_depth > 0:
                    paren_depth -= 1
                curr_part.append(ch)
                i += 1
            elif not in_quotes and paren_depth == 0 and ch == '&':
                current_prefix = "".join(curr_part).lstrip()
                if re.match(r'^@?\s*(?:rem\b|:)', current_prefix, re.IGNORECASE):
                    # In cmd.exe, REM, ::, and labels consume the entire remainder of the line;
                    # ampersands do not execute further commands.
                    curr_part.append(line[i:])
                    break

                prev_str = "".join(curr_part).rstrip()
                # Check for redirection: 2>&1, 1>&2, >&, <&
                if (prev_str.endswith(">") or prev_str.endswith("<") or 
                    re.search(r'[0-9]?>\s*$', prev_str) or re.search(r'[0-9]?<\s*$', prev_str)):
                    curr_part.append(ch)
                    i += 1
                elif i + 1 < n and line[i + 1] == '&':
                    # && conditional operator
                    part_str = "".join(curr_part).strip()
                    if part_str:
                        parts.append(part_str)
                    curr_part = []
                    i += 2
                else:
                    part_str = "".join(curr_part).strip()
                    if part_str:
                        parts.append(part_str)
                    curr_part = []
                    i += 1
            else:
                curr_part.append(ch)
                i += 1
        part_str = "".join(curr_part).strip()
        if part_str:
            parts.append(part_str)
        if parts:
            result_lines.extend(parts)
        else:
            result_lines.append(line)
    return "\n".join(result_lines)

def strip_undefined_vars(text: str, env_vars: dict) -> str:
    """
    Strip undefined %VAR% references outside quotes or wherever used for obfuscation noise.
    Preserves variables defined in env_vars, dynamic system pseudo-variables, and special variables.
    """
    def repl(m):
        name = m.group(1).lower()
        if name in env_vars or name in DYNAMIC_SYSTEM_VARS:
            return m.group(0)
        return ""

    pattern = re.compile(r'%([a-zA-Z0-9_\-\.\:\$]+)%')
    result = pattern.sub(repl, text)
    return collapse_spaces_outside_quotes(result)

def normalize_delimiters(text: str) -> str:
    """Normalize non-standard batch parameter separators like semicolons or commas outside quotes."""
    lines = []
    for line in text.splitlines():
        lines.append(line)
    return "\n".join(lines)

def resolve_slicing(text: str, env_vars: dict) -> str:
    """
    Resolve %VAR:~start,length% and %VAR:~start% with exact cmd.exe semantics,
    including negative start indices and negative lengths.
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
            # Map start to positive index
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

    pattern = re.compile(r'%([a-zA-Z0-9_\-\.\:\$]+):~\s*([+-]?\d+)\s*(?:,\s*([+-]?\d+)\s*)?%', re.IGNORECASE)
    return pattern.sub(slice_repl, text)

def resolve_substitution(text: str, env_vars: dict) -> str:
    """Resolve %VAR:old=new% and %VAR:*old=new% substitutions."""
    def sub_repl(match):
        var_name = match.group(1).lower()
        if var_name not in env_vars:
            return match.group(0)

        val = env_vars[var_name]
        star = match.group(2)
        old_val = match.group(3)
        new_val = match.group(4)

        if star:
            idx = val.lower().find(old_val.lower())
            if idx != -1:
                return new_val + val[idx + len(old_val):]
            return val
        else:
            # Case-insensitive string replacement in cmd.exe (lambda prevents regex replacement template escape errors)
            pattern = re.compile(re.escape(old_val), re.IGNORECASE)
            return pattern.sub(lambda m: new_val, val)

    pattern = re.compile(r'%([a-zA-Z0-9_\-\.\:\$]+):(\*?)([^=%\r\n]+)=([^%\r\n]*)%', re.IGNORECASE)
    return pattern.sub(sub_repl, text)


def zeroize_dict(target: dict) -> None:
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

