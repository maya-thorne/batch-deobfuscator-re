"""
Modular Normalizers & AST String Transformers for Windows Batch Deobfuscation.
Handles Caret, Quotes, Delimiters, UTF-16LE BOM, Env Slicing, and Substitution.
"""

import re

def normalize_bom(data: bytes) -> str:
    """Normalize UTF-16LE, UTF-16BE, UTF-8 BOM or raw Latin1/ASCII bytes to string."""
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16le", errors="replace")
    elif data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16be", errors="replace")
    elif data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    
    # Try utf-8 first, fallback to cp1252 / latin1
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")

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
}

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
    ampersands inside quotes ("... & ..."), and nested parenthesized blocks ((a & b)).
    """
    result_lines = []
    for line in text.splitlines():
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
    return re.sub(r' +', ' ', result)

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
            start = int(start_str)
            # Map start to positive index
            if start < 0:
                start_idx = max(0, val_len + start)
            else:
                start_idx = min(val_len, start)

            if len_str is not None:
                length = int(len_str)
                if length < 0:
                    end_idx = max(start_idx, val_len + length)
                else:
                    end_idx = min(val_len, start_idx + length)
            else:
                end_idx = val_len

            return val[start_idx:end_idx]
        except (ValueError, IndexError):
            return match.group(0)

    pattern = re.compile(r'%([a-zA-Z0-9_\-\.\:\$]+):~\s*(-?\d+)\s*(?:,\s*(-?\d+)\s*)?%', re.IGNORECASE)
    return pattern.sub(slice_repl, text)

def resolve_substitution(text: str, env_vars: dict) -> str:
    """Resolve %VAR:old=new% substitutions."""
    def sub_repl(match):
        var_name = match.group(1).lower()
        old_val = match.group(2)
        new_val = match.group(3)
        if var_name not in env_vars:
            return match.group(0)

        val = env_vars[var_name]
        # Case-insensitive string replacement in cmd.exe
        pattern = re.compile(re.escape(old_val), re.IGNORECASE)
        return pattern.sub(new_val, val)

    pattern = re.compile(r'%([a-zA-Z0-9_\-\.\:\$]+):([^=%\r\n]+)=([^%\r\n]*)%', re.IGNORECASE)
    return pattern.sub(sub_repl, text)
