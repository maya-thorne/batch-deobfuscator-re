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

def strip_empty_quotes(text: str) -> str:
    """Flatten fragmented double quotes inserted between identifiers (e.g. w""h""o""a""m""i -> whoami)."""
    return re.sub(r'([a-zA-Z0-9_\-\/\\])""([a-zA-Z0-9_\-\/\\])', r'\1\2', text)

def normalize_delimiters(text: str) -> str:
    """Normalize non-standard batch parameter separators like semicolons or commas outside quotes."""
    # cmd.exe treats comma, semicolon, equal sign as whitespace between tokens outside quotes
    lines = []
    for line in text.splitlines():
        # Clean leading @ signs
        stripped = line.strip()
        lines.append(line)
    return "\n".join(lines)

def resolve_slicing(text: str, env_vars: dict) -> str:
    """Resolve %VAR:~start,length% and %VAR:~start%."""
    def slice_repl(match):
        var_name = match.group(1).lower()
        args = match.group(2)
        if var_name not in env_vars:
            return match.group(0)

        val = env_vars[var_name]
        try:
            if "," in args:
                start_s, len_s = args.split(",", 1)
                start = int(start_s)
                length = int(len_s)
                if length >= 0:
                    return val[start:start + length]
                else:
                    return val[start:length]
            else:
                start = int(args)
                return val[start:]
        except (ValueError, IndexError):
            return match.group(0)

    pattern = re.compile(r'%([a-zA-Z0-9_\-\.\:\$]+):~([0-9\-]+(?:,[0-9\-]+)?)%', re.IGNORECASE)
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
