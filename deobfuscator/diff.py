"""
Terminal Unified Diff Generator for Obfuscated vs Deobfuscated Scripts.
"""

import difflib

def generate_unified_diff(original: str, deobfuscated: str, filename: str = "script.bat", use_color: bool = True) -> str:
    """Generate a clean unified diff highlighting deobfuscation transformations."""
    orig_lines = original.splitlines(keepends=True)
    deobf_lines = deobfuscated.splitlines(keepends=True)

    diff = list(difflib.unified_diff(
        orig_lines,
        deobf_lines,
        fromfile=f"a/{filename} (obfuscated)",
        tofile=f"b/{filename} (deobfuscated)",
        n=3
    ))

    if not diff:
        return "No differences detected (script already clean)."

    if not use_color:
        return "".join(diff)

    # ANSI Colors
    RED = "\033[91m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

    colored_lines = []
    for line in diff:
        if line.startswith("---") or line.startswith("+++"):
            colored_lines.append(f"{BOLD}{line}{RESET}")
        elif line.startswith("@@"):
            colored_lines.append(f"{CYAN}{line}{RESET}")
        elif line.startswith("-"):
            colored_lines.append(f"{RED}{line}{RESET}")
        elif line.startswith("+"):
            colored_lines.append(f"{GREEN}{line}{RESET}")
        else:
            colored_lines.append(line)

    return "".join(colored_lines)
