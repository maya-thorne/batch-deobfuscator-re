import re
import os
import argparse
import string
import math # For potential eval context
from pathlib import Path
from typing import List, Dict, Optional, Any, Union

# --- Constants and Known Patterns ---

VERBOSE = False

# Environment variables used by ran2 and obf_oneline.obfuscate_normal
ENV_VAR_VALUES = {
    "PUBLIC": r"C:\Users\Public",
    "COMMONPROGRAMFILES(X86)": r"C:\Program Files (x86)\Common Files",
    "PROGRAMFILES": r"C:\Program Files",
    "PROGRAMFILES(X86)": r"C:\Program Files (x86)",
    "DRIVERDATA": r"C:\Windows\System32\Drivers\DriverData",
    "COMMONPROGRAMFILES": r"C:\Program Files\Common Files",
    "COMMONPROGRAMW6432": r"C:\Program Files\Common Files",
    "USERPROFILE": os.environ.get("USERPROFILE", "C:\\Users\\Default"),
    "TEMP": os.environ.get("TEMP", "C:\\Users\\Default\\AppData\\Local\\Temp"),
    "TMP": os.environ.get("TMP", "C:\\Users\\Default\\AppData\\Local\\Temp"),
    "LOCALAPPDATA": os.environ.get("LOCALAPPDATA", "C:\\Users\\Default\\AppData\\Local"),
    "APPDATA": os.environ.get("APPDATA", "C:\\Users\\Default\\AppData\\Roaming"),
    "OS": "Windows_NT",
    "SYSTEMDRIVE": os.environ.get("SYSTEMDRIVE", "C:"),
    "SESSIONNAME": "Console", # Added by obfuscator if double_click_check=True
    # Add others if found necessary
}

# Regex to find the KDOT variable assignment
RE_KDOT = re.compile(r"^\s*set\s+KDOT=([a-zA-Z0-9]+)", re.IGNORECASE)

# Regex to find Caesar cipher definitions (assuming single letters)
RE_CAESAR_DEF = re.compile(r"^\s*set\s+([a-z])=([a-z])", re.IGNORECASE)

# Regex for character obfuscation patterns
# 1. Environment Variable Slicing (Handles random spaces before '1')
RE_ENV_SLICE = re.compile(r"%(\w+):~(-?\d+),(?:\s*)1%", re.IGNORECASE)
# 2. KDOT Slicing (Handles random spaces before '1')
RE_KDOT_SLICE = re.compile(r"%KDOT:~(-?\d+),(?:\s*)1%", re.IGNORECASE)
# 3. Caesar Cipher + Optional Junk Variable
RE_CAESAR_JUNK = re.compile(r"%([a-z])(1?)%(?:%[a-zA-Z0-9]+%)?", re.IGNORECASE)
# 4. Simple Junk Wrapping (Applied last)
RE_SIMPLE_JUNK = re.compile(r"%[a-zA-Z0-9]+%(.)%[a-zA-Z0-9]+%")
# Combined regex for first pass of character deobfuscation
RE_COMBINED_SPECIFIC_CHAR_OBF = re.compile(
    f"({RE_ENV_SLICE.pattern})|({RE_KDOT_SLICE.pattern})|({RE_CAESAR_JUNK.pattern})",
     re.IGNORECASE
)

# --- Scrambler Related Regex ---
# Regex for Scrambler jump setup block in main code (captures math expression)
RE_SCRAMBLE_JUMP = re.compile(
    # Matches "set /a ans = MATH_EXPRESSION"
    r"^\s*set\s+/a\s+ans\s*=\s*(.*?)\s*\n"
    # Matches "goto %ans%" (case-insensitive)
    r"\s*goto\s+%ans%\s*\n"
     # Matches the return label ":NUMBER"
    r"\s*:(\d+)\s*$",
    re.IGNORECASE | re.MULTILINE
)

# Regex for parsing scrambled blocks at the end
RE_SCRAMBLED_BLOCK = re.compile(
    # Matches the target label ":NUMBER"
    r"^:(\d+)\s*\n"
    # Non-greedily capture everything until the return logic starts.
    # This group (2) contains the original code plus potentially injected anti-methods/deadcode.
    r"([\s\S]*?)\n"
    # Matches the return logic: set /a ans = ..., goto %ans%
    # We don't need to capture this part, just ensure it exists.
    r"\s*set\s+/a\s+ans=[\s\S]*?\n"
    r"\s*goto\s+%ans%\s*$",
    re.IGNORECASE | re.MULTILINE
)


# Regex for Lines/Blocks to Remove (Applied *AFTER* Character Deobfuscation)
# These patterns match the DEOBFUSCATED forms of the junk/anti-method/dead code.
RE_JUNK_TO_REMOVE = [
    # --- Static Obfuscator Lines ---
    re.compile(r"^\s*::Made by K\.Dot using SomalifuscatorV2", re.IGNORECASE),
    re.compile(r"^\s*chcp 65001 > nul", re.IGNORECASE),
    re.compile(r"^\s*set\s+[a-z]=[a-z]", re.IGNORECASE), # Base Caesar defs
    re.compile(r"^\s*>nul 2>&1 && exit >nul 2>&1 \|\| cls", re.IGNORECASE), # Initial check line
    re.compile(r"^\s*(goto\s+:eof|exit\s*/b\s*0)\s*$", re.IGNORECASE), # Remove scrambler's goto EOF

    # --- AntiConsole VBS Block ---
    re.compile(r'^\s*if defined redo goto :KDOTUP', re.IGNORECASE),
    re.compile(r'^\s*set "redo=1"', re.IGNORECASE),
    re.compile(r'^\s*echo CreateObject\("Wscript\.Shell"\)\.Run "%~f0", 0, True > temp\.vbs', re.IGNORECASE),
    re.compile(r'^\s*cscript //nologo temp\.vbs', re.IGNORECASE),
    re.compile(r'^\s*del temp\.vbs', re.IGNORECASE),
    re.compile(r'^\s*:KDOTUP', re.IGNORECASE),

    # --- AntiChanges Checks (Deobfuscated) ---
    re.compile(r'^\s*echo @echo off >> kdot\w+\.bat', re.IGNORECASE), # first_line_echo_check start
    re.compile(r'^\s*call kdot\w+\.bat', re.IGNORECASE), # first_line_echo_check end (added)
    re.compile(r'^\s*echo %cmdcmdline% \| find /i "%~f0">nul \|\| exit /b 1', re.IGNORECASE), # double_click_check
    re.compile(r'^\s*echo %logonserver% \| findstr /i "DADDYSERVER" >nul && exit', re.IGNORECASE), # anti_triage
    re.compile(r'^\s*ping .* www\.google\.com .* \|\| exit', re.IGNORECASE), # anti_wifi
    # VM Checks (common patterns)
    re.compile(r'^\s*for /f "tokens=2 delims==" %%a in \(\'wmic computersystem get manufacturer /value\'\) do set manufacturer=%%a', re.IGNORECASE),
    re.compile(r'^\s*if "%manufacturer%"=="Microsoft Corporation" if "%model%"=="Virtual Machine" exit', re.IGNORECASE),
    re.compile(r'^\s*if "%manufacturer%"=="VMware, Inc\." exit', re.IGNORECASE),
    re.compile(r'^\s*if "%model%"=="VirtualBox" exit', re.IGNORECASE),
    re.compile(r'^\s*powershell.*Get-WmiObject Win32_ComputerSystem.*Virtual.*taskkill', re.IGNORECASE),
    re.compile(r'^\s*powershell.*gcim Win32_PhysicalMemory.*sum /1gb -lt 4.*taskkill', re.IGNORECASE), # RAM check
    # Generic PowerShell/WMIC Calls (catch-alls for other checks)
    re.compile(r'^\s*powershell(\.exe)?\s+(-NoLogo|-NoP|-NonI|-W Hidden|-EP Bypass|-EncodedCommand|-Command)\s+', re.IGNORECASE),
    re.compile(r'^\s*wmic\s+', re.IGNORECASE), # Catch generic WMIC calls if specific checks missed

    # --- DeadCode Injections (Deobfuscated) ---
    re.compile(r'^\s*doskey\s+\w+=.*', re.IGNORECASE), # doskey alias=command
    # Simple dead commands
    re.compile(r'^\s*mshta\s*$', re.IGNORECASE),
    re.compile(r'^\s*timeout \d+ >nul\s*$', re.IGNORECASE), # Matches timeout 0 >nul or timeout N >nul
    re.compile(r'^\s*echo %random% >nul\s*$', re.IGNORECASE),
    re.compile(r'^\s*rundll32\s*$', re.IGNORECASE), # Basic rundll32 call likely dead
    re.compile(r'^\s*cd %cd%\s*$', re.IGNORECASE),
    re.compile(r'^\s*wscript /b\s*$', re.IGNORECASE),
    re.compile(r'^\s*doskey /listsize=0\s*$', re.IGNORECASE),
    re.compile(r'^\s*powershell(\.exe)?\s+(-nop)?\s+(-c)?\s+"Write-Host -NoNewLine \$null"\s*$', re.IGNORECASE), # Specific dead PS
    # Dead for /l loop (that runs once) - Captures the whole line
    re.compile(r'^\s*for /l %%\w in \(\d+, \d+, \d+\) do \(.*\)', re.IGNORECASE),
    # Dead if statements (matching common structures) - These are harder to catch perfectly but target common forms
    re.compile(r'^\s*if %random% equ \d+ \(.*\) else \(.*\)', re.IGNORECASE),
    re.compile(r'^\s*if not 0 neq 0 \(.*\) else \(.*\)', re.IGNORECASE),
    re.compile(r'^\s*if exist C:\\Windows\\System32 \(.*\) else \(.*\)', re.IGNORECASE), # Usually true branch runs
    re.compile(r'^\s*if not %cd% == %cd% \(.*\) else \(.*\)', re.IGNORECASE), # Usually true branch runs (else)
    re.compile(r'^\s*if 0 equ 0 \(.*\) else \(.*\)', re.IGNORECASE), # Usually true branch runs
    re.compile(r'^\s*if exist C:\\Windows\\System3\s*\(.*\) else \(.*\)', re.IGNORECASE), # Usually true branch runs (else) - added optional space check
    re.compile(r'^\s*if %cd% == %cd% \(.*\) else \(.*\)', re.IGNORECASE), # Usually true branch runs
    re.compile(r'^\s*if chcp leq 1 \(.*\) else \(.*\)', re.IGNORECASE),
    re.compile(r'^\s*if %CD% == %__CD__% \(.*\) else \(.*\)', re.IGNORECASE), # Needs __CD__ check which isn't standard
    # Dead "better_kill" calls (match pattern, ignore specific bad word)
    re.compile(r'^\s*call \w+\.(exe|dll)\s*(>nul)?\s*(2>nul)?', re.IGNORECASE), # Made redirection optional
    re.compile(r'^\s*echo \w+\.(exe|dll)\s*(>nul)?\s*(2>nul)?', re.IGNORECASE), # Made redirection optional
    re.compile(r'^\s*forfiles /p %cd% /m \w+\.(exe|dll) /c \'cmd /c start @file\'\s*(>nul)?\s*(2>nul)?', re.IGNORECASE), # Made redirection optional

    # --- General Junk/Placeholders ---
    # Caesar `for /l` wrapper for simple set commands (already caught by the dead for /l above, keep commented for reference)
    # re.compile(r'^\s*for /l %%\w in \(\d+, \d+, \d+\) do \( set \w+=\w+ \)', re.IGNORECASE),
    re.compile(r"^\s*rem ANTICHANGES MARKER", re.IGNORECASE), # Example placeholders
    re.compile(r"^\s*rem DEADCODE MARKER", re.IGNORECASE),   # Example placeholders
]


# --- Helper Functions ---

def log_verbose(*args):
    """Prints only if VERBOSE flag is set."""
    if VERBOSE:
        print("VERBOSE:", *args)

def safe_eval_batch_math(expression: str) -> Optional[int]:
    """
    Enhanced evaluator for Batch 'set /a' math expressions.
    Attempts to handle Batch operators and number formats. Limited safety.
    """
    original_expression = expression
    expression = expression.strip()
    if not expression: return None

    log_verbose(f"Attempting to evaluate math: {original_expression}")

    # Replace Batch operators with Python equivalents BEFORE parsing numbers
    # Handle potential spaces around operators
    expression = re.sub(r'\s*\^\^\s*', '^', expression) # Batch XOR ^^ -> Python XOR ^
    expression = re.sub(r'\s*-\s*', '-', expression)
    expression = re.sub(r'\s*\+\s*', '+', expression)
    expression = re.sub(r'\s*\*\s*', '*', expression)
    expression = re.sub(r'\s*/\s*', '//', expression) # Batch / -> Python integer division //
    expression = re.sub(r'\s*%\s*', '%', expression) # Modulo
    expression = re.sub(r'\s*<<\s*', '<<', expression) # Left shift
    expression = re.sub(r'\s*>>\s*', '>>', expression) # Right shift
    expression = re.sub(r'\s*&\s*', '&', expression)   # Bitwise AND
    expression = re.sub(r'\s*\|\s*', '|', expression)  # Bitwise OR
    # Batch NOT `~` needs careful handling. Python `~` acts differently on negative numbers.
    # We will try letting eval handle it directly on numbers.

    # Use a restricted eval context
    safe_globals = {"__builtins__": None}
    safe_locals = {} # No external variables allowed

    processed_expr = expression # Start with the operator-replaced string

    try:
        # Let eval handle number parsing (0x..., 0..., decimal) and operators
        result = eval(processed_expr, safe_globals, safe_locals)
        log_verbose(f"Evaluated '{original_expression}' (Python='{processed_expr}') to: {result}")
        # Ensure result is integer
        return int(result)
    except OverflowError:
         # Handle potential overflow if numbers get extremely large
         print(f"Warning: Math evaluation resulted in overflow for '{original_expression}'")
         return None # Indicate failure
    except (SyntaxError, TypeError, NameError, ValueError, Exception) as e:
        # Catch a wider range of eval errors
        print(f"Warning: Could not evaluate math expression '{original_expression}' (Processed='{processed_expr}'): {type(e).__name__} - {e}")
        return None

# --- Deobfuscation Core Functions ---

def read_and_preprocess(file_path: Path) -> Optional[List[str]]:
    """Reads the file, handles BOM and encoding."""
    try:
        content_bytes = file_path.read_bytes()
    except IOError as e:
        print(f"Error reading file {file_path}: {e}")
        return None

    if content_bytes.startswith(b'\xff\xfe'):
        log_verbose("Detected UTF-16 LE BOM.")
        enc = 'utf-16le'
        content_bytes = content_bytes[2:]
    else:
        # Try UTF-8 first, then fallback
        try:
            content_bytes.decode('utf-8', errors='strict')
            enc = 'utf-8'
            log_verbose("Detected UTF-8 encoding.")
        except UnicodeDecodeError:
            # Try common Windows default encoding
            try:
                 import locale
                 enc = locale.getpreferredencoding(False)
                 log_verbose(f"UTF-8 decode failed, trying system preferred: {enc}")
            except Exception:
                 enc = 'cp1252' # Ultimate fallback
                 log_verbose(f"UTF-8 and system preferred failed, trying fallback: {enc}")

        except Exception as e:
            print(f"Error detecting encoding: {e}")
            return None

    try:
        # Use 'replace' on decode errors for more resilience
        content = content_bytes.decode(enc, errors='replace')
        lines = content.splitlines()
        print(f"Read {len(lines)} lines using {enc} encoding.")
        return lines
    except Exception as e:
        print(f"Error decoding file content with {enc}: {e}")
        return None


def extract_initial_settings(lines: List[str]) -> Dict:
    """Finds KDOT value and builds the reverse Caesar map."""
    settings = {"kdot_value": None, "reverse_caesar_map": {}}
    kdot_found = False
    caesar_map_count = 0

    for i, line in enumerate(lines):
        # Find KDOT only once
        if not kdot_found:
            kdot_match = RE_KDOT.match(line)
            if kdot_match:
                settings["kdot_value"] = kdot_match.group(1)
                log_verbose(f"Found KDOT value at line {i+1}: {settings['kdot_value']}")
                kdot_found = True # Stop searching for KDOT

        # Find Caesar definitions
        caesar_match = RE_CAESAR_DEF.match(line)
        if caesar_match:
            original_char = caesar_match.group(1).lower()
            obfuscated_char = caesar_match.group(2).lower()
            # Store only the first definition found for each obfuscated char
            if obfuscated_char not in settings["reverse_caesar_map"]:
                settings["reverse_caesar_map"][obfuscated_char] = original_char
                log_verbose(f"Found Caesar mapping at line {i+1}: {obfuscated_char} -> {original_char}")
                caesar_map_count += 1
            elif settings["reverse_caesar_map"][obfuscated_char] != original_char:
                 # Log conflict but don't overwrite, assume first is correct
                 log_verbose(f"Ignoring conflicting Caesar definition for '{obfuscated_char}' at line {i+1}.")

    if not settings["kdot_value"]:
        print("Warning: KDOT variable definition ('set KDOT=...') was not found. KDOT slicing cannot be deobfuscated.")
    if not settings["reverse_caesar_map"]:
        print("Warning: Caesar cipher definitions ('set a=b', etc.) were not found. Caesar substitution cannot be deobfuscated.")
    else:
        print(f"Built reverse Caesar map with {len(settings['reverse_caesar_map'])} entries.")

    return settings

# --- Character Deobfuscation Helpers ---
def get_char_from_env_slice(match: re.Match) -> str:
    """Helper to resolve environment variable slicing."""
    var_name = match.group(1).upper()
    try:
        index = int(match.group(2))
    except ValueError: return match.group(0) # Should not happen with regex, but safety

    if var_name in ENV_VAR_VALUES:
        value = ENV_VAR_VALUES[var_name]
        try:
            actual_index = len(value) + index if index < 0 else index
            if 0 <= actual_index < len(value): return value[actual_index]
            else: log_verbose(f"Warning: Index {index} out of bounds for env var {var_name}"); return ""
        except IndexError: log_verbose(f"Warning: IndexError for {var_name}:~{index},1"); return "" # Should be caught above
    else:
        log_verbose(f"Warning: Unknown environment variable '{var_name}' in slice: {match.group(0)}")
        return match.group(0) # Return original if var unknown

def get_char_from_kdot(match: re.Match, kdot_value: Optional[str]) -> str:
    """Helper to resolve KDOT variable slicing."""
    if not kdot_value:
        # Warning printed during settings extraction, avoid repeating here
        return match.group(0)
    try:
        index = int(match.group(1))
        if 0 <= index < len(kdot_value): return kdot_value[index]
        else: log_verbose(f"Warning: KDOT index {index} out of bounds."); return ""
    except (ValueError, IndexError): # Catch potential errors if regex somehow allows bad index
        log_verbose(f"Warning: Invalid KDOT slice index from regex match: {match.group(0)}")
        return match.group(0)

def get_char_from_caesar(match: re.Match, reverse_map: Dict) -> str:
    """Helper to resolve Caesar cipher characters."""
    obfuscated_char = match.group(1).lower(); is_upper_marker = match.group(2)
    if obfuscated_char in reverse_map:
        original_char = reverse_map[obfuscated_char]
        return original_char.upper() if is_upper_marker else original_char
    else:
        # Warning printed during settings extraction if map is empty
        log_verbose(f"Warning: Character '{obfuscated_char}' not found in reverse Caesar map.")
        return match.group(0) # Return original if not found
# ---

def deobfuscate_line_characters(line: str, settings: Dict) -> str:
    """Applies character deobfuscation rules iteratively to a single line."""
    kdot_value = settings.get("kdot_value")
    reverse_caesar_map = settings.get("reverse_caesar_map", {})
    # Avoid processing if essential settings are missing
    if not kdot_value and not reverse_caesar_map and not any(v in line for v in ENV_VAR_VALUES):
         # If no settings and no clear env vars, likely little to do
         # Still run simple junk removal though
         pass

    original_line = line

    # --- Pass 1: Specific Slices and Caesar ---
    def replace_callback(match):
        # Determine which sub-pattern matched by checking capture groups
        if match.group(2): # Matched RE_ENV_SLICE
            env_match = RE_ENV_SLICE.match(match.group(1))
            return get_char_from_env_slice(env_match) if env_match else match.group(0)
        elif match.group(5): # Matched RE_KDOT_SLICE
            kdot_match = RE_KDOT_SLICE.match(match.group(4))
            return get_char_from_kdot(kdot_match, kdot_value) if kdot_match else match.group(0)
        elif match.group(7): # Matched RE_CAESAR_JUNK
            caesar_match = RE_CAESAR_JUNK.match(match.group(6))
            return get_char_from_caesar(caesar_match, reverse_caesar_map) if caesar_match else match.group(0)
        else: return match.group(0) # Should not happen


    passes = 0
    max_passes = 15 # Safety break for potential infinite loops
    last_line = None
    processed_line = line
    # Only iterate if there are patterns to potentially match
    if kdot_value or reverse_caesar_map or any(f"%{v}:~" in line for v in ENV_VAR_VALUES):
        while processed_line != last_line and passes < max_passes:
            last_line = processed_line
            processed_line = RE_COMBINED_SPECIFIC_CHAR_OBF.sub(replace_callback, last_line)
            passes += 1
        if passes >= max_passes and processed_line != last_line:
            print(f"Warning: Max substitution passes ({max_passes}) reached for specific patterns: {original_line[:80]}...")


    # --- Pass 2: Simple Junk Removal ---
    # Always run this pass
    passes = 0
    max_passes_junk = 5
    last_line = None
    while processed_line != last_line and passes < max_passes_junk:
        last_line = processed_line
        processed_line = RE_SIMPLE_JUNK.sub(r"\1", last_line) # Replace %junk%C%junk% with C
        passes += 1
    if passes >= max_passes_junk and processed_line != last_line:
        print(f"Warning: Max substitution passes ({max_passes_junk}) reached for junk removal: {original_line[:80]}...")


    # --- Pass 3: Remove leftover markers ---
    processed_line = processed_line.replace("%escape%", "").replace("%STOP_OBF_HERE%", "")

    # --- Pass 4: Normalize command case (simple version) ---
    words = processed_line.split()
    if words:
        # Expand list of known batch commands
        known_commands = [
            "echo", "set", "goto", "if", "for", "call", "exit", "chcp", "cls", "rem",
            "pause", "del", "copy", "move", "ren", "md", "rd", "dir", "find", "findstr",
            "type", "sort", "start", "assoc", "ftype", "pushd", "popd", "setlocal", "endlocal",
            "verify", "vol", "label", "path", "prompt", "title", "color", "mode", "net", "sc",
            "taskkill", "tasklist", "wmic", "powershell", "cscript"
            ]
        first_word_lower = words[0].lower()
        # Check if the first word (stripping potential leading :) is a known command
        if first_word_lower.lstrip(':') in known_commands:
             words[0] = first_word_lower # Normalize to lowercase
        processed_line = " ".join(words)

    if VERBOSE and original_line != processed_line:
         log_verbose(f"Deobfuscated line: {processed_line[:80]}...")

    return processed_line


def reverse_scrambling(lines: List[str]) -> List[str]:
    """Reverses the Scrambler code reordering, using enhanced math eval."""
    eof_index = -1
    # Find the first potential scrambler EOF marker reliably
    for i, line in enumerate(lines):
        stripped_lower = line.strip().lower()
        # Check for the marker itself
        if stripped_lower == "goto :eof" or stripped_lower == "exit /b 0":
            # Check context: should be preceded by a goto %ans% line for scrambler
            if i > 0:
                prev_line_stripped_lower = lines[i-1].strip().lower()
                if prev_line_stripped_lower == "goto %ans%":
                     eof_index = i
                     log_verbose(f"Found likely scrambler EOF marker at line {i+1}")
                     break # Found it
            # If context doesn't match, it might be user code, continue searching

    if eof_index == -1:
        log_verbose("Scrambler EOF marker not found or context incorrect. Skipping scrambling reversal.")
        return lines # Return lines as they are

    # Proceed with splitting and parsing
    main_code_lines = lines[:eof_index]
    scrambled_part_lines = lines[eof_index + 1:]
    scrambled_part_text = "\n".join(scrambled_part_lines)

    # Parse the scrambled blocks: {target_label_str: original_code_line}
    label_to_code: Dict[str, str] = {}
    parsed_block_count, failed_block_count = 0, 0

    # Iterate through potential blocks using the regex
    for match in RE_SCRAMBLED_BLOCK.finditer(scrambled_part_text):
        label = match.group(1)
        # Group 2 contains original code + potentially injected anti-methods/deadcode.
        # Take the first non-empty line as the most likely original code.
        potential_code_lines = [ln for ln in match.group(2).strip().splitlines() if ln.strip()]
        original_code = ""
        if potential_code_lines:
            original_code = potential_code_lines[0].strip() # Assume first non-empty line is key
        else:
            log_verbose(f"Warning: Found block for label {label} but no non-empty code captured.")
            failed_block_count += 1
            continue # Skip if no code found

        if label in label_to_code:
            log_verbose(f"Warning: Duplicate label {label} found in scrambled blocks. Overwriting with later definition.")
        label_to_code[label] = original_code
        log_verbose(f"Found scrambled block label {label}: {original_code[:60]}...")
        parsed_block_count += 1

    if not label_to_code:
        print("Warning: No valid scrambled blocks parsed after EOF marker. Structure might be broken.")
        # Still return only the main code part, as the rest was likely junk/EOF
        return main_code_lines

    print(f"Parsed {parsed_block_count} scrambled blocks (encountered {failed_block_count} parsing errors).")

    # Reconstruct the main code by replacing jump blocks
    reconstructed_code = []
    main_code_text = "\n".join(main_code_lines)
    last_pos = 0
    replacement_count, failed_evaluation_count = 0, 0

    # Use finditer to process jumps sequentially
    for jump_match in RE_SCRAMBLE_JUMP.finditer(main_code_text):
        math_expression = jump_match.group(1).strip()
        # Return label (group 2) is captured but not strictly needed for replacement
        # return_label = jump_match.group(2)

        # Evaluate the math expression to find the target label
        target_label_int = safe_eval_batch_math(math_expression)
        target_label_str = str(target_label_int) if target_label_int is not None else None

        # Add the text segment *before* this jump block
        reconstructed_code.append(main_code_text[last_pos:jump_match.start()])

        # Attempt to replace the jump block with the original code
        if target_label_str and target_label_str in label_to_code:
            log_verbose(f"Replacing jump (math='{math_expression}', eval={target_label_str})")
            reconstructed_code.append(label_to_code[target_label_str]) # Insert original code
            replacement_count += 1
        elif target_label_str:
            # Math evaluated, but label not found (maybe parsing error or obfuscator bug)
            print(f"Warning: Evaluated target label {target_label_str} (from '{math_expression}'), but no corresponding block found! Jump removed.")
            failed_evaluation_count += 1
            # Append nothing, effectively removing the jump block
        else:
            # Math evaluation failed
             print(f"Warning: Failed to evaluate math for jump target ('{math_expression}'). Jump removed.")
             failed_evaluation_count += 1
             # Append nothing, effectively removing the jump block

        # Update position for the next segment
        last_pos = jump_match.end()

    # Add any remaining text after the last processed jump block
    reconstructed_code.append(main_code_text[last_pos:])

    print(f"Finished reversing scrambling: {replacement_count} jumps replaced, {failed_evaluation_count} failures/removals.")
    # Return the reconstructed code as a list of lines
    return "\n".join(reconstructed_code).splitlines()


def remove_inserted_code(lines: List[str]) -> List[str]:
    """Removes known inserted lines/blocks using patterns in RE_JUNK_TO_REMOVE."""
    original_count = len(lines)
    # Use a list comprehension for efficient filtering
    cleaned_lines = [
        line for line in lines
        if not any(pattern.search(line) for pattern in RE_JUNK_TO_REMOVE)
    ]
    removed_count = original_count - len(cleaned_lines)

    if removed_count > 0:
        print(f"Removed {removed_count} known inserted/junk lines based on patterns.")
    elif VERBOSE:
         log_verbose("No known junk lines found matching removal patterns.")

    return cleaned_lines

def final_cleanup(lines: List[str]) -> List[str]:
    """Basic cleanup: remove extra empty lines and leading/trailing whitespace."""
    cleaned = []
    last_line_empty = True
    for line in lines:
        stripped = line.strip() # Remove leading/trailing whitespace first
        if stripped:
            cleaned.append(stripped) # Add the content line
            last_line_empty = False
        elif not last_line_empty:
            # Only add an empty line if the previous line was not empty
            cleaned.append("") # Add a single empty line
            last_line_empty = True
    # Remove potential trailing empty line added by loop logic
    if cleaned and cleaned[-1] == "":
        cleaned.pop()
    return cleaned


# --- Main Execution ---

def deobfuscate_file(input_path: Path, output_path: Path):
    """Main deobfuscation pipeline with refined steps."""
    print("-" * 60)
    print(f"Starting deobfuscation for: {input_path}")
    print("-" * 60)

    # 1. Read and Preprocess (Encoding, BOM)
    lines = read_and_preprocess(input_path)
    if lines is None:
        print("Failed to read or decode file. Aborting.")
        return # Abort if reading failed

    # 2. Extract Initial Settings (KDOT, Caesar Map)
    print("\n[Step 1/5] Extracting initial settings...")
    settings = extract_initial_settings(lines)

    # 3. Deobfuscate Characters (Applied to ALL lines first)
    print("\n[Step 2/5] Deobfuscating characters...")
    char_deobfuscated_lines = []
    for i, line in enumerate(lines):
         # Use enumerate for line numbers in verbose logging
         log_verbose(f"Processing line {i+1}/{len(lines)}: {line[:80]}...")
         processed_line = deobfuscate_line_characters(line, settings)
         char_deobfuscated_lines.append(processed_line)
    print("Character deobfuscation finished.")

    # 4. Reverse Scrambling (Operates on character-deobfuscated lines)
    print("\n[Step 3/5] Reversing code scrambling...")
    scramble_reversed_lines = reverse_scrambling(char_deobfuscated_lines)

    # 5. Remove Inserted/Known Junk Lines (Operates AFTER scrambling reversal & char deobf)
    print("\n[Step 4/5] Removing known inserted lines, anti-methods and dead code...")
    removed_junk_lines = remove_inserted_code(scramble_reversed_lines)

    # 6. Final Cleanup
    print("\n[Step 5/5] Performing final cleanup...")
    final_lines = final_cleanup(removed_junk_lines)

    # 7. Write Output
    print("\nWriting output...")
    try:
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        # Write with UTF-8 and standard Windows line endings
        output_path.write_text("\n".join(final_lines) + "\n", encoding='utf-8', newline='\r\n')
        print("-" * 60)
        print(f"Deobfuscation complete. Output written to: {output_path}")
        print("-" * 60)
    except IOError as e:
        print(f"ERROR: Could not write output file {output_path}: {e}")
    except Exception as e:
        print(f"ERROR: An unexpected error occurred during file writing: {e}")


if __name__ == "__main__":
    # Setup Argument Parser
    parser = argparse.ArgumentParser(
        description="Enhanced Deobfuscator for SomalifuscatorV2 Batch files.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Show defaults in help message
    )
    parser.add_argument(
        "input_file",
        help="Path to the obfuscated batch file (.bat or .cmd)."
    )
    parser.add_argument(
        "-o", "--output",
        help="Path for the deobfuscated output file. If omitted, saves as '<input_stem>_deobf.bat'."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true", # Makes it a flag, True if present
        help="Enable verbose logging for detailed deobfuscation steps."
    )

    # Parse arguments
    args = parser.parse_args()

    # Set global verbose flag
    VERBOSE = args.verbose

    # Prepare paths
    input_path = Path(args.input_file)
    # Determine output path
    if args.output:
        output_path = Path(args.output)
    else:
        # Default output path construction
        output_path = input_path.with_name(f"{input_path.stem}_deobf{input_path.suffix}")

    # --- Input Validation ---
    # Check if input file exists
    if not input_path.is_file():
        print(f"ERROR: Input file not found: {input_path}")
        exit(1) # Exit script with error code

    # Prevent accidental overwrite of input file
    # Resolve paths to handle relative paths and case differences on Windows
    if input_path.resolve() == output_path.resolve():
         print(f"ERROR: Input and output file paths point to the same file ({input_path}).")
         print("Please specify a different output file using the -o option.")
         exit(1)

    # --- Run Deobfuscation ---
    deobfuscate_file(input_path, output_path)