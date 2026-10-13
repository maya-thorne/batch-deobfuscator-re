# SomalifuscatorV2 Deobfuscator

## Overview

This Python script is designed to deobfuscate Windows Batch files (`.bat`, `.cmd`) that have been processed by the **SomalifuscatorV2** obfuscator. It aims to reverse the primary obfuscation techniques employed by SomalifuscatorV2 (based on analysis of its source code) to restore the original script's logic and readability.

The deobfuscation process involves multiple steps, including character substitution reversal, code structure reconstruction (scrambling reversal), and removal of injected helper code.

## Features

*   **Character Deobfuscation:** Reverses multiple character encoding/substitution methods:
    *   Caesar Cipher substitution (requires definition lines like `set a=b` to be present).
    *   Environment Variable Slicing (e.g., `%PUBLIC:~3,1%`).
    *   `%KDOT%` Variable Slicing (requires `set KDOT=...` line).
    *   Simple Junk Variable Wrapping (e.g., `%random%C%random%`).
*   **Scrambling Reversal:** Reconstructs the original code order for blocks moved by the Scrambler:
    *   Identifies the `goto :EOF` marker inserted by the scrambler.
    *   Parses scrambled code blocks located after the marker.
    *   Finds jump setups (`set /a ans=...`, `goto %ans%`) in the main code.
    *   Attempts to evaluate the `set /a` math expression to find the target label.
    *   Replaces jump setups with the corresponding original code block.
*   **Code Cleanup:** Removes known artifacts introduced by the obfuscator:
    *   Header comments (`::Made by K.Dot...`).
    *   `chcp 65001 > nul` line.
    *   Caesar cipher variable definition lines (`set a=b`, etc.).
    *   Initial redirection check line (`>nul 2>&1 && exit...`).
    *   Leftover obfuscation markers (`%escape%`, `%STOP_OBF_HERE%`).
*   **Encoding Handling:** Detects and handles UTF-16 LE BOM; attempts decoding as UTF-8 or a common fallback (CP1252).
*   **Verbose Logging:** Optional detailed step-by-step output for debugging (`-v` flag).

## Requirements

*   Python 3.7+ (due to usage of `pathlib`, type hints, f-strings)
*   Standard Python libraries (`re`, `os`, `argparse`, `math`, `pathlib`, `typing`, `string`). No external packages need to be installed.

## Installation

No installation is required. Simply save the script as a `.py` file (e.g., `deobfuscator.py`).

## Usage

Run the script from your command line or terminal:

```bash
python deobfuscator.py <input_file> [options]
```

**Arguments:**

*   `input_file`: **Required**. The path to the obfuscated Batch file you want to deobfuscate.

**Options:**

*   `-o OUTPUT`, `--output OUTPUT`: Specifies the path for the deobfuscated output file.
    *   If omitted, the output will be saved in the same directory as the input file, with `_deobf` appended to the original filename (e.g., `script_obf.bat` -> `script_obf_deobf.bat`).
*   `-v`, `--verbose`: Enables verbose logging, showing detailed steps and warnings during the deobfuscation process.

**Examples:**

1.  **Basic Deobfuscation:**
    ```bash
    python deobfuscator.py C:\path\to\obfuscated_script.bat
    ```
    *(Output will be saved as `C:\path\to\obfuscated_script_deobf.bat`)*

2.  **Specify Output File:**
    ```bash
    python deobfuscator.py obfuscated_script.bat -o restored_script.bat
    ```

3.  **Enable Verbose Logging:**
    ```bash
    python deobfuscator.py obfuscated_script.bat -v
    ```

## How It Works

The deobfuscator follows a pipeline approach:

1.  **Read & Preprocess:** Reads the input file, handles potential UTF-16 LE Byte Order Mark (BOM), and determines the likely encoding (UTF-8 or fallback).
2.  **Extract Settings:** Scans the initial lines to find the `set KDOT=...` value and builds a reverse mapping for the Caesar cipher based on `set a=b`, `set b=c`, etc. definitions.
3.  **Deobfuscate Characters:** Iteratively applies regular expressions to replace obfuscated character patterns (`%VAR:~n,1%`, `%KDOT:~n,1%`, `%char%`, `%junk%C%junk%`) with their original characters. This step is crucial before structural analysis.
4.  **Reverse Scrambling:**
    *   Locates the `goto :EOF` marker added by the scrambler.
    *   Parses the code blocks appearing after this marker, mapping target labels to their (character-deobfuscated) original code line.
    *   Searches the main code (before `goto :EOF`) for the scrambler's jump pattern (`set /a ans=MATH_EXPR`, `goto %ans%`).
    *   Uses `safe_eval_batch_math` to attempt evaluating `MATH_EXPR` and determine the target label number.
    *   Replaces the jump pattern in the main code with the corresponding code line retrieved from the parsed blocks.
5.  **Remove Junk Code:** Filters out lines matching known patterns associated with the obfuscator's setup and comments.
6.  **Final Cleanup:** Removes extra blank lines and trims whitespace for better readability.
7.  **Write Output:** Saves the processed lines to the specified output file using UTF-8 encoding and standard Windows CRLF line endings.

## Limitations & Known Issues

*   **Complex `set /a` Math:** The script uses a basic math evaluator (`safe_eval_batch_math`) for the scrambler's jump logic. Very complex or intentionally tricky Batch math expressions might not be evaluated correctly, preventing scrambling reversal for those blocks.
*   **Unknown Anti-Analysis/Bloat:** Techniques used by SomalifuscatorV2's `AntiChanges`, `AntiConsole`, `DeadCode`, or `pogdog` components are not explicitly reversed unless they leave easily identifiable line patterns. Remnants of this code may persist in the output.
*   **Obfuscator Variations:** This deobfuscator is based on the analyzed source code of SomalifuscatorV2. Significant changes or different versions of the obfuscator might use techniques not handled by this script.
*   **Environment Variable Accuracy:** Environment variable slicing (`%VAR:~n,1%`) resolution depends on the values defined in `ENV_VAR_VALUES` or retrieved via `os.environ`. If the system where the script was obfuscated had significantly different paths, the deobfuscation might be inaccurate for those specific characters.
*   **Batch Syntax Complexity:** While aiming for robustness, extremely complex or unusual Batch syntax (e.g., deeply nested parentheses, complex redirection combined with variable expansion) might interfere with the character replacement logic in edge cases.

## License

This script is provided as-is. You are free to use, modify, and distribute it. Please refer to standard open-source licenses like MIT if formal licensing is required. (Consider adding an actual LICENSE file if distributing widely).
```
