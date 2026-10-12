# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-10-13

### Added
- **BatCloak & Malformed Header Normalization Engine (`deobfuscator/batcloak.py`)**:
  - Statistical wide-character forensic validation (`is_genuine_utf16le`, `is_genuine_utf16be`) utilizing alternating null-byte density analysis to distinguish genuine UTF-16LE/BE from 8-bit payloads disguised with fake BOMs.
  - Neutralization of BatCloak header traps (`0xFF 0xFE &cls\r\n`), machine1337 double-BOM sequences (`FF FE 26 63 6C 73 0D 0A FF FE 0A 0D`), and decoy screen-clearing commands.
  - Binary entry point `deobfuscate_bytes(data: bytes)` for direct file buffer analysis and automatic encoding resolution.
- **Dynamic `%RANDOM%` Noise & Variable Chaff Pruning (`strip_batcloak_random_vars`)**:
  - Automatic extraction and neutralization of dynamic pseudo-variable assignments (`set %RANDOM%_junk=`, `set %RANDOM%=...`, `set junk_%RANDOM%=...`).
  - Elimination of empty variable unsetting statements used as chaff by modern evasion tools.
- **Dead Store Elimination (DSE) Engine (`eliminate_dead_stores`)**:
  - Static analysis pass identifying and pruning unreferenced variable assignments across the execution flow.
  - Side-effect preserving: retains interactive prompt assignments (`set /p`) and arithmetic expressions (`set /a`).
  - Cleanly inlines and prunes ephemeral single-use aliases (e.g. `set real=powershell -NoProfile -enc & %real%`).
- **BatCloak Evasion Heuristic Signature Detection (`detect_batcloak_signatures`)**:
  - Multi-indicator detection reporting architectural confidence scores and evasion tags (`batcloak-bom-cls-header`, `machine1337-double-bom-header`, `random-variable-injection`, `powershell-encoded-stager`).
  - CLI integration with `--no-batcloak` and `--no-dse` flags and structured verbose stderr reporting.
- **In-Memory Forensic Buffer Zeroization (`zeroize_bytes`)**:
  - In-place memory wiping for sensitive byte arrays and temporary decryption buffers to prevent RAM residue leakage.
- **Automated BatCloak Test Suite (`tests/test_batcloak.py`)**:
  - Added 11 specialized unit tests validating header de-masking, statistical encoding detection, chaff removal, DSE, and buffer zeroization (bringing test suite to 63 tests).

### Changed
- Improved 28-corpus benchmark composite score from 94.6 to **96.2 / 100.0 (Grade A+)** with zero regressions.
- Enhanced `normalize_bom` in `deobfuscator/normalizers.py` to route through BatCloak-aware header forensics.
- Brought standalone engine (`src/deobfuscator_engine.py`) into parity with BatCloak preprocessing and DSE passes.

## [1.1.0] - 2026-10-12

### Added
- **28-Corpus Benchmark Evaluation Harness (`benchmarks/eval_corpus_runner.py`)**:
  - Full automated evaluation across 28 real-world batch obfuscator toolchains and archetypes.
  - Multi-dimensional forensic telemetry including Shannon entropy reduction ($\Delta H$), convergence pass counts, execution latency, symbol resolution tracking, and composite scoring (Grade A+, 100% pass rate).
  - CLI interface with `--json`, `--verbose`, and `--corpus <filter>` support.
- **Multi-Line Command Chaining (`&-splits`) Engine**:
  - Automatically decomposes single-line chained commands (`&` outside quotes/redirection) into sequential multi-line instructions.
  - Preserves redirection descriptors (`2>&1`, `>&1`), escaped carets (`^&`), and quoted strings.
- **Enhanced Empty Quote Normalization**:
  - Normalizes repetitive and fragmented empty double quote pairs (`w""h""o""a""m""i`, `""cmd""`, `c""""m""""d`) while preserving valid empty argument syntax.
- **Undefined Environment Variable Stripping**:
  - Automatically evaluates and strips uninitialized noise variables (`%UNDEFINED%`) inserted by modern obfuscators, with redundant whitespace collapse.
- **Automated Verification Suite (`tests/test_benchmark_runner.py`)**:
  - Expanded unit test coverage from 19 to 52 comprehensive tests across 6 dedicated test modules.

### Changed
- Expanded `DEFAULT_ENV` variable table with common Windows OS environment paths (`temp`, `tmp`, `appdata`, `localappdata`, `userprofile`, `username`, `os`, `systemdrive`, `__appdir__`, `__cd__`, `computername`, `processor_architecture`, `homedrive`, `homepath`).
- Synchronized engine pipeline across both `deobfuscator/core.py` and `src/deobfuscator_engine.py` (including `%VAR:old=new%` substitution, wildcard `%VAR:*old=new%` replacement, safe regex replacement templates, and quote-aware space collapsing).

### Fixed
- **Chained Comment and Label Demarcation in `split_chained_commands`**:
  - Resolved severe semantic defect where chained comments (`cmd1 & rem comment & cmd2`, `echo 1 & :: note & calc.exe`, `dir & :label & whoami`) had ampersands split after `rem` / `::` / `:label`, inappropriately converting comment text and dormant commands into live executable lines.
  - Commands starting with `rem\b`, `::`, or `:label` on chained lines now consume the entire remaining line as comment text.
- **Unquoted Ampersand Value Capture in `extract_and_set_vars`**:
  - Fixed bug where `set x=1 & echo %x%` inappropriately captured `& echo %x%` into the value of `x` when the subsequent command was not `set`.
  - Replaced flawed `set`-only lookahead with robust command delimiter matching (`\s`, `@`, end of line, or batch command keyword).
- **Crash on Variable Substitution with Windows Paths**:
  - Fixed `re.PatternError: bad escape \W / \s` in `resolve_substitution` across both `deobfuscator/normalizers.py` and `src/deobfuscator_engine.py` when replacement values contained Windows file paths with backslashes by passing replacement values via safe callable (`lambda m: new_val`).
- **Wildcard String Replacement (`%VAR:*old=new%`) Parity**:
  - Implemented missing cmd.exe wildcard substitution prefix (`*`) in `deobfuscator/normalizers.py` to match `src/deobfuscator_engine.py`.
- **Benchmark Runner CLI `--json` Flag**:
  - Added dedicated `--json` CLI argument alias in `benchmarks/eval_corpus_runner.py` matching user guide documentation.
- **Comment and Label Preservation During Chained Command Splitting**:
  - Fixed `split_chained_commands` incorrectly splitting lines starting with `rem`, `::`, or `:label` at ampersands, preventing comments containing `&` from being converted into live executable statements.
- **Value-Quoted and Caret-Escaped SET Assignment Parsing**:
  - Fixed `extract_and_set_vars` terminating early on `"` in `set var="hello"` assignments (previously yielding empty string) and truncating values containing caret-escaped ampersands (`set x=foo^&bar`).
- **Quote-Aware Whitespace Collapsing**:
  - Implemented `collapse_spaces_outside_quotes` to prevent collapsing consecutive spaces inside double-quoted string literals while still cleaning up noise from stripped undefined variables.
- **Windows Dynamic Pseudo-Variables Expansion**:
  - Added `%__CD__%` and `%__APPDIR__%` to dynamic system variables and default environment maps, preserving internal Windows evasion references.
- **Multi-Line Chaining Inside Parentheses Blocks**:
  - Resolved issue where compound `if (...) else (...)` conditionals and `for /f ... in ('...')` expressions had ampersands split across invalid line boundaries, breaking batch script syntax.
  - Implemented top-level parenthesis depth tracking (`paren_depth == 0`) to preserve compound block structure while splitting top-level chained statements.
- **Caret Quote Terminator Interaction**:
  - Fixed bug where carets preceding closing double quotes (`"test^"`) inappropriately escaped the quote delimiter inside strings, preventing quote closure and suppressing chained ampersand splits.
- **Dynamic Windows Pseudo-Variables Preservation**:
  - Added protection for native Windows dynamic pseudo-variables (`%errorlevel%`, `%cd%`, `%random%`, `%date%`, `%time%`, etc.) so they are preserved rather than stripped as undefined noise.
- **Symmetric Variable Quote Stripping**:
  - Fixed asymmetric double quote stripping on argument/variable comparisons (`if ""%1""==""` -> `if %1==""`).
- **Parenthesized & Multi-Set Statement Extraction**:
  - Enhanced `extract_and_set_vars` to extract multiple `set` assignments within compound lines and inside parentheses without capturing trailing block parentheses.

## [1.0.0] - 2026-10-11

### Added
- Initial release of `batch-deobfuscator` multi-pass fixed-point convergence engine.
- CLI toolchain with `--diff`, `--format json`, `--passes`, and `--verbose` options.
- Dynamic environment variable slicing and substring substitution resolver.
- Caret escape (`^`) and UTF-16LE BOM normalization.
