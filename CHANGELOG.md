# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.0] - 2026-10-13

### Added
- **Invoke-DOSfuscation Static Deobfuscation Engine (`deobfuscator/dosfuscation.py`)**:
  - `Out-DosReversedCommand` reverse reconstruction loop unrolling (`unwrap_dosfuscation_for_loops`): statically analyzes cmd.exe `for /L %A in (start, step, end) do ...` loops, supporting arbitrary negative strides (-1, -2, -3) and character padding noise.
  - `Out-DosFORcodedCommand` indexed variable assembly (`unwrap_dosfuscation_for_loops`): reconstructs cleartext payloads built from source character sets via `for %A in (...)` arrays, properly parsing mixed comma/semicolon/space delimiters, careted numbers (`1^3` -> `13`), explicit positive signs (`+1337`), and sentinel termination branches.
  - `Out-EnvVarEncodedCommand` advanced environment variable slicing (`resolve_dosfuscation_slicing`): fully resolves `%VAR:~start,length%` and delayed expansion `!VAR:~start,length!` expressions with embedded whitespace and tabs (`%COMSPEC:~   -7,   +3%`), negative lengths, and clamped start indices against system environment tables.
  - Bohannon delimiter cluster normalization (`normalize_dosfuscation_delimiters`): cleans non-standard parameter separators (`,;,`, `;,;`, `,,;`, `;;`, and token-adjacent `,` or `;`) outside quotes without altering literal string values or redirection syntax.
  - Multi-indicator heuristic signature detection (`detect_dosfuscation_signatures`): accurately identifies `for /L` reverse loops, high-density index arrays, delayed expansion accumulators, and delimiter noise clusters with calculated confidence scores.
  - Cryptographic in-memory buffer zeroization (`zeroize_dict`) to overwrite temporary forensic tables and symbol buffers before deallocation.
  - `DOSfuscationNormalizer` production class exposing clean `normalize()` and `detect()` interfaces.
- **Dedicated Invoke-DOSfuscation Verification Suite (`tests/test_dosfuscation.py`)**:
  - Added 14 unit tests covering reverse reconstruction, stride padding, careted loop syntax, index array extraction with sentinels, wildcard substitution, delimiter cluster normalization, advanced slicing variants with tabs and positive signs, delayed expansion substitution chains, memory zeroization, and end-to-end pipeline integration (expanding test suite to 114 tests).

### Changed
- Integrated Invoke-DOSfuscation normalization into the core multi-pass convergence pipeline (`deobfuscator/core.py`, `deobfuscate_script`, `deobfuscate_bytes`) via `enable_dosfuscation=True`.
- Enhanced `resolve_variables` in `BatchDeobfuscator` to natively evaluate delayed expansion substitution (`!VAR:old=new!`) and variable expansion (`!VAR!`) during fixed-point convergence passes.
- Updated AST slicing normalizer (`deobfuscator/normalizers.py`) to handle explicit plus signs (`+3`) and tab whitespace.
- Brought standalone engine (`src/deobfuscator_engine.py`) into parity with Invoke-DOSfuscation normalization passes.
- Updated CLI toolchain (`deobfuscator/cli.py`) with `--no-dosfuscation` flag and structured Invoke-DOSfuscation telemetry reporting in verbose mode.
- Synchronized architecture mapping guide (`scripts/ARCHITECTURE_MAP.md`) and bumped package version to v1.6.0.

## [1.5.0] - 2026-10-13

### Added
- **Abobus-obfuscator Normalization & Unicode Noise Filtering Engine (`deobfuscator/abobus.py`)**:
  - Zero-width character and Unicode noise filtering (`strip_abobus_unicode_noise`) eliminating bidirectional control marks (LTR/RTL marks, ZWSP, ZWNJ, ZWJ, and non-breaking spaces).
  - Anti-detect decoy variable elimination neutralizing Arabic character sets (`ﭲسﺖﮚ...`), Kaomoji face strings (`ヾ(⌐■_■)ノ`, `(◕‿◕)`...), and Chinese anti-copy warning text (`此訊息已被神秘魔法保護...`) embedded in variable references.
  - Caret separation and delimiter normalization (`normalize_abobus_carets_and_delimiters`) resolving caret-escaped quotes (`^"` -> `"`), keyword splitting (`s^e^t`, `c^m^d`, `e^c^h^o`), variable identifiers, leading delimiter sequences (`;;`, `;@;`, `@@`), and large indentation blocks (>50 spaces).
  - Multi-stage Chinese substring dictionary harvesting and inlining (`resolve_abobus_substring_dictionaries`) resolving `%public:~idx,1%` system slicing against `C:\Users\Public` and iteratively decomposing chained Chinese alphabet tables (`阿贝色德...`).
  - Opaque predicate and trap chaff elimination (`strip_abobus_traps_and_chaff`) unwrapping `random_if` prefixes (`if 1 EQU 1`, `if N EQU 0 (@exit) else`, `if N LsS M`, `for /l %%y in (1 1 1) do`) and removing anti-analysis execution loops, echo traps, and exit assertions.
  - Multi-indicator heuristic signature detection (`detect_abobus_signatures`) evaluating author markers (`:ABOBUS-OBFUSCATOR`, `EscaLag`), decoy glyphs, and structural trap metrics with confidence scoring.
  - Memory zeroization (`zeroize_dict`) overwriting temporary forensic tables and harvested dictionary buffers.
- **Dedicated Abobus Verification Suite (`tests/test_abobus.py`)**:
  - Added 14 comprehensive unit tests covering canonical watermarked scripts, markerless heuristic detection, Unicode noise stripping, caret quote handling, random_if unwrapping, chained dictionary inlining, dummy variable DSE, and multi-pass pipeline integration (expanding test suite to 100 tests).

### Changed
- Integrated Abobus normalization into the core convergence loop (`deobfuscator/core.py`, `deobfuscate_script`, `deobfuscate_bytes`) via `enable_abobus=True`.
- Brought standalone engine (`src/deobfuscator_engine.py`) into parity with Abobus normalization passes.
- CLI toolchain updated with `--no-abobus` flag and structured Abobus forensic telemetry reporting in verbose mode.
- Synchronized architecture mapping guide (`scripts/ARCHITECTURE_MAP.md`) and package versioning to v1.5.0.

## [1.4.0] - 2026-10-13

### Added
- **0xidiz3r Zero-Literal Bootstrap & Reversible Alphabet Normalization Engine (`deobfuscator/oxidizer.py`)**:
  - Three-stage zero-literal primitive seed resolver (`extract_bootstrap_primitives`) automatically reconstructing `set`, `space`, and `equals` variables from obfuscated preambles (`set S=set`, `%S% SP= `, `%S%%SP%EQ===`), with full support for caret escaping (`s^e^t`), quoted syntax, and single-line command chaining (`&`).
  - Dynamic reversible alphabet table harvesting (`harvest_oxidizer_alphabet`) extracting 52+ character symbol definitions, multi-token payloads, and special literal percent escapes (`%%` -> `%`).
  - Automated space token resolution (`%space_var%` -> `' '`) and inline payload variable substitution reconstructing cleartext commands in a single pass.
  - Preamble chaff and watermark elimination: reliably strips base64 attribution comments (`:: VGhpcyBmaWxlIHdhcyBvYmZ1c2NhdGVk...`), seed bootstrap definitions, and dead alphabet store statements to produce clean, legible scripts.
  - Multi-indicator heuristic signature detection (`detect_oxidizer_signatures`) calculating evasion confidence scores and reporting architectural tags (`base64_watermark`, `zero_literal_bootstrap_seed`, `alphabet_definitions_count`, `high_percent_density`).
  - Cryptographic in-memory symbol table wiping (`zeroize_dict`) overwriting parsed dictionaries and buffers prior to garbage collection.
- **Dedicated 0xidiz3r Verification Suite (`tests/test_oxidizer.py`)**:
  - Added 10 comprehensive unit tests covering canonical watermarked scripts, watermark-stripped malware evasion variants, chained single-line bootstraps, GoodChars variable symbol handling, literal percent escapes, and end-to-end multi-pass pipeline integration (expanding test suite to 85 tests).
- **Toolchain Package Configuration (`package.json`)**:
  - Added root package configuration for unified test verification and repository asset tooling.

### Changed
- Integrated 0xidiz3r zero-literal bootstrap resolution into the core convergence loop (`deobfuscator/core.py`, `deobfuscate_script`, `deobfuscate_bytes`) via `enable_oxidizer=True`.
- Brought standalone engine (`src/deobfuscator_engine.py`) into parity with 0xidiz3r normalization passes.
- CLI toolchain updated with `--no-oxidizer` / `--no-0xidiz3r` flags and structured 0xidiz3r forensic telemetry reporting in verbose mode.
- Synchronized architecture mapping guide (`scripts/ARCHITECTURE_MAP.md`) and package versioning.

## [1.3.0] - 2026-10-13

### Added
- **Somalifuscator Caesar Inversion & Array Normalization Engine (`deobfuscator/somalifuscator.py`)**:
  - Statistical consensus solver (`solve_caesar_rotation`) determining the Caesar rotation value $k \in [0, 25]$ across candidate variable/character pairs with noise rejection.
  - Full bidirectional alphabet reconstruction (`infer_and_complete_caesar_table`) capable of synthesizing all 52 lowercase and uppercase (`var1=CHAR`) letter mappings from sparse partial definitions.
  - Automated single-pass `for /l` wrapper loop decomposition (`unwrap_somalifuscator_loops`) that extracts inner assignments and purges loop overhead from active execution lines.
  - Shuffled character array resolution (`extract_kdot_shuffled_array`, `resolve_kdot_slicing`) handling variable whitespace and arbitrary negative/positive slice bounds.
  - Targeted chaff and decoy pruning (`strip_somalifuscator_chaff`) neutralizing anti-triage headers (`>nul 2>&1 && exit ...`), `%TO_SCRAMBLE_PLZ%` markers, and dead dictionary definitions.
  - Memory zeroization (`zeroize_dict`) cryptographically overwriting substitution tables and temporary forensic buffers prior to release.
- **Dedicated Somalifuscator Verification Suite (`tests/test_somalifuscator.py`)**:
  - Added 12 comprehensive unit tests covering rotation solving, table synthesis, loop unrolling, array indexing, and end-to-end deobfuscation (expanding test suite to 75 tests).
- **GitHub Actions CI Workflow (`.github/workflows/ci.yml`)**:
  - Multi-version Python CI pipeline (3.10, 3.11, 3.12) running unit tests and benchmark suite on every push and pull request.

### Changed
- Expanded default Windows environment variable table with `DRIVERDATA` (`C:\Windows\System32\Drivers\DriverData`) and `COMMONPROGRAMW6432` (`C:\Program Files\Common Files`).
- Synchronized standalone deobfuscator engine (`src/deobfuscator_engine.py`) with Somalifuscator normalization passes and extended environment variables.
- CLI toolchain updated with `--no-somalifuscator` flag and structured Somalifuscator forensic telemetry output in verbose mode.

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
