# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  - 9 comprehensive unit tests verifying suite integrity, metrics schema, filtering, entropy computation, and CLI JSON export.

### Changed
- Expanded `DEFAULT_ENV` variable table with common Windows OS environment paths (`temp`, `tmp`, `appdata`, `localappdata`, `userprofile`, `username`, `os`, `systemdrive`).
- Synchronized engine pipeline across both `deobfuscator/core.py` and `src/deobfuscator_engine.py`.

### Fixed
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
