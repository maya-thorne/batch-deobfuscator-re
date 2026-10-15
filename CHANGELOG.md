# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.13.0] - 2026-10-15

### Added
- **batobfuscate-machine1337 Fake Header Neutralizer & Original Batch Recovery (`deobfuscator/machine1337.py`)**:
  - Heuristic signature detection (`detect_machine1337_signatures`): classifies machine1337 fake headers and obfuscation artifacts across 5 indicators (multi-BOM sequence, CJK Chinese transcoded glyphs, inline caret spam, `&cls` preamble masking, and decoy header bytes) with quantitative confidence scoring.
  - Multi-BOM binary header stripping (`strip_machine1337_header`, `neutralize_machine1337_headers`): identifies and strips composite UTF-16LE double-BOM patterns (`FF FE 26 63 6C 73 0D 0A FF FE 0A 0D`, CRLF, LF, Big-Endian variants) and corrupted UTF-8 replacement byte sequences (`\xef\xbf\xbd\xef\xbf\xbd&cls...`) without misclassifying single-BOM formats like BatCloak.
  - CJK Chinese pseudo-text transcode recovery (`recover_cjk_transcoded_batch`): detects batch files incorrectly decoded by UTF-16LE editors (yielding glyphs such as `挦獬਍`), re-encodes to UTF-16LE binary bytes, strips the header trap, and cleanly reconstructs the original 8-bit ASCII batch script.
  - Inline caret unescaping (`unescape_machine1337_carets`): unescapes redundant caret escape characters (`^`) outside quoted string literals while preserving escaped quotes and special control characters.
  - Error suppression de-masking (`strip_cls_preamble`): purges `&cls & ` and `@cls & ` preambles used to mask parse error messages when batch scripts execute in `cmd.exe`.
  - In-memory cryptographic buffer sanitization (`zeroize_bytes`, `zeroize_dict`): securely wipes binary header buffers, intermediate decodes, and forensic telemetry dictionaries prior to deallocation.
  - `Machine1337Normalizer` production class exposing clean object-oriented normalization API with custom environment support.
- **Dedicated Telemetry Module (`deobfuscator/telemetry.py`)**:
  - Extracted telemetry collection, aggregation, formatting, and memory wiping logic from `deobfuscator/core.py` into a dedicated submodule to maintain strict codebase modularity (<700 lines).
- **Dedicated machine1337 Verification Suite (`tests/test_machine1337.py`)**:
  - Added 14 comprehensive unit and integration tests covering multi-BOM stripping (CRLF, LF, Big-Endian), corrupted UTF-8 replacement headers, CJK transcode recovery, caret unescaping, preamble de-masking, signature detection (positive/negative), memory zeroization, class interface methods, and end-to-end `BatchDeobfuscator` pipeline convergence (expanding the test suite to 244 tests).

### Changed
- Integrated machine1337 normalization into the core multi-pass convergence pipeline (`deobfuscator/core.py`, `deobfuscate_script`, `deobfuscate_bytes`) via `enable_machine1337=True` (executing pre-convergence in Step 0.55).
- Updated standalone engine (`src/deobfuscator_engine.py`) with machine1337 normalization passes and parity.
- Extended CLI toolchain (`deobfuscator/cli.py`) with `--no-machine1337` flag and verbose telemetry reporting for detected indicators, stripped headers, CJK transcoded recoveries, and unescaped carets.
- Synchronized architecture mapping guide (`scripts/ARCHITECTURE_MAP.md`) and bumped package version across `package.json`, `pyproject.toml`, and `deobfuscator/__init__.py` to v1.13.0.

### Fixed
- **BatCloak Single-BOM False Positive Prevention**: Constrained `is_machine1337_header` byte matching to require trailing double-BOM signatures or specific corrupted UTF-8 headers, ensuring 8-byte BatCloak single-BOM scripts remain intact for BatCloak-specific processing.
- **Quoted Literal Preservation in Caret Unescaper**: Added quote-state tracking to `unescape_machine1337_carets` to ensure caret characters inside string literals (`"..."`) are preserved without corruption.

## [1.12.0] - 2026-10-14

### Added
- **BatchToApp / DosX Native Wrapper & Operator Deobfuscation Engine (`deobfuscator/batchtoapp.py`)**:
  - Heuristic signature detection (`detect_batchtoapp_signatures`): classifies BatchToApp and DosX wrapper patterns across 6 indicators (wrapper header `@shift /0`, exit routine `:b2a_ExitProcess`, character noise slicing, mutation jump block, operator variables, and fake labels) with quantitative confidence scoring.
  - Static PE forensics and embedded batch extraction (`extract_embedded_batch_from_pe`, `inspect_batchtoapp_pe`): triages .NET CLR executables without executing untrusted code, extracts DeflateStream resources matching RFC 1951 (-15 wbits) with fallback heuristic scanners, decodes CP866 / UTF-8 / Latin-1 payloads, and reports application GUID, window visibility, and anti-tamper filesystem flags.
  - Character noise slicing neutralization (`strip_batchtoapp_noise_slices`): inverts `ObfuscateString` single-character variable slices (`^c%path:~40000,-40000%`) and joins caret line continuations (`^\r\n` / `^\n`).
  - Mutation block & binary junk unwrapping (`strip_batchtoapp_mutation_block`): detects and prunes dead mutation jump preambles (`@goto <label> ... binary junk ... @exit /b ... :<label>`).
  - Operator variable mapping & closing bracket resolution (`resolve_batchtoapp_operators`): harvests operator dictionaries (`%guard% @set <op_var>=^\n<op>`), inverts commands in script body, resolves closing bracket variable (`@set <bracket_var>=^)`), and strips declaration boilerplate.
  - Fake label pruning (`prune_batchtoapp_fake_labels`): prunes unreferenced `:label_0x[0-9a-f]{8}` decoy labels inserted by `AddFakeLabels` while preserving valid execution targets.
  - Wrapper header & exit routine normalization (`normalize_batchtoapp_headers`): removes `@shift /0` preamble and `:b2a_ExitProcess` wrapper footer.
  - In-memory cryptographic buffer sanitization (`zeroize_dict`, `zeroize_bytes`): securely overwrites parsed operator tables, bytearrays, and forensic dictionaries prior to deallocation.
  - `BatchToAppNormalizer` production class exposing clean object-oriented normalization API with custom environment support.
- **Dedicated BatchToApp Verification Suite (`tests/test_batchtoapp.py`)**:
  - Added 32 comprehensive unit and integration tests covering Deflate decompression, noise slicing stripping, mutation block unwrapping, operator mapping resolution, fake label pruning, header normalization, anti-tamper guards, dynamic jump dispatches, word-boundary preservation, NUL byte rejection, positive/negative signature detection, non-PE triage, synthetic BatchToApp PE generation and extraction, memory zeroization, class interface methods, and full `BatchDeobfuscator` pipeline convergence (expanding the test suite to 230 tests).

### Changed
- Integrated BatchToApp normalization into the core multi-pass convergence pipeline (`deobfuscator/core.py`, `deobfuscate_script`, `deobfuscate_bytes`) via `enable_batchtoapp=True` (executing pre-convergence in Step 0.72 and post-convergence in Step 4.95).
- Added automatic PE embedded batch extraction in `deobfuscate_bytes()` when given PE executable bytes.
- Updated standalone engine (`src/deobfuscator_engine.py`) with BatchToApp normalization passes and parity.
- Extended CLI toolchain (`deobfuscator/cli.py`) with `--no-batchtoapp` / `--no-dosx` flags, automated PE triage extraction on `.exe` inputs, and verbose telemetry reporting for detected indicators, stripped noise slices, unwrapped mutation blocks, resolved operators, pruned fake labels, and extracted PE forensics metadata (`meta["batchtoapp_pe"]`).
- Synchronized architecture mapping guide (`scripts/ARCHITECTURE_MAP.md`) and bumped package version across `package.json`, `pyproject.toml`, and `deobfuscator/__init__.py` to v1.12.0.

### Fixed
- **Anti-Tamper Temp Directory Header Guard Stripping**: Resolved fatal dangling jump where BatchToApp header normalizer stripped footer label `:b2a_ExitProcess` without removing the matching `@if not "%~dp0" == "%TEMP%\" goto b2a_ExitProcess` header guard, by expanding `normalize_batchtoapp_headers` and signature tracking to purge the check.
- **Subroutine False-Positive Preservation in Mutation Stripper**: Constrained mutation block regex in `strip_batchtoapp_mutation_block` from generic `[a-zA-Z0-9_]+` to signature `label_0x[0-9a-fA-F]{8}`, preventing accidental deletion of legitimate user functions.
- **Fake Label Dynamic Jump Target Preservation**: Added wildcard prefix/suffix matching (`goto :label_0x12%stage%`) to `prune_batchtoapp_fake_labels`, preventing premature pruning of active labels targeted by runtime dynamic dispatches.
- **Set Variable and Comment False-Positive Exclusion**: Tokenized command lines across `&`/`|` and excluded `set` assignment targets and comments (`REM`, `::`) from label reference harvesting, ensuring truly unreferenced fake labels are pruned cleanly.
- **PE Candidate Scoring & Alignment Robustness**: Added NUL byte (`\x00`) rejection to heuristic scoring, upgraded resource table scanner to select the maximum scoring candidate (`max(c[0]) >= 20`) with 4-byte alignment, avoiding redundant and fragile full-binary scans.


## [1.11.0] - 2026-10-14


### Added
- **Exorcism Subroutine Label Jump & Control Flow Normalization Engine (`deobfuscator/exorcism.py`)**:
  - Multi-indicator heuristic signature detection (`detect_exorcism_signatures`): identifies non-sequential execution graphs and control flow obfuscation across 6 indicators (unconditional goto hopping, spaghetti jumps, trampolines, opaque predicates, leaf subroutine calls, and command dispatch chaining) with quantitative confidence scoring.
  - Trampoline jump chain flattening (`flatten_jump_trampolines`): collapses intermediate label hops (`:hop1 goto :hop2 \n :hop2 goto :dest`) directly to target labels, resolving transitive pointer chains with cycle detection.
  - Opaque predicate normalizer (`normalize_opaque_predicates`): evaluates static constant conditions (`if 1==1`, `if 1 EQU 1`, `if "%x%"=="%x%"`, `if 1==0`, `if not 1==1`, `/i` case-insensitivity) to unwrap true branches and discard dead conditional blocks, while strictly preserving runtime dynamic variables (`%errorlevel%`, `%~1`, `%var%`).
  - Leaf subroutine inlining (`inline_subroutines`): inlines non-recursive leaf `call :sub [args]` routines with parameter substitutions (`%~1`, `%1`, `%*`, `%~2`..`%~9`) and strips subroutine return boilerplate (`goto :eof`, `exit /b`).
  - Control flow graph linearization (`linearize_control_flow`): reconstructs natural linear execution paths from entry points following unconditional gotos and fall-throughs, reordering scattered label blocks and pruning redundant fall-through gotos.
  - Dead block & chaff label pruning (`prune_unreachable_blocks`): eliminates unreachable decoy blocks and labels with in-degree 0 that cannot be reached from any valid execution path.
  - Exorcism runtime dispatch trace emulation (`emulate_exorcism_dispatch`, `export_exorcism_trace`): simulates `cmd.exe!FindFixAndRun` command dispatch, normalizing chained commands (`&`, `&&`, `||`) and exporting structured JSON traces compatible with Exorcism `cmd_hook.json`.
  - In-memory cryptographic buffer sanitization (`zeroize_dict`, `zeroize_bytes`): securely overwrites parsed label tables, CFG nodes, and trace data in memory.
  - `ExorcismNormalizer` production class exposing clean object-oriented normalization API with custom environment support.
- **Dedicated Exorcism Verification Suite (`tests/test_exorcism.py`)**:
  - Added 20 comprehensive unit and integration tests covering signature detection (positive/negative), trampoline jump flattening (simple/multi-hop/cycle-resistant), opaque predicate evaluation (true/false/else/case-insensitive/identical strings), leaf subroutine inlining, non-leaf call preservation, control flow linearization and redundant goto pruning, unreachable block pruning, dispatch trace emulation, JSON trace export, memory zeroization, class interface wrapper methods, and full `BatchDeobfuscator` pipeline convergence (expanding the test suite to 195 tests).

### Changed
- Integrated Exorcism normalization into the core multi-pass convergence pipeline (`deobfuscator/core.py`, `deobfuscate_script`, `deobfuscate_bytes`) via `enable_exorcism=True` (executing pre-convergence in Step 0.73 and post-convergence in Step 4.9).
- Updated standalone engine (`src/deobfuscator_engine.py`) with Exorcism normalization passes and parity.
- Extended CLI toolchain (`deobfuscator/cli.py`) with `--no-exorcism` flag and verbose telemetry reporting for detected indicators, collapsed trampolines, normalized predicates, inlined subroutines, pruned fall-through gotos, and dead blocks.
- Synchronized architecture mapping guide (`scripts/ARCHITECTURE_MAP.md`) and bumped package version across `package.json`, `pyproject.toml`, and `deobfuscator/__init__.py` to v1.11.0.

## [1.10.0] - 2026-10-14

### Added
- **PandaCrypter & Certutil Multi-Stage Stager Deobfuscator & Forensic Emulation Engine (`deobfuscator/pandacrypter.py`)**:
  - Heuristic signature detection (`detect_pandacrypter_signatures`, `detect_certutil_signatures`): classifies PandaCrypter and advanced Certutil/PowerShell batch stager patterns across 8 distinct evasion indicators (colon padding, self-extraction, decode, decodehex, echo redirection, comment payloads, AMSI bypass) with quantitative confidence scoring.
  - Multi-format Certutil hexadecimal static emulation (`emulate_certutil_decodehex`): converts hexadecimal byte streams into cleartext or binary payloads without invoking Windows command processes, supporting mixed hex pairs, raw continuous hex, dash-delimited sequences, comma-separated `0x` byte arrays, and formatted memory dumps with address offsets and right-hand ASCII previews (Formats 0, 4, 11, and 12).
  - Certutil Base64 static emulation (`emulate_certutil_decode`): safely extracts and decodes Base64 payloads, filtering certificate wrapper headers (`-----BEGIN CERTIFICATE-----`), inline comment tags (`::B64:`, `::PAYLOAD:`), and handling whitespace or irregular padding.
  - PandaCrypter colon padding neutralization (`strip_pandacrypter_colon_padding`): eliminates large repetitive colon noise blocks (`:::...`) inserted to distort file entropy and bypass statistical scanners, while strictly preserving legitimate batch labels (`:label`, `:EOF`).
  - Virtual file staging and redirection tracker (`trace_virtual_staged_files`): tracks files constructed across execution flows via `echo >` / `echo >>` pipelines and `findstr` extractions targeting `%~f0`, resolving target file paths against environment mappings.
  - Staged payload inlining and PE binary triage (`emulate_certutil_staging`): automatically intercepts `certutil -decode` and `certutil -decodehex` command lines, decodes staged inputs, inlines recovered batch scripts or commands directly at subsequent execution points (`call`, `cmd /c`), and safely classifies PE executables (`MZ` header) with cryptographic SHA-256 hashes and size telemetry.
  - In-memory cryptographic buffer sanitization (`zeroize_dict`, `zeroize_bytes`): securely overwrites parsed staging buffers, decoded bytearrays, and forensic dictionaries prior to deallocation.
  - `PandaCrypterNormalizer` production class exposing clean object-oriented normalization API with custom environment support.
- **Dedicated PandaCrypter Verification Suite (`tests/test_pandacrypter.py`)**:
  - Added 19 comprehensive unit and integration tests covering colon padding stripping, Certutil command signature detection, PandaCrypter heuristic triage, spaced/continuous/dash/comma hex decoding, address-offset hex dump parsing, Base64 certificate decoding, comment extraction, virtual file echo tracing, end-to-end hex and Base64 staging pipeline inlining, binary PE payload classification, memory zeroization, class interface wrapper methods, and full `BatchDeobfuscator` pipeline convergence (expanding the test suite to 174 tests).

### Changed
- Integrated PandaCrypter normalization into the core multi-pass convergence pipeline (`deobfuscator/core.py`, `deobfuscate_script`, `deobfuscate_bytes`) via `enable_pandacrypter=True` (executing pre-convergence in Step 0.74 and post-convergence in Step 4.8).
- Updated standalone engine (`src/deobfuscator_engine.py`) with PandaCrypter normalization passes and parity.
- Extended CLI toolchain (`deobfuscator/cli.py`) with `--no-pandacrypter` / `--no-certutil` flags and verbose telemetry reporting for detected indicators, stripped colon lines, and decoded staged payload telemetry.
- Synchronized architecture mapping guide (`scripts/ARCHITECTURE_MAP.md`) and bumped package version across `package.json`, `pyproject.toml`, and `deobfuscator/__init__.py` to v1.10.0.

## [1.9.0] - 2026-10-13

### Added
- **BatchShield Virtual Symbol Table & Compound Environment Deobfuscation Engine (`deobfuscator/batchshield.py`)**:
  - Heuristic signature detection (`detect_batchshield_signatures`): accurately flags BatchShield obfuscation patterns, static OS variable indexing (`%COMSPEC:~-7,3%`, `%PATH:~0,1%`, `%SYSTEMROOT:~...%`), high-entropy randomized symbol variable declarations, dense multi-token concatenations, and interleaved dummy noise tokens with confidence scoring.
  - Shannon entropy computation (`calculate_shannon_entropy`): calculates informational entropy per variable identifier to detect algorithmically randomized symbol names ($H \ge 2.3$).
  - Virtual symbol dictionary harvesting and topological convergence (`harvest_batchshield_symbols`): extracts assignments across line boundaries and parenthesized blocks, evaluating chained definitions, variable slicing, and dynamic replacements with circular dependency protection.
  - Compound environment variable chain resolution (`resolve_batchshield_env_chains`): recursively evaluates multi-tier environment variable chains and expands virtual symbols into their concrete characters or commands.
  - Selective dummy noise variable elimination (`strip_batchshield_dummy_noise`): strips uninitialized random dummy noise variables (`%random_chaff%`) interleaved within command names while strictly protecting valid defined variables, dynamic system variables (`%RANDOM%`, `%ERRORLEVEL%`, `%CD%`, `%DATE%`, `%TIME%`), batch parameters (`%0`..`%9`, `%*`, `%~dp0`), and `for` loop parameters (`%%i`).
  - Dead symbol definition pruning (`eliminate_batchshield_chaff`): automatically removes obfuscation table definitions once all references in payload commands have been inlined, leaving clean cleartext commands.
  - In-memory cryptographic buffer sanitization (`zeroize_dict`, `zeroize_bytes`): securely overwrites parsed symbol tables and decrypted buffers prior to garbage collection.
  - `BatchShieldNormalizer` class exposing clean object-oriented normalization API with custom environment support.
- **Dedicated BatchShield Verification Suite (`tests/test_batchshield.py`)**:
  - Added 13 comprehensive unit tests covering Shannon entropy calculation, clean vs obfuscated signature triage, positive/negative slice and substitution semantics, compound chain resolution, circular dependency safety, selective noise stripping, dead chaff elimination, memory zeroization, class interface wrapper methods, and benchmark Corpus 08 parity (expanding test suite to 155 tests).

### Changed
- Integrated BatchShield normalization into the core multi-pass convergence pipeline (`deobfuscator/core.py`, `deobfuscate_script`, `deobfuscate_bytes`) via `enable_batchshield=True` (executing pre-convergence in Step 0.76 and post-convergence in Step 4.7).
- Updated standalone engine (`src/deobfuscator_engine.py`) with BatchShield normalization passes and parity.
- Extended CLI toolchain (`deobfuscator/cli.py`) with `--no-batchshield` flag and verbose telemetry reporting for resolved symbol counts, compound chains, stripped noise tokens, and eliminated chaff statements.
- Synchronized architecture mapping guide (`scripts/ARCHITECTURE_MAP.md`) and bumped package version across `package.json`, `pyproject.toml`, and `deobfuscator/__init__.py` to v1.9.0.

## [1.8.0] - 2026-10-13

### Added
- **Batch-Encryption-DeCoder (BEDeCode) Runtime Stub Unpacker & PE Forensics Engine (`deobfuscator/bedecode.py`)**:
  - Multi-indicator heuristic signature detection (`detect_bedecode_signatures`): accurately identifies BatchEncryption symbol table definitions (`@set '=<alphabet>`), single-quote / symbol slicing expressions, dynamic substitution ciphers (`%VAR:old=new%`), and pre-seeded environment variable bootstrapping preambles with calculated confidence scoring.
  - Character mapping table extraction and normalization (`extract_bedecode_tables`): parses variable table assignments and resolves caret escape sequences (`clean_bedecode_escapes`) where `^^` and `^&` are sanitized and unescaped according to VB6 BEDeCode specifications.
  - Comprehensive slicing and substitution evaluation (`eval_batch_slice`, `eval_batch_subst`, `resolve_bedecode_slices`): natively evaluates both standard (`:~/offset`) and non-standard (`~/offset`) substring syntax, including negative offsets, compound length slices (`start,-end`, `-start,-end`, `-start,length`), and wildcard prefix replacements (`*old=new`).
  - Pre-seeded Windows environment bootstrapping (`resolve_env_bootstrapping`): dynamically resolves preambles referencing core operating system variables (`%ALLUSERSPROFILE%`, `%ProgramFiles%`, `%COMSPEC%`, `%SYSTEMROOT%`, etc.) to expose hidden password tables.
  - Multi-layer recursive onion unrolling (`unwrap_bedecode_inline_stub`): peels nested BatchEncryption protection layers iteratively, inlining character slices and eliminating dead preamble headers and table definitions upon complete resolution.
  - PE static self-extracting runtime stub triage (`inspect_bedecode_pe`): performs static binary analysis on compiled Batch-to-EXE wrappers, detecting VB6 MSVBVM60 ThunRTMain stubs (`BEDeCode.exe` / cnHopeStudio), parsing PE section layouts and overlay streams, and recovering embedded batch script payloads without executing untrusted binaries.
  - In-memory cryptographic buffer sanitization (`zeroize_dict`, `zeroize_bytes`): securely wipes extracted symbol tables and decrypted payload buffers prior to memory deallocation.
  - `BEDeCodeNormalizer` production class exposing clean `detect()`, `normalize()`, and `inspect_pe()` interfaces.
- **Dedicated BEDeCode Verification Suite (`tests/test_bedecode.py`)**:
  - Added 12 unit tests covering escape normalization, slicing expressions, dynamic substitution, environment bootstrapping, single-layer and multi-layer onion unrolling, PE static stub inspection, memory zeroization, class wrapper methods, and end-to-end engine integration (expanding test suite to 142 tests).

### Changed
- Integrated BEDeCode normalization into the core multi-pass convergence pipeline (`deobfuscator/core.py`, `deobfuscate_script`, `deobfuscate_bytes`) via `enable_bedecode=True` (executing pre-convergence in Step 0.77 and post-convergence in Step 4.6).
- Extended `PEBatchPackerForensics` (`src/pe_packer_forensics.py`) with `unpack_bedecode_runtime_stub()` to support static extraction and automatic deobfuscation of embedded batch scripts from PE executables.
- Synchronized standalone engine (`src/deobfuscator_engine.py`) with BEDeCode normalization passes.
- Updated CLI toolchain (`deobfuscator/cli.py`) with `--no-bedecode` flag and verbose telemetry reporting for BEDeCode analysis.
- Synchronized architecture mapping guide (`scripts/ARCHITECTURE_MAP.md`) and bumped package version to v1.8.0.

## [1.7.0] - 2026-10-13

### Added
- **Invoke-CradleCrafter PowerShell Download Stager Chunking Restoration Pipeline (`deobfuscator/cradlecrafter.py`)**:
  - Multi-indicator heuristic signature detection (`detect_cradle_signatures`): classifies CradleCrafter and Invoke-Stealth obfuscation patterns across 17 download cradle methods (Net.WebClient, BitsTransfer, WinHttp, ComObject, Invoke-WebRequest, IEX aliases, etc.) with calculated confidence scores.
  - Base64 stager extraction and decoding (`decode_base64_payload`): statically extracts `-EncodedCommand` / `-enc` payloads, validates wide-character null byte distributions to accurately distinguish UTF-16LE from UTF-8 without unicode decode corruption, and handles Deflate/zlib decompression streams.
  - Advanced PowerShell AST and token normalization (`normalize_powershell_stager`):
    - Format string operator resolution (`-f`) unpacking indexed replacement arrays (`"{1}{0}" -f 'B','A'`).
    - Character code array resolution unrolling `[char]` casts and pipeline byte transformations (`(-join (73,69,88|%{[char]$_}))`).
    - Substring and string reversal unrolling (`[-1..-N]`).
    - Identifier unmasking stripping backtick escape characters (`` `I`e`X ``).
    - Obfuscated IEX / execution alias normalization resolving `.(GCI Alias:\IE*)`, `.(gcm *iex*)`, and `$env:ComSpec`.
  - Stager chunking and cleartext conversion (`normalize_cradlecrafter`): normalizes `-enc <Base64>` stagers into transparent `-Command "..."` payloads, preserving script execution flow while exposing hidden logic.
  - Forensic telemetry extraction (`extract_cradle_telemetry`): analyzes reconstructed stagers to catalog extracted C2 URLs and destination download paths for incident response analysis.
  - Cryptographic in-memory buffer zeroization (`zeroize_dict`, `zeroize_bytes`): securely overwrites parsed payloads, decrypted byte arrays, and forensic metadata tables prior to memory release.
  - `CradleCrafterNormalizer` production class exposing clean `detect()` and `normalize()` interfaces.
- **Dedicated Invoke-CradleCrafter Verification Suite (`tests/test_cradlecrafter.py`)**:
  - Added 16 unit tests covering signature detection, Base64 UTF-16LE/UTF-8 discrimination, format string unrolling, character array reconstruction, reverse indexing, backtick identifier stripping, IEX alias expansion, telemetry extraction, in-memory zeroization, pipeline integration, and edge-case error tolerance (expanding test suite to 130 tests).

### Changed
- Integrated CradleCrafter normalization into the core convergence pipeline (`deobfuscator/core.py`, `deobfuscate_script`, `deobfuscate_bytes`) via `enable_cradlecrafter=True` (executing pre-convergence in Step 0.79 and post-convergence in Step 4.5).
- Brought standalone engine (`src/deobfuscator_engine.py`) into full parity with CradleCrafter normalization passes.
- Updated CLI toolchain (`deobfuscator/cli.py`) with `--no-cradlecrafter` flag and structured CradleCrafter forensic telemetry reporting in verbose mode.
- Fixed Python 3.10 and 3.11 runner compatibility by eliminating PEP 701 backslash-in-f-string syntax in `deobfuscator/abobus.py`.
- Synchronized architecture mapping guide (`scripts/ARCHITECTURE_MAP.md`) and bumped package version to v1.7.0.

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
