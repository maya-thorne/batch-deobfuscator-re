# Project Roadmap

This document tracks shipped capabilities and future engineering milestones for batch-deobfuscator-re.

---

## Shipped Capabilities

- [x] **Fixed-Point Deobfuscator Engine (v1.0.0)** — Core iterative convergence loop, AST string transformers, variable slicing/substitution resolution, and baseline test suite.
- [x] **28-Sample Corpus Benchmark Harness** — Automated evaluation framework (`benchmarks/eval_corpus_runner.py`) tracking Shannon entropy deltas, convergence speed, symbol resolution density, and composite scoring across 28 production obfuscation archetypes (96.2 / 100.0, Grade A+).
- [x] **BatCloak & Malformed Header Normalizer (v1.2.0)** — Fake UTF-16LE BOM header neutralization (`0xFF 0xFE &cls\r\n`), machine1337 double BOM trap de-masking, statistical wide-character forensic validation, `%RANDOM%` chaff pruning, and Dead Store Elimination (DSE).
- [x] **Somalifuscator Caesar Inversion & Array Normalizer (v1.3.0)** — Statistical consensus solver for Caesar rotation shifts ($k$), full 52-character alphabet synthesis from partial matrices, single-pass `for /l` loop unwrapping, `KDOT` shuffled array slicing, `%TO_SCRAMBLE_PLZ%` and anti-triage decoy header stripping, and memory zeroization.
- [x] **0xidiz3r Zero-Literal Bootstrap & Alphabet Normalizer (v1.4.0)** — Three-stage primitive seed resolver (`set`, `space`, `equals`), full reversible variable alphabet inversion, literal percent escape (`%%` -> `%`) handling, base64 watermark (`VGhpcyBmaWxl...`) and dead alphabet store elimination (DSE), and cryptographic dictionary memory wiping.
- [x] **Abobus Unicode Noise, Decoy & Trap Normalizer (v1.5.0)** — Zero-width character & LTR/RTL mark filtering, Kaomoji, Arabic decoy glyph, and Chinese warning string variable elimination, caret quote (`^"`) and keyword unescaping, multi-stage Chinese substring dictionary extraction and `%public%` slicing inversion, `random_if` opaque predicate and anti-analysis trap pruning, and cryptographic dictionary zeroization.
- [x] **Invoke-DOSfuscation Bohannon Static Transformer (v1.6.0)** — Complete static deobfuscation for Daniel Bohannon's Invoke-DOSfuscation techniques: Out-DosReversedCommand `for /L` reverse reconstruction loop unrolling (with arbitrary negative strides and character padding support), Out-DosFORcodedCommand `for %A in (...)` index array command reconstruction with sentinel detection, Out-EnvVarEncodedCommand advanced environment variable slicing (supporting negative offsets, explicit plus signs, embedded whitespace/tabs, and clamped boundaries), delayed expansion (`!var!`) and substring substitution (`!var:old=new!`), Bohannon delimiter noise cluster (`,;,`, `;,;`, etc.) normalization, heuristic signature detection, and in-memory cryptographic buffer zeroization.
- [x] **Invoke-CradleCrafter & PowerShell Stager Deobfuscator (v1.7.0)** — Complete static deobfuscation for Daniel Bohannon's Invoke-CradleCrafter and PowerShell download cradles: Base64 UTF-16LE EncodedCommand (`-enc`, `-encodedcommand`, `-e`) decoding and payload normalization, inline `[Convert]::FromBase64String` decoding and Deflate/zlib decompression, format operator (`-f`) reordering and inlining, integer character code arrays (`[char]73+[char]69+[char]88`, `(-join (73,69,88|%{[char]$_}))`) casting, string reversal (`[-1..-N]`) resolution, PowerShell identifier backtick unmasking, obfuscated IEX aliases (`.(GCI Alias:\IE*)`, `.(gcm *iex*)`, `$env:ComSpec`) normalization, cradle method classification (WebClient, IWR, IRM, BITS, Certutil), target URL and destination file forensic extraction, and in-memory cryptographic buffer zeroization.
- [x] **Batch-Encryption-DeCoder (BEDeCode) Runtime Stub Unpacker & PE Forensics (v1.8.0)** — Complete static unpacker for BatchEncryption and BEDeCode runtime wrappers: extraction of dynamic character mapping tables (`@set '=<alphabet>`), resolution of single-quote and special symbol slices (`%'~offset,len%`, `%':~offset,len%`), compound and negative slicing support, multi-layer recursive onion stub unrolling, automated Windows environment variable bootstrapping (`%ALLUSERSPROFILE%`, `%ProgramFiles%`, `%COMSPEC%`), dynamic string substitution (`%VAR:old=new%`) cipher synthesis, static PE triage for VB6 MSVBVM60 ThunRTMain stubs (`BEDeCode.exe`) and embedded batch payload recovery from sections, resources, and overlays, and in-memory cryptographic memory zeroization.

---

## Planned Milestones

- [ ] **BatchShield Dynamic Symbol Table Solver** — Automated resolution for high-entropy obfuscation dictionaries.
- [ ] **PandaCrypter Hex & Certutil Decoding Pipeline** — Static Certutil `-decode` and multi-stage payload extraction.
- [ ] **Windows 11 AMSI Inline Inspection Harness** — In-memory emulation and virtual AMSI buffer verification testbed.
- [ ] **High-Throughput Asynchronous Worker Pool** — Multi-threaded forensic pipeline for processing enterprise script corpora at scale.
- [ ] **Native Rust Fixed-Point AST Acceleration Core** — PyO3 bindings for sub-millisecond AST processing on megabyte-scale scripts.
- [ ] **LLVM/Rust Batch-to-Binary Static Forensics Pipeline** — Static extraction and AST reverse engineering for batch payloads embedded in compiled native binaries (Rust, Go, Nim).
- [ ] **eBPF/ETW Inline Batch Execution Telemetry Harness** — Real-time telemetry decoder interfacing with Microsoft-Windows-CommandProcessor ETW channels.
- [ ] **PowerShell 7+ Pwsh Cross-Platform Stager Forensics** — Multi-architecture shell stager and triple-encoding static analyzer.
- [ ] **Hypervisor Virtual Registry Batch Persistence Mapper** — Static extractor and forensic mapper for RunKey and ScheduledTask persistence mechanisms in batch scripts.
- [ ] **Windows Kernel Minifilter & Directory Traversal Evasion Detector** — NTFS Alternate Data Streams (ADS) and path traversal evasion script extraction.
- [ ] **Fuzzy Hash & Cryptographic Entropy Histogram Classifier** — Automated clustering of batch malware variants using SSDEEP and TLSH.
