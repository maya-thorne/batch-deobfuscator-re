# Project Roadmap

This document tracks shipped capabilities and future engineering milestones for batch-deobfuscator-re.

---

## Shipped Capabilities

- [x] **Fixed-Point Deobfuscator Engine (v1.0.0)** — Core iterative convergence loop, AST string transformers, variable slicing/substitution resolution, and baseline test suite.
- [x] **28-Sample Corpus Benchmark Harness** — Automated evaluation framework (`benchmarks/eval_corpus_runner.py`) tracking Shannon entropy deltas, convergence speed, symbol resolution density, and composite scoring across 28 production obfuscation archetypes (96.2 / 100.0, Grade A+).
- [x] **BatCloak & Malformed Header Normalizer (v1.2.0)** — Fake UTF-16LE BOM header neutralization (`0xFF 0xFE &cls\r\n`), machine1337 double BOM trap de-masking, statistical wide-character forensic validation, `%RANDOM%` chaff pruning, and Dead Store Elimination (DSE).
- [x] **Somalifuscator Caesar Inversion & Array Normalizer (v1.3.0)** — Statistical consensus solver for Caesar rotation shifts ($k$), full 52-character alphabet synthesis from partial matrices, single-pass `for /l` loop unwrapping, `KDOT` shuffled array slicing, `%TO_SCRAMBLE_PLZ%` and anti-triage decoy header stripping, and memory zeroization.

---

## Planned Milestones

- [ ] **0xidiz3r Zero-Literal Extractor** — Heuristic unpacker for dynamic literal-less bootstrap routines.
- [ ] **Abobus Unicode & Control Noise Filter** — Caret separation and zero-width/unicode noise normalization.
- [ ] **Daniel Bohannon Invoke-DOSfuscation Matrix Transformer** — Multi-slicing and concatenated token unmasking.
- [ ] **PowerShell Download Cradle & Staging Extractor** — De-chunking and inline stager reconstruction pipeline.
- [ ] **BEDeCode Native Self-Extracting Unpacker** — Embedded PE executable and batch inline stub extraction.
- [ ] **BatchShield Dynamic Symbol Table Solver** — Automated resolution for high-entropy obfuscation dictionaries.
- [ ] **PandaCrypter Hex & Certutil Decoding Pipeline** — Static Certutil `-decode` and multi-stage payload extraction.
- [ ] **Windows 11 AMSI Inline Inspection Harness** — In-memory emulation and virtual AMSI buffer verification testbed.
