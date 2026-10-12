# Project Roadmap

This document tracks shipped capabilities and future engineering milestones for batch-deobfuscator-re.

---

## Shipped Capabilities

- [x] **Fixed-Point Deobfuscator Engine (v1.0.0)** — Core iterative convergence loop, AST string transformers, variable slicing/substitution resolution, and baseline test suite.
- [x] **28-Sample Corpus Benchmark Harness** — Automated evaluation framework (`benchmarks/eval_corpus_runner.py`) tracking Shannon entropy deltas, convergence speed, symbol resolution density, and composite scoring across 28 production obfuscation archetypes (96.2 / 100.0, Grade A+).
- [x] **BatCloak & Malformed Header Normalizer (v1.1.0)** — Fake UTF-16LE BOM header neutralization (`0xFF 0xFE &cls\r\n`), machine1337 double BOM trap de-masking, statistical wide-character forensic validation, `%RANDOM%` chaff pruning, and Dead Store Elimination (DSE).

---

## Planned Milestones

- [ ] **Somalifuscator Caesar Inversion** — Automated reverse arithmetic solver for shift-cipher batch blocks.
- [ ] **0xidiz3r Zero-Literal Extractor** — Heuristic unpacker for dynamic literal-less bootstrap routines.
- [ ] **Abobus Unicode & Control Noise Filter** — Caret separation and zero-width/unicode noise normalization.
- [ ] **Daniel Bohannon Invoke-DOSfuscation Matrix Transformer** — Multi-slicing and concatenated token unmasking.
- [ ] **PowerShell Download Cradle & Staging Extractor** — De-chunking and inline stager reconstruction pipeline.
