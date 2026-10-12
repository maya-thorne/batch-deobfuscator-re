# Project Roadmap

This document tracks shipped capabilities and future engineering milestones for batch-deobfuscator-re.

---

## Shipped Capabilities

- [x] **Fixed-Point Deobfuscator Engine** — Core deobfuscation loop, heuristic string normalization, and 10 unit tests.

---

## Planned Milestones

- [ ] **28-Sample Corpus Evaluation Harness** — Automated benchmark runner (eval_corpus_runner.py) with quantitative recovery scoring.
- [ ] **BatCloak Obfuscation Preprocessor** — BOM masking and randomized variable signature neutralization.
- [ ] **Somalifuscator Caesar Inversion** — Automated reverse arithmetic solver for shift-cipher batch blocks.
- [ ] **0xidiz3r Zero-Literal Extractor** — Heuristic unpacker for dynamic literal-less bootstrap routines.
