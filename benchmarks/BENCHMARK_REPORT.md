# Batch Deobfuscator 28-Corpus Benchmark Evaluation Report

**Verdict:** PASSED (Zero Regression)
**Mean Score:** `94.6 / 100.0` (A (Superior)) | **Pass Rate:** `100.0%` (28/28)

## Benchmark Summary

| Metric | Value |
|---|---|
| **Total Corpora** | `28` |
| **Passed** | `28` |
| **Failed** | `0` |
| **Mean Score** | `94.6` / 100.0 |
| **Grade** | `A (Superior)` |
| **Mean Passes** | `2.0` |
| **Symbols Resolved** | `45` |
| **Mean Clarity Index** | `88.6` / 100.0 |
| **Mean Compression** | `22.6%` |
| **Mean Latency** | `0.172 ms` |
| **Total Elapsed Time** | `6.1 ms` |

## Detailed Corpus Results

| ID | Corpus Name | Archetype | Difficulty | Passes | Latency | Clarity | Score | Status |
|:---:|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| `01` | **BatCloak** | Variable Shuffling & Dead Code Injection | Medium | `2` | `1.80ms` | `92.5` | `92.8` | **PASS** |
| `02` | **Somalifuscator** | Caesar Alphabet Slicing & Array Indexing | Hard | `2` | `0.23ms` | `92.5` | `96.3` | **PASS** |
| `03` | **0xidiz3r** | Reversible Variable Alphabet Substitution | Medium | `2` | `0.16ms` | `96.2` | `95.4` | **PASS** |
| `04` | **Abobus** | Unicode Noise & Caret Escaped Identifiers | Medium | `2` | `0.07ms` | `90.9` | `94.9` | **PASS** |
| `05` | **Invoke-DOSfuscation** | Daniel Bohannon Environment Slicing & Caret Interleaving | Advanced | `2` | `0.04ms` | `85.0` | `97.0` | **PASS** |
| `06` | **Invoke-CradleCrafter** | Download Cradle Environment Splicing | Hard | `2` | `0.12ms` | `92.5` | `95.0` | **PASS** |
| `07` | **Batch-Encryption-DeCoder** | Dynamic String Replacement (%VAR:old=new%) | Medium | `2` | `0.20ms` | `100.0` | `97.1` | **PASS** |
| `08` | **BatchShield** | Static OS Variable Indexing & Offset Extraction | Hard | `2` | `0.09ms` | `92.5` | `95.4` | **PASS** |
| `09` | **PandaCrypter** | Uninitialized Dummy Variable Injection | Easy | `2` | `0.05ms` | `77.5` | `95.4` | **PASS** |
| `10` | **Exorcism** | Sequential Hooking & Dispatch Chaining | Easy | `2` | `0.09ms` | `92.5` | `93.8` | **PASS** |
| `11` | **BatchToApp** | Native Wrapper String Encapsulation | Medium | `2` | `0.10ms` | `89.1` | `93.8` | **PASS** |
| `12` | **batobfuscate-machine1337** | BOM Masking & Inline Caret Scrambling | Medium | `2` | `0.06ms` | `85.0` | `94.5` | **PASS** |
| `13` | **CMD-DeObfuscator** | Multi-Token Caret & Boundary Normalization | Easy | `2` | `0.03ms` | `85.0` | `95.8` | **PASS** |
| `14` | **simple-batch-obfuscator** | Character-Level Random Variable Fragment Infiltration | Hard | `2` | `0.08ms` | `84.1` | `96.9` | **PASS** |
| `15` | **JSBatchDeobfuscator** | JavaScript Transpiled Chained SET Tokens | Medium | `2` | `0.11ms` | `85.0` | `92.6` | **PASS** |
| `16` | **BatchStealer-Takaovi** | Credential Harvester Caret Masking | Medium | `2` | `0.06ms` | `81.2` | `93.9` | **PASS** |
| `17` | **BatchObfuscator-BiggerDABOSS** | Repetitive Empty Quote Pairs with Undefined Variables | Hard | `2` | `0.05ms` | `85.0` | `97.0` | **PASS** |
| `18` | **BatchObfuscator-EmenstaNougat** | Multi-Line & Command Chaining & Variable Dereference | Medium | `2` | `0.17ms` | `100.0` | `93.5` | **PASS** |
| `19` | **BatchObfuscator-wirebits** | Sequential Single-Character Variable Splicing | Medium | `2` | `0.25ms` | `82.2` | `93.2` | **PASS** |
| `20` | **batchalchemy** | AST Parser Validation & Nested Concatenation | Medium | `2` | `0.16ms` | `92.5` | `94.5` | **PASS** |
| `21` | **BatchDeobfuscator-CrowTheBest** | Chained Single-Line @set Table Dereferencing | Medium | `2` | `0.14ms` | `90.4` | `93.7` | **PASS** |
| `22` | **assemblyline-batchdeobfuscator** | Automated Sandbox Multi-Pass Variable Resolution | Medium | `2` | `0.10ms` | `92.5` | `92.8` | **PASS** |
| `23` | **Remcos-Rat-Batch-Deobfuscator** | RAT Dropper Short Alias & Registry Persistence | Medium | `2` | `0.08ms` | `84.6` | `92.3` | **PASS** |
| `24` | **Out-FINcodedCommand** | APT FIN7 Network Reconnaissance Construction | Medium | `2` | `0.07ms` | `89.3` | `92.4` | **PASS** |
| `25` | **Bat2Exe** | Multi-Stage s-e-t Bootstrap & Binary Dehoisting | Hard | `2` | `0.16ms` | `82.0` | `93.6` | **PASS** |
| `26` | **01_env_slicing** | OS Environment Slicing & Dynamic Assembly | Advanced | `2` | `0.16ms` | `89.6` | `97.5` | **PASS** |
| `27` | **02_caret_delimiters** | Caret Interleaving & Comma/Semicolon Delimiters | Medium | `2` | `0.08ms` | `79.1` | `93.6` | **PASS** |
| `28` | **05_certutil_hex** | Inline Base64 / Hex Extraction Pipeline | Advanced | `2` | `0.10ms` | `92.5` | `92.8` | **PASS** |