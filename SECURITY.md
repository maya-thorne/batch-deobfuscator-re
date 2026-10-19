# Security Policy

## Supported Versions

Security updates are applied to the latest release series on the `main` branch.

| Version | Supported          |
| ------- | ------------------ |
| Latest (`1.x`) | :white_check_mark: |
| `< 1.0.0` | :x:                |

## Cryptographic & Memory Safety Invariants

1. **Key Material & Buffer Hygiene**: All passphrases, derived keys, intermediate KDF buffers, virtual symbol dictionaries, label maps, CFG structures, and decrypted payload trace buffers are securely wiped from memory on drop via `zeroize_dict` and `zeroize_bytes`.
2. **Authenticated Encryption & Forensics**: All containers verify integrity and authenticity prior to exposing plaintext. Forensic PE parsers execute static structural parsing without executing untrusted code.
3. **Constant-Time Verification**: Authentication tags, MACs, and sensitive token comparisons execute in constant time to mitigate side-channel timing attacks.
4. **Bounds, Recursion & ReDoS Protection**: Binary container parsers and AST normalizers enforce strict length checks, bounds validation on string slicing indices (`%VAR:~start,len%`), bounded loop convergence passes ($\le 15$), recursion depth limits ($\le 25$), and atomic regex patterns with non-backtracking character classes to prevent Denial of Service (ReDoS) or infinite hangs.
5. **Forensic Parser & Anti-Evasion Defense**: Input decoders perform statistical wide-character density analysis to neutralize malformed fake UTF-16LE/BE BOM header traps (BatCloak, machine1337, WireBits), Base64/Hex encoding stagers (PandaCrypter, Certutil), octal/hex escape sequences, and runtime unpacker stubs (BEDeCode, BatchShield, Invoke-CradleCrafter). Intermediate payload buffers, extracted stagers, and Assemblyline JSON forensic tables are zeroized in RAM via `zeroize_dict` and `zeroize_bytes` to prevent forensic residue leakage.

## Reporting a Vulnerability

If you discover a potential security issue, memory safety bug, or cryptographic flaw:

1. **Do not open a public issue** with exploit details before a fix is available.
2. Report the finding via [GitHub Security Advisories](../../security/advisories/new) or contact the maintainers directly with a minimal reproduction case.
3. We review reports promptly and coordinate fixes and release notes upon resolution.
