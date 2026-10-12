# Security Policy

## Supported Versions

Security updates are applied to the latest release series on the `main` branch.

| Version | Supported          |
| ------- | ------------------ |
| Latest (`1.x`) | :white_check_mark: |
| `< 1.0.0` | :x:                |

## Cryptographic & Memory Safety Invariants

1. **Key Material Hygiene**: All passphrases, derived keys, intermediate KDF buffers, substitution tables, and decrypted payloads are wiped from memory on drop via `zeroize`, `zeroize_bytes`, and `zeroize_dict`.
2. **Authenticated Encryption**: All containers verify integrity and authenticity using ChaCha20-Poly1305 AEAD or HMAC/CRC-32 layers prior to exposing plaintext.
3. **Constant-Time Verification**: Authentication tags, MACs, and sensitive token comparisons execute in constant time to mitigate side-channel timing attacks.
4. **Bounds & Overflow Protection**: Binary container parsers and AST normalizers enforce strict length checks, bounds validation on string slicing indices (`%VAR:~start,len%`), and modulo-bounded arithmetic on Caesar shift offsets ($k \pmod{26}$).
5. **Forensic Parser & Fake-BOM Defense**: Input decoders perform statistical wide-character density analysis to neutralize malformed fake UTF-16LE/BE BOM header traps (BatCloak, machine1337) and prevent memory or parser corruption. Intermediate payload buffers are zeroized in RAM to prevent forensic residue leakage.

## Reporting a Vulnerability

If you discover a potential security issue, memory safety bug, or cryptographic flaw:

1. **Do not open a public issue** with exploit details before a fix is available.
2. Report the finding via [GitHub Security Advisories](../../security/advisories/new) or contact the maintainers directly with a minimal reproduction case.
3. We review reports promptly and coordinate fixes and release notes upon resolution.
