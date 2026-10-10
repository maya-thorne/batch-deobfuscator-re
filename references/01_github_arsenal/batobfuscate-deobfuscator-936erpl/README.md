# batobfuscator-deobfuscate

A deobfuscator for `.bat` files produced by `bat.py` (Machine1337's "Batch Obfuscator"). Strips the fake header and recovers the original, untouched batch script.

## Why this works

`bat.py` doesn't actually transform the file content at all. It just prepends a fixed 12-byte header before the original bytes, unmodified:

```
FF FE 26 63 6C 73 0D 0A FF FE 0A 0D
```

That's a UTF-16 byte-order mark (`FF FE`), the text `&cls`, a CRLF, and a second BOM. Editors like Notepad or HxD see the leading BOM and try to render the whole file as UTF-16, which turns the perfectly readable ASCII batch script that follows into garbled junk on screen. Windows' `cmd.exe`, on the other hand, only looks at the very first bytes to decide how to interpret the file, and effectively skips past the junk header when running it — so the script still executes fine despite looking "encrypted" in a hex/text editor.

No actual encryption or encoding is applied to the script body. Removing the 12-byte header recovers the exact original file, byte for byte.

## How it works

1. Reads the obfuscated `.bat` file in binary mode.
2. Verifies it starts with the known 12-byte header.
3. Strips those 12 bytes and writes the remainder to a new file.
4. Prints the recovered script to stdout.

## Usage

```bash
python deobfuscator.py obfuscated.bat [output.bat]
```

If no output path is given, it defaults to `deobfuscated.bat`.

## Disclaimer

Built for educational purposes — to understand how trivial "obfuscation" tricks can fool text/hex editors into misrendering a file without actually protecting its content. Use only on files you own or have authorization to analyze.
