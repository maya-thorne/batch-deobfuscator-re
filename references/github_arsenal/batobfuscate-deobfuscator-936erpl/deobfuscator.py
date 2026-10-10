import sys
HEADER = bytes.fromhex("FFFE26636C730D0AFFFE0A0D")

# shit made by 936erpl - github.com/936erpl

def deobfuscate(bat_path):
    with open(bat_path, "rb") as f:
        data = f.read()

    if not data.startswith(HEADER):
        raise ValueError("File does not start with the expected obfuscation header")

    return data[len(HEADER):]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python debat.py <obfuscated.bat> [output.bat]")
        sys.exit(1)

    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else "deobfuscated.bat"

    original = deobfuscate(src)

    with open(dst, "wb") as f:
        f.write(original)

    print(original.decode("utf-8", errors="replace"))
    print(f"\n[+] Written to {dst}")