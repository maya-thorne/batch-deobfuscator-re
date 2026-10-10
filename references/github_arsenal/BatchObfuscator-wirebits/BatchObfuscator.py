# BatchObfuscator
# A tool that obfuscates bat/cmd files.
# Author - WireBits

import os
import sys
import shutil
import base64

def show_banner():
    print("+──────────────────────────────────────────────+")
    print("|╔╗ ╔═╗╔╦╗╔═╗╦ ╦ ╔═╗╔╗ ╔═╗╦ ╦╔═╗╔═╗╔═╗╔╦╗╔═╗╦═╗|")
    print("|╠╩╗╠═╣ ║ ║  ╠═╣ ║ ║╠╩╗╠╣ ║ ║╚═╗║  ╠═╣ ║ ║ ║╠╦╝|")
    print("|╚═╝╩ ╩ ╩ ╚═╝╩ ╩ ╚═╝╚═╝╚  ╚═╝╚═╝╚═╝╩ ╩ ╩ ╚═╝╩╚═|")
    print("+──────────────────────────────────────────────+")
    print("|         Batch File Obfuscation Tool          |")
    print("+──────────────────────────────────────────────+")
    print("|              Author : WireBits               |")
    print("+──────────────────────────────────────────────+")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def process(arg_file=None):
    clear_screen()
    show_banner()
    print("+─────────────+")
    print("| Operartions |")
    print("+─────────────+")
    print("╰┈➤ Obfuscate a .bat/.cmd file : o")
    print("╰┈➤ Exit                       : q")
    op = get_input("╰┈➤ Choose Operartion ⮞ ", ['o', 'q'])
    if op == 'q':
        print('╰┈➤ [!] Closing the tool. Goodbye!')
        return False
    if arg_file:
        file_path = arg_file
        print(f"\n╰┈➤ Using file from command line: {file_path}")
    else:
        file_path = input("╰┈➤ Enter path to the .bat/.cmd file OR just a filename with extension ⮞ ").strip()
    file_path = os.path.expanduser(file_path)
    try:
        output = obfuscation(file_path)
        print(f"╰┈➤ File Obfuscated : {output}!")
    except Exception as e:
        print(f"╰┈➤ [!] Error: {e}")
    return True

def get_input(prompt, valid_values):
    while True:
        user_input = input(prompt).strip().lower()
        if user_input in valid_values:
            return user_input
        print("╰┈➤ [!] Invalid input! Please try again!\n")

try:
    import readline
except ImportError:
    try:
        import pyreadline as readline
    except Exception:
        try:
            import pyreadline3 as readline
        except Exception:
            readline = None

if readline:
    import glob
    def complete_path(text, state):
        line = readline.get_line_buffer().split()
        if not line:
            return [None][state]
        else:
            return (glob.glob(os.path.expanduser(text) + '*') + [None])[state]

    readline.set_completer_delims(' \t\n;')
    try:
        readline.parse_and_bind("tab: complete")
    except Exception:
        pass
    readline.set_completer(complete_path)

BASE64_PAYLOAD = b"//4mY2xzDQo="

def obfuscation(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    file_ext = os.path.splitext(file_path)[1].lower()
    file_name = os.path.splitext(os.path.basename(file_path))[0]
    if file_ext not in [".bat", ".cmd"]:
        raise ValueError("[!] Only .bat or .cmd files are supported.")
    try:
        decoded_bytes = base64.b64decode(BASE64_PAYLOAD, validate=True)
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")
    output_file = f"{file_name}_obf{file_ext}"
    try:
        with open(output_file, "wb") as out_f:
            out_f.write(decoded_bytes)
    except Exception as e:
        raise IOError(f"Failed to write decoded file: {e}")
    try:
        with open(output_file, "ab") as out_f, open(file_path, "rb") as in_f:
            shutil.copyfileobj(in_f, out_f)
    except Exception as e:
        raise IOError(f"Failed to append the input file: {e}")
    return output_file

def main():
    clear_screen()
    try:
        while True:
            cont = process()
            if not cont:
                break
            again = input("╰┈➤ Do you want to continue? (yes/no) ⮞ ").strip().lower()
            if again not in ['yes', 'y']:
                print("╰┈➤ [!] Exiting the tool. Goodbye!")
                break
    except KeyboardInterrupt:
        print('\n╰┈➤ [!] Aborting the tool. Goodbye!')
    except Exception as e:
        print('╰┈➤[!] ERROR: ' + str(e))

if __name__ == "__main__":
    main()