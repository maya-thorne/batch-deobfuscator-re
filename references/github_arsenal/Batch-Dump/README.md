<h1 align="center">⚙️ Batch Dump ⚙️</h1>

<p align="center">
  <a href="https://www.python.org" target="_blank"><img src="https://img.shields.io/badge/Language-Python-blue?style=for-the-badge&logo=python" /></a>
  <a href="https://t.me/swezy" target="_blank"><img src="https://img.shields.io/badge/Telegram-@Swezy-blue?style=for-the-badge&logo=telegram" /></a>
  <br>
  <code>Leave a ⭐ if you like this Repository</code>
</p>

---

## 🚩 Project overview

**Batch Dump** is a compact Python utility that **watches common system/user directories** for newly created compiled `.bat` files, **copies them to the tool directory** for inspection, and optionally **deobfuscates** certain compiled batch stubs by removing a known hex sequence.

The program uses a **clean CLI interface**, a **gradient ASCII logo**, and a lightweight **watchdog**-based file monitor to automate discovery and basic recovery of batch source code.

> [!CAUTION]
> This tool is intended for **legitimate reverse-engineering, debugging, recovery, and research** in environments where you have explicit permission.
> Do **not** use this to access or exfiltrate files you are not authorized to access. The author and contributors are **not** responsible for misuse of this code.

---

## ✨ Features

* 📁 **Watch & Dump `.bat` files** — Monitors a configurable set of likely locations (Temp, Desktop, Documents, Downloads, ProgramData, etc.) and copies newly created `.bat` files into the script folder.
* 🧩 **Deobfuscate Batch Files** — Removes a specific byte/hex pattern (`FF FE 26 63 6C 73 0D 0A FF FE 0A 0D`) to reveal readable batch source where applicable.
* 🎨 **Aesthetic CLI** — Displays a gradient ASCII logo and menu using `rgbprint` and colored output via `colorama`.
* 🔁 **Duplicate protection** — Tracks already-processed files to avoid copying the same file multiple times during a session.

---

## 🧭 How It Works

1. Run the tool (`python main.py`).
2. Choose one of the two options:

   * `[1] Dump compiled Batch` — start monitoring the configured directories and copy discovered `.bat` files to the script directory.
   * `[2] Deobfuscate Batch` — provide a path to a `.bat` file and the script will remove the configured hex sequence and open the result in your system editor. (This only works for the Chinese method)
3. The tool prints progress to the console and saves discovered files for offline inspection.

> ✅ When dumping, any discovered `.bat` will be copied into the same folder as `main.py`. When deobfuscating, the file is modified in-place (make backups if needed).

---

## 🧰 Requirements

* 🐍 Python **3.9+**
* 📦 Dependencies:

  ```bash
  pip install watchdog rgbprint colorama
  ```
* 💾 Access to the directories you want to monitor (run with appropriate permissions).

---

## 🔑 Notes on Safety & Usage

* Only run this tool on machines you own or where you have explicit permission.
* `utility.delete_hex()` modifies files in-place — always keep backups of originals if you need to preserve them.
* Reduce risk for false detections during testing by limiting `utility.possible_paths` to a single controlled directory.

---

## 📝 Repository structure 

```/
├─ assets/ ➔ Screenshots of the Program in action
│ └─ preview.png ➔ A screenshot of the Program running
├─ main.py ➔ Main program logic and CLI
├─ LICENSE ➔ License file
└─ README.md ➔ Read me file
```

---

## 🖼️ Preview

<p align="center">
  <img src="https://img.shields.io/badge/UI-Gradient%20CLI-blueviolet?style=for-the-badge"/>
  <br><br>
  <img src="https://github.com/SwezyDev/Batch-Dump/blob/main/assets/preview.png?raw=true" alt="Program preview">
</p>

---

## 🧠 Hex Sequence Removed

The script removes the following hex byte sequence (shown as hex groups):

```
FF FE 26 63 6C 73 0D 0A FF FE 0A 0D
```
<img width="669" height="97" alt="image" src="https://github.com/user-attachments/assets/1ea099de-ffa9-4a73-a87e-f5a020350e42" />

You can change the target pattern by editing the `utility.delete_hex()` call in `BatchDump.deobfuscate()`, but doing so is not recommended as it may break the deobfuscation process.

---

## ⚙️ Technical Details

* `watchdog.Observer` + `utility.FileCreationHandler` (subclass of `FileSystemEventHandler`) to react to file creation events.
* `shutil.copy()` copies detected files into the running script directory.
* `utility.delete_hex()` reads file bytes, replaces occurrences of `bytes.fromhex(hex)` with `b''`, and writes back the result.
* `rgbprint.gradient_print()` for the logo and menu; `colorama.Fore` for colored status lines.

---

## ⚖️ License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

## 🙌 Credits & contact

- Maintainer: [@SwezyDev](https://github.com/SwezyDev) — reach out via Telegram: [@Swezy](https://t.me/swezy)  
- Inspiration: public security research and community writeups.

---

## 🚨 Disclaimer

This project is **unofficial** and is **not** affiliated with any vendor. It is meant for **educational, analysis, and recovery** tasks only. Use responsibly and legally.

---

## 📣 Final note

This utility exists to help researchers and devs recover and inspect compiled/obfuscated batch stubs. Use responsibly — do **not** use it to spy, exfiltrate, or automate access to systems you don't own or have permission to test.
