<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=32&duration=3000&pause=1500&color=39D353&center=true&vCenter=true&multiline=false&repeat=true&width=620&height=60&lines=BAT2EXE+Converter;Drag+%26+Drop+Edition;.bat+%E2%86%92+.exe+Instantly" alt="BAT2EXE Converter Animated Title" />

<br/>

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=15&duration=4000&pause=2000&color=58A6FF&center=true&vCenter=true&repeat=true&width=560&height=30&lines=Convert+any+.bat+into+a+portable+.exe+%E2%80%94+instantly%2C+natively%2C+no+installs." alt="Subtitle" />

<br/><br/>

*By [Sunil56224972](https://github.com/Sunil56224972)*

---

![Windows](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows)
![No Install](https://img.shields.io/badge/Dependencies-None-brightgreen?style=flat-square)
![Native](https://img.shields.io/badge/Engine-IExpress%20%28Built--in%20Windows%29-blueviolet?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Stars](https://img.shields.io/github/stars/Sunil56224972?style=flat-square)

</div>

---

## 📌 Overview

**BAT2EXE Converter** is a zero-dependency, drag-and-drop Windows batch utility that wraps any `.bat` script into a portable `.exe` executable using **IExpress** — a packaging tool built directly into Windows itself.

No Python. No Node.js. No third-party software. Just a `.bat` file and your target script.

> ✅ Works on Windows 7, 8, 10, and 11 — no additional runtime needed.

---
     Terminal 
<div align="center">
  <img src="assets/terminal-demo.svg" alt="BAT2EXE Terminal Demo" />
</div>

##
## ✨ Features

| Feature | Description |
|---|---|
| 🖱️ **Drag & Drop** | Simply drag any `.bat` file onto the converter to build the `.exe` |
| 🔒 **No Dependencies** | Uses Windows' built-in `IExpress` engine — nothing to install |
| ⚡ **Instant Build** | Conversion completes in seconds |
| 📦 **Self-Contained Output** | The resulting `.exe` bundles and launches your batch script automatically |
| 🧹 **Clean Operation** | Temp files (`.sed`) are created and deleted automatically — no mess left behind |
| 🖥️ **Cross-Version Windows** | Compatible with Windows 7 through Windows 11 |

---

## 🚀 How to Use

### Method 1 — Drag & Drop (Recommended)

```
1. Download the converter:  BAT2EXE_Converter(drag&drop)-By_Emensta.bat
2. Locate your target .bat file in File Explorer
3. Drag and drop your .bat file directly onto the converter script
4. Wait a moment — the .exe will appear in the same folder as your .bat
```

### Method 2 — Command Line

```cmd
BAT2EXE_Converter.bat "C:\Path\To\YourScript.bat"
```

### Output Location

The generated `.exe` is saved in the **same directory as your source `.bat` file**, with the same name:

```
YourScript.bat  →  YourScript.exe
```

---

## 🔬 How It Works

This tool is a **dual-purpose `.bat` file** — its structure is cleverly engineered to function as both a runnable batch script *and* a valid IExpress `.sed` (Self-Extraction Directive) configuration file simultaneously.

```
┌─────────────────────────────────────────────────────────────┐
│                    BAT2EXE Converter Flow                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. You drop yourscript.bat onto the converter              │
│         │                                                   │
│         ▼                                                   │
│  2. Converter reads the dropped file's name & directory     │
│         │                                                   │
│         ▼                                                   │
│  3. A temp .sed config is generated in %TEMP%               │
│         │                                                   │
│         ▼                                                   │
│  4. IExpress (Windows built-in) packages your .bat          │
│         │                                                   │
│         ▼                                                   │
│  5. yourscript.exe is created in the same folder            │
│         │                                                   │
│         ▼                                                   │
│  6. Temp .sed file is deleted automatically                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Role |
|---|---|
| `iexpress /n /q /m` | Windows' native self-extractor/packager (silent mode) |
| `.sed` config | Defines source file, launch command, and output target |
| `cmd /c "%bat_name%"` | The launch command embedded inside the final `.exe` |
| `%temp%\2exe.sed` | Temporary config file, auto-cleaned after build |

---

## 🖥️ Terminal Demo

```cmd
C:\Tools> BAT2EXE_Converter.bat "myscript.bat"

  [*] Target detected: myscript.bat
  [*] Reading source directory...
  [*] Setting output target: myscript.exe
  [*] Generating IExpress SED config → %TEMP%\2exe.sed
  [*] Bundling batch file into self-extractor...
  [*] Calling: iexpress /n /q /m %TEMP%\2exe.sed

  [####################] 100%

  [*] Cleaning up temp files...
  [+] Done! myscript.exe created successfully.
  [+] Output: C:\Tools\myscript.exe

C:\Tools> _
```

---

## 📂 Project Structure

```
📦 BAT2EXE-Converter
 ┣ 📄 BAT2EXE_Converter(drag&drop)-By_Emensta.bat   ← The converter itself
 ┗ 📄 README.md
```

---

## ⚠️ Important Notes

- The generated `.exe` **still requires your original `.bat` to be bundled** — it is not compiled native code, but a self-extracting package that runs your script.
- **Administrator rights** may be required depending on what your batch script does.
- **Antivirus false positives** — some AV tools may flag IExpress-generated executables. This is a known false positive with self-extracting `.exe` packages. The tool itself contains no malicious code.
- The converter does **not** obfuscate or protect your source code — the `.bat` contents are accessible inside the `.exe` package.

---

## 🧩 Requirements

| Requirement | Details |
|---|---|
| OS | Windows 7 / 8 / 10 / 11 |
| IExpress | Pre-installed on all Windows versions (`C:\Windows\System32\iexpress.exe`) |
| Permissions | Standard user (admin may be needed for certain batch scripts) |

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/my-improvement`
3. Commit your changes: `git commit -m 'Add some improvement'`
4. Push to the branch: `git push origin feature/my-improvement`
5. Open a Pull Request

---

## 👤 Author

**Sunil**
- GitHub: [@Sunil56224972](https://github.com/Sunil56224972)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

*Made with ❤️ by Sunil — If you found this useful, drop a ⭐ on the repo!*

</div>
