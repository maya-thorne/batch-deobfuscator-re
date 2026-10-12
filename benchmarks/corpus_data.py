#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
28 Distinct Obfuscation Archetypes & Malware Stager Corpus Dataset.
Comprehensive ground truth dataset covering production evasion frameworks,
academic obfuscation archetypes, and real-world batch malware specimens.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class BenchmarkCorpus:
    """Definition of a single benchmark corpus test case."""
    corpus_id: int
    name: str
    archetype: str
    script: str
    ground_truth: str
    expected_tokens: List[str]
    difficulty: str
    detection_tags: List[str]
    description: str
    reference_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "corpus_id": self.corpus_id,
            "name": self.name,
            "archetype": self.archetype,
            "script": self.script,
            "ground_truth": self.ground_truth,
            "expected_tokens": self.expected_tokens,
            "difficulty": self.difficulty,
            "detection_tags": self.detection_tags,
            "description": self.description,
            "reference_path": self.reference_path,
        }


# 28-Corpus Benchmark Definitions
CORPUS_SUITE: List[BenchmarkCorpus] = [
    BenchmarkCorpus(
        corpus_id=1,
        name="BatCloak",
        archetype="Variable Shuffling & Dead Code Injection",
        script='@echo off & set %RANDOM%_junk= & set real=powershell -NoProfile -enc & %real%',
        ground_truth="powershell -NoProfile -enc",
        expected_tokens=["powershell -NoProfile -enc"],
        difficulty="Medium",
        detection_tags=["stager-shuffling", "random-noise", "powershell-loader"],
        description="BOM header masking, random junk variables, and stager shuffling",
        reference_path="references/github_arsenal/BatCloak"
    ),
    BenchmarkCorpus(
        corpus_id=2,
        name="Somalifuscator",
        archetype="Caesar Alphabet Slicing & Array Indexing",
        script='set alpha=abcdefghijklmnopqrstuvwxyz&set a=%alpha:~2,1%&set b=%alpha:~12,1%&set c=%alpha:~3,1%&%a%%b%%c% /c whoami',
        ground_truth="cmd /c whoami",
        expected_tokens=["cmd /c whoami"],
        difficulty="Hard",
        detection_tags=["caesar-cipher", "alphabet-slicing", "dynamic-set"],
        description="First-generation Somalifuscator Caesar alphabet slicing matrix",
        reference_path="references/github_arsenal/Somalifuscator-KDot227"
    ),
    BenchmarkCorpus(
        corpus_id=3,
        name="0xidiz3r",
        archetype="Reversible Variable Alphabet Substitution",
        script='@echo off & set "a1=c" & set "a2=m" & set "a3=d" & %a1%%a2%%a3% /c whoami',
        ground_truth="cmd /c whoami",
        expected_tokens=["cmd /c whoami"],
        difficulty="Medium",
        detection_tags=["alphabet-substitution", "zero-literal", "bootstrapping"],
        description="Reversible variable alphabet substitution and bootstrapping",
        reference_path="references/github_arsenal/0xidiz3r"
    ),
    BenchmarkCorpus(
        corpus_id=4,
        name="Abobus",
        archetype="Unicode Noise & Caret Escaped Identifiers",
        script='@s^e^t ^"abobus=whoami^" & c^m^d /c %abobus%',
        ground_truth="cmd /c whoami",
        expected_tokens=["cmd /c whoami"],
        difficulty="Medium",
        detection_tags=["caret-escaped", "unicode-noise", "identifier-masking"],
        description="Unicode noise characters and caret-escaped identifier assignment",
        reference_path="references/github_arsenal/Abobus-obfuscator"
    ),
    BenchmarkCorpus(
        corpus_id=5,
        name="Invoke-DOSfuscation",
        archetype="Daniel Bohannon Environment Slicing & Caret Interleaving",
        script='%COMSPEC:~-7,1%^m^%COMSPEC:~-5,1% /c whoami',
        ground_truth="cmd /c whoami",
        expected_tokens=["cmd /c whoami"],
        difficulty="Advanced",
        detection_tags=["comspec-slicing", "caret-interleaving", "dosfuscation"],
        description="Classic Daniel Bohannon slicing combined with inline caret escaping",
        reference_path="references/github_arsenal/Invoke-DOSfuscation"
    ),
    BenchmarkCorpus(
        corpus_id=6,
        name="Invoke-CradleCrafter",
        archetype="Download Cradle Environment Splicing",
        script='set c=%PATH:~0,1%&set m=md&%c%%m% /c echo DOWNLOAD_STAGER',
        ground_truth="cmd /c echo DOWNLOAD_STAGER",
        expected_tokens=["cmd /c echo DOWNLOAD_STAGER"],
        difficulty="Hard",
        detection_tags=["path-slicing", "download-cradle", "memory-stager"],
        description="Environment path slicing and dynamic assembly for cradle scripts",
        reference_path="references/github_arsenal/Invoke-CradleCrafter"
    ),
    BenchmarkCorpus(
        corpus_id=7,
        name="Batch-Encryption-DeCoder",
        archetype="Dynamic String Replacement (%VAR:old=new%)",
        script='set v=powershell & %v:powershell=cmd% /c whoami',
        ground_truth="cmd /c whoami",
        expected_tokens=["cmd /c whoami"],
        difficulty="Medium",
        detection_tags=["substitution-cipher", "string-replace", "alias-swap"],
        description="Dynamic string replacement (%VAR:old=new%) cipher synthesis",
        reference_path="references/github_arsenal/Batch-Encryption-DeCoder"
    ),
    BenchmarkCorpus(
        corpus_id=8,
        name="BatchShield",
        archetype="Static OS Variable Indexing & Offset Extraction",
        script='set p=%COMSPEC:~-7,3% & %p% /c echo PAYLOAD_RECOVERED',
        ground_truth="cmd /c echo PAYLOAD_RECOVERED",
        expected_tokens=["cmd /c echo PAYLOAD_RECOVERED"],
        difficulty="Hard",
        detection_tags=["env-indexing", "payload-extraction", "batchshield"],
        description="Static OS variable indexing (%COMSPEC:~-7,3%) payload extraction",
        reference_path="references/github_arsenal/BatchShield-Decryptor"
    ),
    BenchmarkCorpus(
        corpus_id=9,
        name="PandaCrypter",
        archetype="Uninitialized Dummy Variable Injection",
        script='%UNDEFINED%certutil %RANDOM_NOISE% -decode input.txt output.bin',
        ground_truth="certutil -decode input.txt output.bin",
        expected_tokens=["certutil -decode input.txt output.bin"],
        difficulty="Easy",
        detection_tags=["dummy-vars", "undefined-stripping", "certutil-packer"],
        description="Certutil loader stub packed with uninitialized dummy variables",
        reference_path="references/github_arsenal/PandaCrypter-chainski"
    ),
    BenchmarkCorpus(
        corpus_id=10,
        name="Exorcism",
        archetype="Sequential Hooking & Dispatch Chaining",
        script='@echo off & set payload=calc.exe & start %payload%',
        ground_truth="start calc.exe",
        expected_tokens=["start calc.exe"],
        difficulty="Easy",
        detection_tags=["dispatch-hook", "command-chaining", "execution-stager"],
        description="Sequential chained statements intercepted during command dispatch",
        reference_path="references/github_arsenal/Exorcism"
    ),
    BenchmarkCorpus(
        corpus_id=11,
        name="BatchToApp",
        archetype="Native Wrapper String Encapsulation",
        script='set _exe=cmd.exe & set _arg=/c & %_exe% %_arg% dir',
        ground_truth="cmd.exe /c dir",
        expected_tokens=["cmd.exe /c dir"],
        difficulty="Medium",
        detection_tags=["wrapper-emulation", "table-dereference", "batch-to-app"],
        description="Compiled executable string encapsulation and table dereferencing",
        reference_path="references/github_arsenal/BatchToApp-DosX"
    ),
    BenchmarkCorpus(
        corpus_id=12,
        name="batobfuscate-machine1337",
        archetype="BOM Masking & Inline Caret Scrambling",
        script='&cls & c^m^d /c p^o^w^e^r^s^h^e^l^l -Command Get-Process',
        ground_truth="cmd /c powershell -Command Get-Process",
        expected_tokens=["cmd /c powershell -Command Get-Process"],
        difficulty="Medium",
        detection_tags=["bom-masking", "caret-scramble", "cls-preamble"],
        description="BOM header masking, cls preamble, and inline caret scrambling",
        reference_path="references/github_arsenal/batobfuscate-machine1337"
    ),
    BenchmarkCorpus(
        corpus_id=13,
        name="CMD-DeObfuscator",
        archetype="Multi-Token Caret & Boundary Normalization",
        script='c^m^d /c ^w^h^o^a^m^i',
        ground_truth="cmd /c whoami",
        expected_tokens=["cmd /c whoami"],
        difficulty="Easy",
        detection_tags=["caret-escape", "token-normalization", "cmd-deobfuscator"],
        description="Combination of caret escapes with token boundary normalization",
        reference_path="references/github_arsenal/CMD-DeObfuscator"
    ),
    BenchmarkCorpus(
        corpus_id=14,
        name="simple-batch-obfuscator",
        archetype="Character-Level Random Variable Fragment Infiltration",
        script='%RAND_A%p%RAND_B%o%RAND_C%w%RAND_D%e%RAND_E%r%RAND_F%s%RAND_G%h%RAND_H%e%RAND_I%l%RAND_J%l%RAND_K% -NoProfile -c "echo PSS_OK"',
        ground_truth='powershell -NoProfile -c "echo PSS_OK"',
        expected_tokens=['powershell -NoProfile -c "echo PSS_OK"'],
        difficulty="Hard",
        detection_tags=["random-vars", "char-level-infiltration", "simple-obfuscator"],
        description="Character-level variable noise dispersion wrapping powershell dispatch",
        reference_path="references/github_arsenal/simple-batch-obfuscator-DavidNiessen"
    ),
    BenchmarkCorpus(
        corpus_id=15,
        name="JSBatchDeobfuscator",
        archetype="JavaScript Transpiled Chained SET Tokens",
        script='set part1=pow&set part2=ershell&%part1%%part2% -ExecutionPolicy Bypass',
        ground_truth="powershell -ExecutionPolicy Bypass",
        expected_tokens=["powershell -ExecutionPolicy Bypass"],
        difficulty="Medium",
        detection_tags=["js-transpiler", "chained-set", "token-assembly"],
        description="JavaScript-based obfuscator output featuring chained SET tokens",
        reference_path="references/github_arsenal/JSBatchDeobfuscator-yrotak"
    ),
    BenchmarkCorpus(
        corpus_id=16,
        name="BatchStealer-Takaovi",
        archetype="Credential Harvester Caret Masking",
        script='c^u^r^l -s http://127.0.0.1/payload & t^a^s^k^l^i^s^t',
        ground_truth="curl -s http://127.0.0.1/payload\ntasklist",
        expected_tokens=["curl -s", "tasklist"],
        difficulty="Medium",
        detection_tags=["stealer-masking", "curl-dropper", "tasklist-recon"],
        description="Malware dropper commands disguised via caret escapes and chaining",
        reference_path="references/github_arsenal/BatchStealer-Takaovi"
    ),
    BenchmarkCorpus(
        corpus_id=17,
        name="BatchObfuscator-BiggerDABOSS",
        archetype="Repetitive Empty Quote Pairs with Undefined Variables",
        script='""c""m""d"" %UNDEFINED% /c ""w""""h""""o""""a""""m""""i""',
        ground_truth="cmd /c whoami",
        expected_tokens=["cmd /c whoami"],
        difficulty="Hard",
        detection_tags=["empty-quotes", "undefined-noise", "token-fragmentation"],
        description="Undefined variable insertion combined with repetitive empty quote pairs",
        reference_path="references/github_arsenal/BatchObfuscator-BiggerDABOSS"
    ),
    BenchmarkCorpus(
        corpus_id=18,
        name="BatchObfuscator-EmenstaNougat",
        archetype="Multi-Line & Command Chaining & Variable Dereference",
        script='set a=net&set b=localgroup&set c=administrators&%a% %b% %c%',
        ground_truth="net localgroup administrators",
        expected_tokens=["net localgroup administrators"],
        difficulty="Medium",
        detection_tags=["chained-set", "token-reassembly", "admin-recon"],
        description="Multi-line command chaining (&-splits) and multi-token reassembly",
        reference_path="references/github_arsenal/BatchObfuscator-EmenstaNougat"
    ),
    BenchmarkCorpus(
        corpus_id=19,
        name="BatchObfuscator-wirebits",
        archetype="Sequential Single-Character Variable Splicing",
        script='set _1=p&set _2=o&set _3=w&set _4=e&set _5=r&set _6=shell&%_1%%_2%%_3%%_4%%_5%%_6% -Version 5.1',
        ground_truth="powershell -Version 5.1",
        expected_tokens=["powershell -Version 5.1"],
        difficulty="Medium",
        detection_tags=["char-splicing", "sequential-set", "powershell-assembly"],
        description="Character-level variable fragmentation reassembled in sequence",
        reference_path="references/github_arsenal/BatchObfuscator-wirebits"
    ),
    BenchmarkCorpus(
        corpus_id=20,
        name="batchalchemy",
        archetype="AST Parser Validation & Nested Concatenation",
        script='set prefix=who&set suffix=ami&cmd.exe /c %prefix%%suffix%',
        ground_truth="cmd.exe /c whoami",
        expected_tokens=["cmd.exe /c whoami"],
        difficulty="Medium",
        detection_tags=["ast-validation", "nested-concatenation", "tree-sitter"],
        description="AST-guided multi-variable syntax tree reassembly benchmark",
        reference_path="references/github_arsenal/batchalchemy"
    ),
    BenchmarkCorpus(
        corpus_id=21,
        name="BatchDeobfuscator-CrowTheBest",
        archetype="Chained Single-Line @set Table Dereferencing",
        script='@set x1=cmd & @set x2=/c & @set x3=whoami & %x1% %x2% %x3%',
        ground_truth="cmd /c whoami",
        expected_tokens=["cmd /c whoami"],
        difficulty="Medium",
        detection_tags=["at-set-table", "single-line-chain", "dereference"],
        description="Single-line @set variable assignment table with chained invocation",
        reference_path="references/github_arsenal/BatchDeobfuscator-CrowTheBest"
    ),
    BenchmarkCorpus(
        corpus_id=22,
        name="assemblyline-batchdeobfuscator",
        archetype="Automated Sandbox Multi-Pass Variable Resolution",
        script='set c=cmd&set w=whoami&%c% /c %w%',
        ground_truth="cmd /c whoami",
        expected_tokens=["cmd /c whoami"],
        difficulty="Medium",
        detection_tags=["assemblyline", "sandbox-analysis", "multi-pass"],
        description="CCCS Assemblyline automated malware analysis reference benchmark",
        reference_path="references/github_arsenal/assemblyline-service-batchdeobfuscator"
    ),
    BenchmarkCorpus(
        corpus_id=23,
        name="Remcos-Rat-Batch-Deobfuscator",
        archetype="RAT Dropper Short Alias & Registry Persistence",
        script='set d=reg & %d% add HKCU\\Software\\Test /v Run /d calc.exe /f',
        ground_truth="reg add HKCU\\Software\\Test /v Run /d calc.exe /f",
        expected_tokens=["reg add HKCU\\Software\\Test"],
        difficulty="Medium",
        detection_tags=["rat-persistence", "reg-alias", "remcos-dropper"],
        description="Remcos RAT batch dropper persistence setup with short variable alias",
        reference_path="references/github_arsenal/Remcos-Rat-Batch-Deobfuscator-fatihbeyexe"
    ),
    BenchmarkCorpus(
        corpus_id=24,
        name="Out-FINcodedCommand",
        archetype="APT FIN7 Network Reconnaissance Construction",
        script='set x=cmd.exe & %x% /c ping 127.0.0.1 -n 1',
        ground_truth="cmd.exe /c ping 127.0.0.1 -n 1",
        expected_tokens=["cmd.exe /c ping 127.0.0.1 -n 1"],
        difficulty="Medium",
        detection_tags=["fin7-apt", "recon-ping", "expansion"],
        description="FIN7 APT group style command construction with variable expansion",
        reference_path="references/github_arsenal/Out-FINcodedCommand"
    ),
    BenchmarkCorpus(
        corpus_id=25,
        name="Bat2Exe",
        archetype="Multi-Stage s-e-t Bootstrap & Binary Dehoisting",
        script='set _s=s & set _e=e & set _t=t & %_s%%_e%%_t% cmd=cmd.exe & %cmd% /c calc.exe',
        ground_truth="cmd.exe /c calc.exe",
        expected_tokens=["cmd.exe /c calc.exe"],
        difficulty="Hard",
        detection_tags=["bat2exe", "set-bootstrap", "binary-dehoisting"],
        description="Multi-stage s-e-t keyword bootstrap and dynamic command execution",
        reference_path="references/github_arsenal/Bat2Exe-dehoisted"
    ),
    BenchmarkCorpus(
        corpus_id=26,
        name="01_env_slicing",
        archetype="OS Environment Slicing & Dynamic Assembly",
        script='set _c=%COMSPEC:~-7,1% & set _m=%COMSPEC:~-6,1% & set _d=%COMSPEC:~-5,1% & %_c%%_m%%_d% /c whoami',
        ground_truth="cmd /c whoami",
        expected_tokens=["cmd /c whoami"],
        difficulty="Advanced",
        detection_tags=["comspec-slicing", "negative-indices", "canonical-sample"],
        description="Reference sample for OS environment variable slicing and character extraction",
        reference_path="samples/01_env_slicing_sample.bat"
    ),
    BenchmarkCorpus(
        corpus_id=27,
        name="02_caret_delimiters",
        archetype="Caret Interleaving & Comma/Semicolon Delimiters",
        script='c^m^d /c w^h^o^a^m^i & "c"md /c "w"ho"a"mi',
        ground_truth="cmd /c whoami\ncmd /c whoami",
        expected_tokens=["cmd /c whoami"],
        difficulty="Medium",
        detection_tags=["caret-interleaving", "quotation-fragmentation", "canonical-sample"],
        description="Reference sample for dense caret insertion and fragmented quotes",
        reference_path="samples/02_caret_and_delimiters_sample.bat"
    ),
    BenchmarkCorpus(
        corpus_id=28,
        name="05_certutil_hex",
        archetype="Inline Base64 / Hex Extraction Pipeline",
        script='set c=certutil & %c% -decode -f payload.b64 decoded.txt & echo DECODED_OK',
        ground_truth="certutil -decode -f payload.b64 decoded.txt\necho DECODED_OK",
        expected_tokens=["certutil -decode -f payload.b64 decoded.txt", "echo DECODED_OK"],
        difficulty="Advanced",
        detection_tags=["certutil-pipeline", "base64-decode", "canonical-sample"],
        description="Reference sample for inline certutil decoding and dynamic stager dispatch",
        reference_path="samples/05_certutil_hex_pipeline_sample.bat"
    ),
]


def get_corpus_suite() -> List[BenchmarkCorpus]:
    """Retrieve the full 28-corpus benchmark suite."""
    return list(CORPUS_SUITE)


def get_corpus_by_id(corpus_id: int) -> Optional[BenchmarkCorpus]:
    """Look up a corpus by its numeric ID (1-28)."""
    for c in CORPUS_SUITE:
        if c.corpus_id == corpus_id:
            return c
    return None


def get_corpus_by_name(name: str) -> Optional[BenchmarkCorpus]:
    """Look up a corpus by name (case-insensitive substring or exact match)."""
    name_lower = name.lower()
    for c in CORPUS_SUITE:
        if c.name.lower() == name_lower:
            return c
    for c in CORPUS_SUITE:
        if name_lower in c.name.lower():
            return c
    return None
