"""
Core Multi-Pass Fixed-Point Deobfuscator Engine.
Deterministic convergence loop with dynamic symbol table resolution and virtual sandbox state.
"""

import re
import time
from typing import Dict, Any, Tuple, List
from .normalizers import (
    strip_carets,
    strip_empty_quotes,
    split_chained_commands,
    strip_undefined_vars,
    resolve_slicing,
    resolve_substitution,
    normalize_bom,
    collapse_spaces_outside_quotes,
    DYNAMIC_SYSTEM_VARS,
)
from .batcloak import (
    normalize_batcloak_headers,
    strip_batcloak_random_vars,
    eliminate_dead_stores,
    detect_batcloak_signatures,
)
from .somalifuscator import (
    normalize_somalifuscator,
    detect_somalifuscator_signatures,
)
from .oxidizer import (
    normalize_oxidizer,
    detect_oxidizer_signatures,
)
from .abobus import (
    normalize_abobus,
    detect_abobus_signatures,
)
from .dosfuscation import (
    normalize_dosfuscation,
    detect_dosfuscation_signatures,
    resolve_dosfuscation_slicing,
    normalize_dosfuscation_delimiters,
)
from .cradlecrafter import (
    normalize_cradlecrafter,
    detect_cradle_signatures,
    CradleCrafterNormalizer,
)
from .bedecode import (
    normalize_bedecode,
    detect_bedecode_signatures,
    BEDeCodeNormalizer,
)

class BatchDeobfuscator:
    """Multi-Pass Fixed-Point Batch Script Deobfuscator."""

    DEFAULT_ENV = {
        "comspec": r"C:\Windows\system32\cmd.exe",
        "systemroot": r"C:\Windows",
        "windir": r"C:\Windows",
        "programdata": r"C:\ProgramData",
        "public": r"C:\Users\Public",
        "allusersprofile": r"C:\ProgramData",
        "commonprogramfiles": r"C:\Program Files\Common Files",
        "commonprogramfiles(x86)": r"C:\Program Files (x86)\Common Files",
        "commonprogramw6432": r"C:\Program Files\Common Files",
        "programfiles": r"C:\Program Files",
        "programfiles(x86)": r"C:\Program Files (x86)",
        "driverdata": r"C:\Windows\System32\Drivers\DriverData",
        "path": r"C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem",
        "pathext": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
        "temp": r"C:\Users\Administrator\AppData\Local\Temp",
        "tmp": r"C:\Users\Administrator\AppData\Local\Temp",
        "appdata": r"C:\Users\Administrator\AppData\Roaming",
        "localappdata": r"C:\Users\Administrator\AppData\Local",
        "userprofile": r"C:\Users\Administrator",
        "username": "Administrator",
        "os": "Windows_NT",
        "systemdrive": "C:",
        "__appdir__": "C:\\Windows\\system32\\",
        "__cd__": "C:\\Windows\\system32\\",
        "computername": "DESKTOP-ENV",
        "processor_architecture": "AMD64",
        "homedrive": "C:",
        "homepath": r"\Users\Administrator",
    }

    def __init__(self, max_passes: int = 15, custom_env: Dict[str, str] = None, 
                 strip_undefined: bool = True, split_chains: bool = True,
                 enable_batcloak: bool = True, enable_somalifuscator: bool = True,
                 enable_oxidizer: bool = True, enable_abobus: bool = True,
                 enable_dosfuscation: bool = True,
                 enable_cradlecrafter: bool = True,
                 enable_bedecode: bool = True,
                 eliminate_dead_code: bool = True):
        self.max_passes = max_passes
        self.strip_undefined = strip_undefined
        self.split_chains = split_chains
        self.enable_batcloak = enable_batcloak
        self.enable_somalifuscator = enable_somalifuscator
        self.enable_oxidizer = enable_oxidizer
        self.enable_abobus = enable_abobus
        self.enable_dosfuscation = enable_dosfuscation
        self.enable_cradlecrafter = enable_cradlecrafter
        self.enable_bedecode = enable_bedecode
        self.eliminate_dead_code = eliminate_dead_code
        self.env_vars: Dict[str, str] = dict(self.DEFAULT_ENV)
        if custom_env:
            self.env_vars.update({k.lower(): v for k, v in custom_env.items()})
        self.pass_history: List[Dict[str, Any]] = []

    def extract_and_set_vars(self, line: str):
        """
        Identify 'set VAR=VAL' or 'set \"VAR=VAL\"' anywhere in line and register in symbol table.
        Robustly parses quoted syntax, value-quoted syntax (set v=\"val\"), caret-escaped ampersands,
        compound blocks, and switches (/a, /p).
        """
        keyword_pat = re.compile(r'(?:^|[;&@\(\)\s])set(?:\s+(?:/[ap]\s+)?|/[ap]\s*)', re.IGNORECASE)

        for m in keyword_pat.finditer(line):
            idx = m.end()
            if idx >= len(line):
                continue

            # Branch 1: Quoted assignment starting with double quote: set "VAR=VAL"
            if line[idx] == '"':
                q_m = re.match(r'\"([a-zA-Z0-9_\-\.\:\$%]+)=([^\"\r\n]*)\"?', line[idx:])
                if q_m:
                    var_name = q_m.group(1).lower()
                    var_val = q_m.group(2)
                    var_val = strip_carets(var_val)
                    var_val = self.resolve_variables(var_val, strip_undefined=False)
                    self.env_vars[var_name] = var_val
                    continue

            # Branch 2: Unquoted or value-quoted assignment: set VAR=VAL or set VAR="VAL"
            eq_idx = line.find('=', idx)
            if eq_idx == -1:
                continue
            var_name = line[idx:eq_idx].strip().lower()
            if not re.match(r'^[a-zA-Z0-9_\-\.\:\$%]+$', var_name):
                continue

            val_chars = []
            in_quotes = False
            local_parens = 0
            i = eq_idx + 1
            n = len(line)
            while i < n:
                ch = line[i]
                if ch == '"':
                    in_quotes = not in_quotes
                    val_chars.append(ch)
                    i += 1
                elif not in_quotes and ch == '^':
                    val_chars.append(ch)
                    if i + 1 < n:
                        val_chars.append(line[i + 1])
                        i += 2
                    else:
                        i += 1
                elif not in_quotes and ch == '(':
                    local_parens += 1
                    val_chars.append(ch)
                    i += 1
                elif not in_quotes and ch == ')':
                    if local_parens > 0:
                        local_parens -= 1
                        val_chars.append(ch)
                        i += 1
                    else:
                        break
                elif not in_quotes and ch == '&':
                    rest = line[i:]
                    if re.match(r'^&(?:\s|@|$|(?:set|echo|dir|copy|move|del|cls|call|start|cmd|powershell|whoami|curl|certutil|rem|if|goto)\b)', rest, re.IGNORECASE) or local_parens > 0:
                        break
                    else:
                        val_chars.append(ch)
                        i += 1
                else:
                    val_chars.append(ch)
                    i += 1

            var_val = "".join(val_chars).strip()
            var_val = strip_carets(var_val)
            var_val = self.resolve_variables(var_val, strip_undefined=False)
            self.env_vars[var_name] = var_val

    def resolve_variables(self, text: str, strip_undefined: bool = None) -> str:
        """Resolve standard %VAR%, delayed !VAR!, slicing %VAR:~0,1%, substitution %VAR:a=b%, and undefined stripping."""
        if strip_undefined is None:
            strip_undefined = self.strip_undefined

        prev = ""
        curr = text
        loop_limit = 10
        count = 0
        while prev != curr and count < loop_limit:
            prev = curr
            count += 1
            # 1. Slicing (%VAR:~...% and !VAR:~...!)
            curr = resolve_slicing(curr, self.env_vars)
            curr = resolve_dosfuscation_slicing(curr, self.env_vars)
            # 2. Substitution (%VAR:old=new% and !VAR:old=new!)
            curr = resolve_substitution(curr, self.env_vars)
            def del_sub_repl(m):
                var_name = m.group(1).lower()
                if var_name not in self.env_vars:
                    return m.group(0)
                val = self.env_vars[var_name]
                star = m.group(2)
                old_val = m.group(3)
                new_val = m.group(4)
                if star:
                    idx = val.lower().find(old_val.lower())
                    if idx != -1:
                        return new_val + val[idx + len(old_val):]
                    return val
                else:
                    return re.compile(re.escape(old_val), re.IGNORECASE).sub(lambda _: new_val, val)
            curr = re.sub(r'!([a-zA-Z0-9_\-\.\:\$]+):(\*?)([^=!\r\n]+)=([^!\r\n]*)!', del_sub_repl, curr)

            # 3. Simple %VAR% with optional undefined variable stripping
            def var_repl(match):
                name = match.group(1).lower()
                if name in self.env_vars:
                    return self.env_vars[name]
                if name in DYNAMIC_SYSTEM_VARS:
                    return match.group(0)
                if strip_undefined:
                    return ""
                return match.group(0)

            curr = re.sub(r'%([a-zA-Z0-9_\-\.\:\$]+)%', var_repl, curr)

            # 4. Simple delayed expansion !VAR!
            def del_var_repl(match):
                name = match.group(1).lower()
                if name in self.env_vars:
                    return self.env_vars[name]
                return match.group(0)

            curr = re.sub(r'!([a-zA-Z0-9_\-\.\:\$]+)!', del_var_repl, curr)
        if strip_undefined:
            curr = collapse_spaces_outside_quotes(curr)
        return curr

    def deobfuscate(self, script_text: str) -> Tuple[str, Dict[str, Any]]:
        """
        Execute iterative multi-pass fixed-point convergence loop.
        Returns:
            Tuple[clean_script, telemetry_metadata]
        """
        start_time = time.perf_counter()
        curr_text = script_text
        self.pass_history = []
        batcloak_sig = detect_batcloak_signatures(None, script_text)
        somalifuscator_sig = detect_somalifuscator_signatures(script_text)
        oxidizer_sig = detect_oxidizer_signatures(script_text)
        abobus_sig = detect_abobus_signatures(script_text)
        dosfuscation_sig = detect_dosfuscation_signatures(script_text)
        cradle_sig = detect_cradle_signatures(script_text)
        bedecode_sig = detect_bedecode_signatures(script_text)
        removed_random_vars: List[str] = []
        eliminated_dead_vars: List[str] = []
        somalifuscator_meta: Dict[str, Any] = {}
        oxidizer_meta: Dict[str, Any] = {}
        abobus_meta: Dict[str, Any] = {}
        bedecode_meta: Dict[str, Any] = {}
        dosfuscation_meta: Dict[str, Any] = {}
        cradle_meta: Dict[str, Any] = {}

        # Step 0: Split multi-line chained statements (&-splits outside quotes)
        if self.split_chains:
            curr_text = split_chained_commands(curr_text)

        # Step 0.5: BatCloak random variable pre-filtering
        if self.enable_batcloak:
            curr_text, removed_random_vars = strip_batcloak_random_vars(curr_text)

        # Step 0.6: Somalifuscator Caesar cipher inversion and array normalization
        if self.enable_somalifuscator:
            curr_text, somalifuscator_meta = normalize_somalifuscator(curr_text, custom_env=self.env_vars)

        # Step 0.7: 0xidiz3r zero-literal bootstrap resolution and alphabet normalization
        if self.enable_oxidizer:
            curr_text, oxidizer_meta = normalize_oxidizer(curr_text, custom_env=self.env_vars)

        # Step 0.75: Abobus Unicode noise filtering, decoy elimination, and trap chaff removal
        if self.enable_abobus:
            curr_text, abobus_meta = normalize_abobus(curr_text, custom_env=self.env_vars)

        # Step 0.77: Batch-Encryption-DeCoder (BEDeCode) runtime stub peeling & slice normalization
        if self.enable_bedecode:
            curr_text, bedecode_meta = normalize_bedecode(curr_text, custom_env=self.env_vars)

        # Step 0.78: Invoke-DOSfuscation Bohannon loop unwrapping and delimiter normalization
        if self.enable_dosfuscation:
            curr_text, dosfuscation_meta = normalize_dosfuscation(curr_text, custom_env=self.env_vars)

        # Step 0.79: Invoke-CradleCrafter PowerShell stager reconstruction & Base64 decoding
        if self.enable_cradlecrafter:
            curr_text, cradle_meta = normalize_cradlecrafter(curr_text, custom_env=self.env_vars)

        # Step 0.8: Pre-scan symbol table for set declarations across script
        for line in curr_text.splitlines():
            self.extract_and_set_vars(line)

        for p in range(1, self.max_passes + 1):
            prev_pass_text = curr_text
            lines = curr_text.splitlines()
            processed_lines = []

            for line in lines:
                # 1. Strip carets outside quotes
                l = strip_carets(line)
                # 2. Strip empty double quotes
                l = strip_empty_quotes(l)
                # 3. Resolve variables, slicing, and undefined variables
                l = self.resolve_variables(l)
                # 4. Harvest dynamic SET commands on resolved line
                self.extract_and_set_vars(l)
                processed_lines.append(l.strip())

            curr_text = "\n".join(processed_lines)

            # Record telemetry for this pass
            diff_chars = abs(len(curr_text) - len(prev_pass_text))
            self.pass_history.append({
                "pass": p,
                "length": len(curr_text),
                "delta": diff_chars,
                "converged": (curr_text == prev_pass_text)
            })

            # Check mathematical fixed-point convergence
            if curr_text == prev_pass_text:
                break

        # Step 4.5: Post-convergence CradleCrafter check for newly assembled stagers
        if self.enable_cradlecrafter and ("powershell" in curr_text.lower() or "-enc" in curr_text.lower() or "download" in curr_text.lower()):
            curr_text, post_cradle_meta = normalize_cradlecrafter(curr_text, custom_env=self.env_vars)
            if post_cradle_meta.get("is_cradle"):
                cradle_meta["is_cradle"] = True
                cradle_meta["confidence"] = max(cradle_meta.get("confidence", 0.0), post_cradle_meta.get("confidence", 0.0))
                cradle_meta["indicators"] = list(set(cradle_meta.get("indicators", []) + post_cradle_meta.get("indicators", [])))
                cradle_meta["signatures"] = post_cradle_meta.get("signatures", cradle_meta.get("signatures", {}))
            if post_cradle_meta.get("decoded_payloads"):
                if "decoded_payloads" not in cradle_meta:
                    cradle_meta["decoded_payloads"] = []
                cradle_meta["decoded_payloads"].extend(post_cradle_meta["decoded_payloads"])
                cradle_meta["decoded_payloads_count"] = len(cradle_meta["decoded_payloads"])
                cradle_meta["extracted_urls"] = list(set(cradle_meta.get("extracted_urls", []) + post_cradle_meta.get("extracted_urls", [])))
                cradle_meta["extracted_destinations"] = list(set(cradle_meta.get("extracted_destinations", []) + post_cradle_meta.get("extracted_destinations", [])))
                cradle_meta["cradle_methods"] = list(set(cradle_meta.get("cradle_methods", []) + post_cradle_meta.get("cradle_methods", [])))

        # Step 4.6: Post-convergence BEDeCode check for newly emerged table stubs
        if self.enable_bedecode and ("set '" in curr_text.lower() or "%':~" in curr_text or "%'~" in curr_text):
            curr_text, post_bedecode_meta = normalize_bedecode(curr_text, custom_env=self.env_vars)
            if post_bedecode_meta.get("is_bedecode"):
                bedecode_meta["is_bedecode"] = True
                bedecode_meta["confidence"] = max(bedecode_meta.get("confidence", 0.0), post_bedecode_meta.get("confidence", 0.0))
                bedecode_meta["indicators"] = list(set(bedecode_meta.get("indicators", []) + post_bedecode_meta.get("indicators", [])))
                bedecode_meta["layers_unwrapped"] = bedecode_meta.get("layers_unwrapped", 0) + post_bedecode_meta.get("layers_unwrapped", 0)
                bedecode_meta["slices_resolved"] = bedecode_meta.get("slices_resolved", 0) + post_bedecode_meta.get("slices_resolved", 0)

        # Step 5: Dead Store Elimination (DSE) for ephemeral alias variables & chaff
        if self.eliminate_dead_code:
            curr_text, eliminated_dead_vars = eliminate_dead_stores(curr_text)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        metadata = {
            "passes_executed": len(self.pass_history),
            "converged": self.pass_history[-1]["converged"] if self.pass_history else True,
            "elapsed_ms": round(elapsed_ms, 3),
            "symbols_resolved_count": len(self.env_vars) - len(self.DEFAULT_ENV),
            "symbol_table": {k: v for k, v in self.env_vars.items() if k not in self.DEFAULT_ENV},
            "pass_telemetry": self.pass_history,
            "batcloak_telemetry": {
                "detected": batcloak_sig["is_batcloak_family"],
                "confidence": batcloak_sig["confidence"],
                "indicators": batcloak_sig["indicators"],
                "removed_random_vars": removed_random_vars,
                "eliminated_dead_stores": eliminated_dead_vars,
            },
            "somalifuscator_telemetry": somalifuscator_meta or {
                "signatures": somalifuscator_sig,
                "rotation_value": None,
                "unwrapped_loops_count": 0,
                "kdot_detected": False,
                "caesar_symbols_count": 0,
                "eliminated_chaff_count": 0,
            },
            "oxidizer_telemetry": oxidizer_meta or {
                "signatures": oxidizer_sig,
                "is_oxidizer": oxidizer_sig["is_oxidizer"],
                "confidence": oxidizer_sig["confidence"],
                "bootstrap_vars": oxidizer_sig["bootstrap_vars"],
                "alphabet_size": 0,
                "eliminated_preamble_count": 0,
            },
            "abobus_telemetry": abobus_meta or {
                "signatures": abobus_sig,
                "is_abobus": abobus_sig["is_abobus"] if self.enable_abobus else False,
                "confidence": abobus_sig["confidence"] if self.enable_abobus else 0.0,
                "indicators": abobus_sig["indicators"] if self.enable_abobus else [],
                "eliminated_traps_count": 0,
                "stripped_noise_count": 0,
                "dictionaries_resolved_count": 0,
                "dictionary_variables": [],
            },
            "dosfuscation_telemetry": dosfuscation_meta or {
                "signatures": dosfuscation_sig,
                "is_dosfuscation": dosfuscation_sig["is_dosfuscation"] if self.enable_dosfuscation else False,
                "confidence": dosfuscation_sig["confidence"] if self.enable_dosfuscation else 0.0,
                "indicators": dosfuscation_sig["indicators"] if self.enable_dosfuscation else [],
                "unwrapped_loops_count": 0,
                "unwrapped_commands": [],
                "delimiters_normalized": False,
                "slicing_resolved": False,
            },
            "cradlecrafter_telemetry": cradle_meta or {
                "signatures": cradle_sig,
                "is_cradle": cradle_sig["is_cradle"] if self.enable_cradlecrafter else False,
                "confidence": cradle_sig["confidence"] if self.enable_cradlecrafter else 0.0,
                "indicators": cradle_sig["indicators"] if self.enable_cradlecrafter else [],
                "decoded_payloads_count": 0,
                "decoded_payloads": [],
                "extracted_urls": [],
                "extracted_destinations": [],
                "cradle_methods": [],
            },
            "bedecode_telemetry": bedecode_meta or {
                "signatures": bedecode_sig,
                "detected": bedecode_sig["is_bedecode"] if self.enable_bedecode else False,
                "is_bedecode": bedecode_sig["is_bedecode"] if self.enable_bedecode else False,
                "confidence": bedecode_sig["confidence"] if self.enable_bedecode else 0.0,
                "indicators": bedecode_sig["indicators"] if self.enable_bedecode else [],
                "layers_unwrapped": 0,
                "env_bootstraps_resolved": 0,
                "slices_resolved": 0,
            }
        }

        return curr_text, metadata

def deobfuscate_script(script_text: str, max_passes: int = 15, strip_undefined: bool = True,
                       split_chains: bool = True, enable_batcloak: bool = True,
                       enable_somalifuscator: bool = True,
                       enable_oxidizer: bool = True,
                       enable_abobus: bool = True,
                       enable_dosfuscation: bool = True,
                       enable_cradlecrafter: bool = True,
                       enable_bedecode: bool = True,
                       eliminate_dead_code: bool = True) -> str:
    """Convenience helper to deobfuscate a script and return clean string."""
    engine = BatchDeobfuscator(
        max_passes=max_passes,
        strip_undefined=strip_undefined,
        split_chains=split_chains,
        enable_batcloak=enable_batcloak,
        enable_somalifuscator=enable_somalifuscator,
        enable_oxidizer=enable_oxidizer,
        enable_abobus=enable_abobus,
        enable_dosfuscation=enable_dosfuscation,
        enable_cradlecrafter=enable_cradlecrafter,
        enable_bedecode=enable_bedecode,
        eliminate_dead_code=eliminate_dead_code,
    )
    clean_text, _ = engine.deobfuscate(script_text)
    return clean_text

def deobfuscate_bytes(data: bytes, max_passes: int = 15, strip_undefined: bool = True,
                      split_chains: bool = True, enable_batcloak: bool = True,
                      enable_somalifuscator: bool = True,
                      enable_oxidizer: bool = True,
                      enable_abobus: bool = True,
                      enable_dosfuscation: bool = True,
                      enable_cradlecrafter: bool = True,
                      enable_bedecode: bool = True,
                      eliminate_dead_code: bool = True) -> Tuple[str, Dict[str, Any]]:
    """
    Deobfuscate raw batch file bytes, neutralizing fake UTF-16LE BOM headers and decoys.
    Returns:
        Tuple[clean_script_text, forensic_metadata]
    """
    text, header_meta = normalize_batcloak_headers(data)
    engine = BatchDeobfuscator(
        max_passes=max_passes,
        strip_undefined=strip_undefined,
        split_chains=split_chains,
        enable_batcloak=enable_batcloak,
        enable_somalifuscator=enable_somalifuscator,
        enable_oxidizer=enable_oxidizer,
        enable_abobus=enable_abobus,
        enable_dosfuscation=enable_dosfuscation,
        enable_cradlecrafter=enable_cradlecrafter,
        enable_bedecode=enable_bedecode,
        eliminate_dead_code=eliminate_dead_code,
    )
    clean_text, meta = engine.deobfuscate(text)
    meta["header_metadata"] = header_meta
    return clean_text, meta
