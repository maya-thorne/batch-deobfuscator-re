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
        "programfiles": r"C:\Program Files",
        "programfiles(x86)": r"C:\Program Files (x86)",
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
                 enable_batcloak: bool = True, eliminate_dead_code: bool = True):
        self.max_passes = max_passes
        self.strip_undefined = strip_undefined
        self.split_chains = split_chains
        self.enable_batcloak = enable_batcloak
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
        """Resolve standard %VAR%, slicing %VAR:~0,1%, substitution %VAR:a=b%, and undefined stripping."""
        if strip_undefined is None:
            strip_undefined = self.strip_undefined

        prev = ""
        curr = text
        loop_limit = 10
        count = 0
        while prev != curr and count < loop_limit:
            prev = curr
            count += 1
            # 1. Slicing
            curr = resolve_slicing(curr, self.env_vars)
            # 2. Substitution
            curr = resolve_substitution(curr, self.env_vars)
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
        removed_random_vars: List[str] = []
        eliminated_dead_vars: List[str] = []

        # Step 0: Split multi-line chained statements (&-splits outside quotes)
        if self.split_chains:
            curr_text = split_chained_commands(curr_text)

        # Step 0.5: BatCloak random variable pre-filtering
        if self.enable_batcloak:
            curr_text, removed_random_vars = strip_batcloak_random_vars(curr_text)

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
            }
        }

        return curr_text, metadata

def deobfuscate_script(script_text: str, max_passes: int = 15, strip_undefined: bool = True,
                       split_chains: bool = True, enable_batcloak: bool = True,
                       eliminate_dead_code: bool = True) -> str:
    """Convenience helper to deobfuscate a script and return clean string."""
    engine = BatchDeobfuscator(
        max_passes=max_passes,
        strip_undefined=strip_undefined,
        split_chains=split_chains,
        enable_batcloak=enable_batcloak,
        eliminate_dead_code=eliminate_dead_code,
    )
    clean_text, _ = engine.deobfuscate(script_text)
    return clean_text

def deobfuscate_bytes(data: bytes, max_passes: int = 15, strip_undefined: bool = True,
                      split_chains: bool = True, enable_batcloak: bool = True,
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
        eliminate_dead_code=eliminate_dead_code,
    )
    clean_text, meta = engine.deobfuscate(text)
    meta["header_metadata"] = header_meta
    return clean_text, meta
