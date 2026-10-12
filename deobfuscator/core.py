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
    DYNAMIC_SYSTEM_VARS,
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
    }

    def __init__(self, max_passes: int = 15, custom_env: Dict[str, str] = None, 
                 strip_undefined: bool = True, split_chains: bool = True):
        self.max_passes = max_passes
        self.strip_undefined = strip_undefined
        self.split_chains = split_chains
        self.env_vars: Dict[str, str] = dict(self.DEFAULT_ENV)
        if custom_env:
            self.env_vars.update({k.lower(): v for k, v in custom_env.items()})
        self.pass_history: List[Dict[str, Any]] = []

    def extract_and_set_vars(self, line: str):
        """Identify 'set VAR=VAL' or 'set \"VAR=VAL\"' anywhere in line and register in symbol table."""
        pattern = re.compile(
            r'(?:^|[;&@\(\)\s])set\s+(?:/[ap]\s+)?(?:\"([a-zA-Z0-9_\-\.\:\$]+)=([^\"\r\n]*)\"|([a-zA-Z0-9_\-\.\:\$]+)=([^\"&)\r\n]*))',
            re.IGNORECASE
        )
        for m in pattern.finditer(line):
            if m.group(1):
                var_name = m.group(1).lower()
                var_val = m.group(2)
            else:
                var_name = m.group(3).lower()
                var_val = m.group(4).strip()
            # Evaluate immediate slicing or substitution in value
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
            curr = re.sub(r' +', ' ', curr)
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

        # Step 0: Split multi-line chained statements (&-splits outside quotes)
        if self.split_chains:
            curr_text = split_chained_commands(curr_text)

        # Step 0.5: Pre-scan symbol table for set declarations across script
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
                processed_lines.append(l)

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

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        metadata = {
            "passes_executed": len(self.pass_history),
            "converged": self.pass_history[-1]["converged"] if self.pass_history else True,
            "elapsed_ms": round(elapsed_ms, 3),
            "symbols_resolved_count": len(self.env_vars) - len(self.DEFAULT_ENV),
            "symbol_table": {k: v for k, v in self.env_vars.items() if k not in self.DEFAULT_ENV},
            "pass_telemetry": self.pass_history
        }

        return curr_text, metadata

def deobfuscate_script(script_text: str, max_passes: int = 15, strip_undefined: bool = True, split_chains: bool = True) -> str:
    """Convenience helper to deobfuscate a script and return clean string."""
    engine = BatchDeobfuscator(max_passes=max_passes, strip_undefined=strip_undefined, split_chains=split_chains)
    clean_text, _ = engine.deobfuscate(script_text)
    return clean_text
