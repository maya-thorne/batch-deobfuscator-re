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
    resolve_slicing,
    resolve_substitution,
    normalize_bom,
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
        "path": r"C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem",
        "pathext": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
    }

    def __init__(self, max_passes: int = 15, custom_env: Dict[str, str] = None):
        self.max_passes = max_passes
        self.env_vars: Dict[str, str] = dict(self.DEFAULT_ENV)
        if custom_env:
            self.env_vars.update({k.lower(): v for k, v in custom_env.items()})
        self.pass_history: List[Dict[str, Any]] = []

    def extract_and_set_vars(self, line: str):
        """Identify 'set VAR=VAL' or 'set \"VAR=VAL\"' and register in symbol table."""
        cleaned = line.strip()
        if cleaned.lower().startswith("@set "):
            cleaned = cleaned[1:]

        m = re.match(r'^set\s+(?:/a\s+|/p\s+)?(?:")?([a-zA-Z0-9_\-\.\:\$]+)=([^"\r\n]*)(?:")?', cleaned, re.IGNORECASE)
        if m:
            var_name = m.group(1).lower()
            var_val = m.group(2)
            # Evaluate immediate slicing or substitution in value
            var_val = self.resolve_variables(var_val)
            self.env_vars[var_name] = var_val

    def resolve_variables(self, text: str) -> str:
        """Resolve standard %VAR%, slicing %VAR:~0,1%, and substitution %VAR:a=b%."""
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
            # 3. Simple %VAR%
            def var_repl(match):
                name = match.group(1).lower()
                return self.env_vars.get(name, match.group(0))

            curr = re.sub(r'%([a-zA-Z0-9_\-\.\:\$]+)%', var_repl, curr)
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

        for p in range(1, self.max_passes + 1):
            prev_pass_text = curr_text
            lines = curr_text.splitlines()
            processed_lines = []

            for line in lines:
                # 1. Strip carets outside quotes
                l = strip_carets(line)
                # 2. Strip empty double quotes
                l = strip_empty_quotes(l)
                # 3. Harvest dynamic SET commands
                self.extract_and_set_vars(l)
                # 4. Resolve variables and slicing
                l = self.resolve_variables(l)
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

def deobfuscate_script(script_text: str, max_passes: int = 15) -> str:
    """Convenience helper to deobfuscate a script and return clean string."""
    engine = BatchDeobfuscator(max_passes=max_passes)
    clean_text, _ = engine.deobfuscate(script_text)
    return clean_text
