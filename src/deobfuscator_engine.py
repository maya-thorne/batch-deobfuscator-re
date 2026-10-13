#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Universal Batch Deobfuscator Engine (Multi-Pass Normalizer)
Synthesizes state-machine techniques from DissectMalware, KingKDot, 0xTas, and CrowTheBest.
"""

import re
import sys
import os
from pathlib import Path

# Try importing BatCloak, Somalifuscator, Oxidizer, Abobus & DOSfuscation modules from project root
try:
    from deobfuscator.batcloak import strip_batcloak_random_vars, eliminate_dead_stores
    from deobfuscator.somalifuscator import normalize_somalifuscator
    from deobfuscator.oxidizer import normalize_oxidizer
    from deobfuscator.abobus import normalize_abobus
    from deobfuscator.dosfuscation import normalize_dosfuscation
    HAS_SECURITY_MODULES = True
except ImportError:
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from deobfuscator.batcloak import strip_batcloak_random_vars, eliminate_dead_stores
        from deobfuscator.somalifuscator import normalize_somalifuscator
        from deobfuscator.oxidizer import normalize_oxidizer
        from deobfuscator.abobus import normalize_abobus
        from deobfuscator.dosfuscation import normalize_dosfuscation
        HAS_SECURITY_MODULES = True
    except ImportError:
        HAS_SECURITY_MODULES = False

class BatchDeobfuscator:
    def __init__(self, max_passes=15, strip_undefined=True, split_chains=True,
                 enable_batcloak=True, enable_somalifuscator=True, enable_oxidizer=True,
                 enable_abobus=True, enable_dosfuscation=True, eliminate_dead_code=True):
        self.max_passes = max_passes
        self.strip_undefined = strip_undefined
        self.split_chains = split_chains
        self.enable_batcloak = enable_batcloak
        self.enable_somalifuscator = enable_somalifuscator
        self.enable_oxidizer = enable_oxidizer
        self.enable_abobus = enable_abobus
        self.enable_dosfuscation = enable_dosfuscation
        self.eliminate_dead_code = eliminate_dead_code
        self.env_vars = {}
        # Prepopulate default Windows environment variables commonly used for slicing
        self.env_vars.update({
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
        })

    def strip_carets(self, text):
        """Strip carets outside quotes. If inside quotes, preserve them."""
        result = []
        in_quotes = False
        i = 0
        n = len(text)
        while i < n:
            char = text[i]
            if char == '"':
                in_quotes = not in_quotes
                result.append(char)
                i += 1
            elif char == '^':
                if in_quotes:
                    result.append(char)
                    i += 1
                else:
                    # Skip the caret, take the next char directly if available
                    if i + 1 < n:
                        result.append(text[i + 1])
                        i += 2
                    else:
                        i += 1
            else:
                result.append(char)
                i += 1
        return "".join(result)

    DYNAMIC_SYSTEM_VARS = {
        "errorlevel",
        "cd",
        "random",
        "date",
        "time",
        "cmdextversion",
        "cmdcmdline",
        "highestnumanodenumber",
        "__cd__",
        "__appdir__",
    }

    def collapse_spaces_outside_quotes(self, text):
        """Collapse consecutive spaces outside double quotes while preserving whitespace within strings."""
        result = []
        in_quotes = False
        space_pending = False
        for ch in text:
            if ch == '"':
                in_quotes = not in_quotes
                space_pending = False
                result.append(ch)
            elif not in_quotes:
                if ch == ' ':
                    if not space_pending:
                        result.append(' ')
                        space_pending = True
                else:
                    space_pending = False
                    result.append(ch)
            else:
                result.append(ch)
        return "".join(result)

    def strip_empty_quotes(self, text):
        """Flatten fragmented double quotes (e.g. w""h""o""a""m""i -> whoami, ""whoami -> whoami)."""
        prev = ""
        curr = text
        while prev != curr:
            prev = curr
            curr = re.sub(r'""+', '""', curr)
            curr = re.sub(r'([a-zA-Z0-9_\-\/\\\.\:%])""(?=[a-zA-Z0-9_\-\/\\\.\:%])', r'\1', curr)
            curr = re.sub(r'(^|[\s,;=@])""(?=[a-zA-Z0-9_\-\/\\\.\:%])', r'\1', curr)
            curr = re.sub(r'([a-zA-Z0-9_\-\/\\\.\:%])""(?=$|[\s,;=@\(\)&\|])', r'\1', curr)
        return curr

    def split_chained_commands(self, text):
        """Split single-line chained commands (& outside quotes/redirection/parens) into multiple lines."""
        result_lines = []
        for line in text.splitlines():
            stripped = line.strip()
            # Preserve comment and label lines
            if re.match(r'^@?\s*(?:rem\b|:)', stripped, re.IGNORECASE):
                result_lines.append(line)
                continue

            parts = []
            curr_part = []
            in_quotes = False
            paren_depth = 0
            i = 0
            n = len(line)
            while i < n:
                ch = line[i]
                if ch == '"':
                    in_quotes = not in_quotes
                    curr_part.append(ch)
                    i += 1
                elif not in_quotes and ch == '^':
                    curr_part.append(ch)
                    if i + 1 < n:
                        curr_part.append(line[i + 1])
                        i += 2
                    else:
                        i += 1
                elif not in_quotes and ch == '(':
                    paren_depth += 1
                    curr_part.append(ch)
                    i += 1
                elif not in_quotes and ch == ')':
                    if paren_depth > 0:
                        paren_depth -= 1
                    curr_part.append(ch)
                    i += 1
                elif not in_quotes and paren_depth == 0 and ch == '&':
                    current_prefix = "".join(curr_part).lstrip()
                    if re.match(r'^@?\s*(?:rem\b|:)', current_prefix, re.IGNORECASE):
                        curr_part.append(line[i:])
                        break

                    prev_str = "".join(curr_part).rstrip()
                    if (prev_str.endswith(">") or prev_str.endswith("<") or 
                        re.search(r'[0-9]?>\s*$', prev_str) or re.search(r'[0-9]?<\s*$', prev_str)):
                        curr_part.append(ch)
                        i += 1
                    elif i + 1 < n and line[i + 1] == '&':
                        part_str = "".join(curr_part).strip()
                        if part_str:
                            parts.append(part_str)
                        curr_part = []
                        i += 2
                    else:
                        part_str = "".join(curr_part).strip()
                        if part_str:
                            parts.append(part_str)
                        curr_part = []
                        i += 1
                else:
                    curr_part.append(ch)
                    i += 1
            part_str = "".join(curr_part).strip()
            if part_str:
                parts.append(part_str)
            if parts:
                result_lines.extend(parts)
            else:
                result_lines.append(line)
        return "\n".join(result_lines)

    def extract_and_set_vars(self, line):
        """Identify 'set VAR=VAL' or 'set \"VAR=VAL\"' anywhere in line and record in symbol table."""
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
                    var_val = self.strip_carets(var_val)
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
            var_val = self.strip_carets(var_val)
            var_val = self.resolve_variables(var_val, strip_undefined=False)
            self.env_vars[var_name] = var_val

    def resolve_slicing(self, text):
        """Resolve %VAR:~start,length% and %VAR:~start% with exact cmd.exe semantics."""
        def slice_repl(match):
            var_name = match.group(1).lower()
            start_str = match.group(2)
            len_str = match.group(3)
            
            if var_name in self.env_vars:
                val = self.env_vars[var_name]
                val_len = len(val)
                try:
                    start = int(start_str)
                    if start < 0:
                        start_idx = max(0, val_len + start)
                    else:
                        start_idx = min(val_len, start)

                    if len_str is not None:
                        length = int(len_str)
                        if length < 0:
                            end_idx = max(start_idx, val_len + length)
                        else:
                            end_idx = min(val_len, start_idx + length)
                    else:
                        end_idx = val_len

                    return val[start_idx:end_idx]
                except (ValueError, IndexError):
                    return match.group(0)
            return match.group(0)

        pattern = r'%([a-zA-Z0-9_\-\.\:\$]+):~\s*(-?\d+)\s*(?:,\s*(-?\d+)\s*)?%'
        return re.sub(pattern, slice_repl, text)

    def resolve_substitution(self, text):
        """Resolve %VAR:old=new% and %VAR:*old=new%."""
        def sub_repl(match):
            var_name = match.group(1).lower()
            if var_name not in self.env_vars:
                return match.group(0)

            val = self.env_vars[var_name]
            star = match.group(2)
            old = match.group(3)
            new = match.group(4)

            if star:
                idx = val.lower().find(old.lower())
                if idx != -1:
                    return new + val[idx + len(old):]
                return val
            else:
                pattern = re.compile(re.escape(old), re.IGNORECASE)
                return pattern.sub(lambda m: new, val)

        pattern = re.compile(r'%([a-zA-Z0-9_\-\.\:\$]+):(\*?)([^=]+)=([^%]*)%', re.IGNORECASE)
        return pattern.sub(sub_repl, text)

    def resolve_variables(self, text, strip_undefined=None):
        """Resolve simple %VAR%, slicing, substitution, and undefined variable stripping."""
        if strip_undefined is None:
            strip_undefined = self.strip_undefined

        prev = ""
        curr = text
        loop_limit = 10
        count = 0
        while prev != curr and count < loop_limit:
            prev = curr
            count += 1
            # 1. Resolve slicing
            curr = self.resolve_slicing(curr)
            # 2. Resolve substitution
            curr = self.resolve_substitution(curr)
            # 3. Direct variable references %VAR%
            def var_repl(match):
                vname = match.group(1).lower()
                if vname in self.env_vars:
                    return self.env_vars[vname]
                if vname in self.DYNAMIC_SYSTEM_VARS:
                    return match.group(0)
                if strip_undefined:
                    return ""
                return match.group(0)

            curr = re.sub(r'%([a-zA-Z0-9_\-\.\:\$]+)%', var_repl, curr)

        if strip_undefined:
            curr = self.collapse_spaces_outside_quotes(curr)
        return curr

    def deobfuscate(self, script_content):
        """Execute multi-pass deobfuscation until convergence."""
        current = script_content

        if self.split_chains:
            current = self.split_chained_commands(current)

        # Step 0.5: BatCloak random variable pre-filtering
        if self.enable_batcloak and HAS_SECURITY_MODULES:
            current, _ = strip_batcloak_random_vars(current)

        # Step 0.6: Somalifuscator Caesar cipher inversion and array normalization
        if self.enable_somalifuscator and HAS_SECURITY_MODULES:
            current, _ = normalize_somalifuscator(current, custom_env=self.env_vars)

        # Step 0.7: 0xidiz3r zero-literal bootstrap resolution and alphabet normalization
        if self.enable_oxidizer and HAS_SECURITY_MODULES:
            current, _ = normalize_oxidizer(current, custom_env=self.env_vars)

        # Step 0.75: Abobus Unicode noise filtering, decoy elimination, and trap chaff removal
        if self.enable_abobus and HAS_SECURITY_MODULES:
            current, _ = normalize_abobus(current, custom_env=self.env_vars)

        # Step 0.78: Invoke-DOSfuscation Bohannon loop unwrapping and delimiter normalization
        if self.enable_dosfuscation and HAS_SECURITY_MODULES:
            current, _ = normalize_dosfuscation(current, custom_env=self.env_vars)

        # Pre-scan symbol table across script
        for line in current.splitlines():
            self.extract_and_set_vars(line)

        for pass_num in range(1, self.max_passes + 1):
            prev = current
            
            # Step 1: Strip carets and normalize fragmented empty quotes
            current = self.strip_carets(current)
            current = self.strip_empty_quotes(current)
            
            # Step 2: Line by line variable resolution and dynamic extraction
            lines = current.splitlines()
            processed_lines = []
            
            for line in lines:
                # Resolve variable expansions in the line
                resolved_line = self.resolve_variables(line)
                # Update variable table if it's a SET statement on resolved line
                self.extract_and_set_vars(resolved_line)
                processed_lines.append(resolved_line.strip())
                
            current = "\n".join(processed_lines)
            
            # Convergence check
            if current == prev:
                break

        # Step 5: Dead Store Elimination for unreferenced variables and ephemeral aliases
        if self.eliminate_dead_code and HAS_SECURITY_MODULES:
            current, _ = eliminate_dead_stores(current)

        return current


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python deobfuscator_engine.py <input.bat> [output.bat]")
        sys.exit(1)

    in_file = sys.argv[1]
    out_file = sys.argv[2] if len(sys.argv) > 2 else in_file + ".deobf.bat"

    with open(in_file, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    engine = BatchDeobfuscator()
    clean = engine.deobfuscate(content)

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(clean)

    print(f"[+] Deobfuscation complete. Result saved to: {out_file}")
