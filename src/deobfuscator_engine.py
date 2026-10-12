#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Universal Batch Deobfuscator Engine (Multi-Pass Normalizer)
Synthesizes state-machine techniques from DissectMalware, KingKDot, 0xTas, and CrowTheBest.
"""

import re
import sys
import os

class BatchDeobfuscator:
    def __init__(self, max_passes=15, strip_undefined=True, split_chains=True):
        self.max_passes = max_passes
        self.strip_undefined = strip_undefined
        self.split_chains = split_chains
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
    }

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

        # Regex for slicing: %VAR:~start[,length]%
        pattern = r'%([a-zA-Z0-9_\-\.\:\$]+):~\s*(-?\d+)\s*(?:,\s*(-?\d+)\s*)?%'
        return re.sub(pattern, slice_repl, text)

    def resolve_variables(self, text, strip_undefined=None):
        """Resolve simple %VAR%, slicing, and undefined variable stripping."""
        if strip_undefined is None:
            strip_undefined = self.strip_undefined

        # 1. Resolve slicing first
        text = self.resolve_slicing(text)

        # 2. Resolve direct variable references %VAR%
        def var_repl(match):
            vname = match.group(1).lower()
            if vname in self.env_vars:
                return self.env_vars[vname]
            if vname in self.DYNAMIC_SYSTEM_VARS:
                return match.group(0)
            if strip_undefined:
                return ""
            return match.group(0)

        pattern = r'%([a-zA-Z0-9_\-\.\:\$]+)%'
        return re.sub(pattern, var_repl, text)

    def deobfuscate(self, script_content):
        """Execute multi-pass deobfuscation until convergence."""
        current = script_content

        if self.split_chains:
            current = self.split_chained_commands(current)

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
                processed_lines.append(resolved_line)
                
            current = "\n".join(processed_lines)
            
            # Convergence check
            if current == prev:
                break

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
