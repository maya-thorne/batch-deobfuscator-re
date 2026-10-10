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
    def __init__(self, max_passes=15):
        self.max_passes = max_passes
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
            "path": r"C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem",
            "pathext": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"
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

    def strip_empty_quotes(self, text):
        """Strip consecutive empty quotes used for token fragmentation outside parameters (e.g., /a""l""l -> /all)."""
        # Normalize non-quoted empty quote pairs inserted between word characters
        return re.sub(r'([a-zA-Z0-9_\-\/\\])""([a-zA-Z0-9_\-\/\\])', r'\1\2', text)

    def extract_and_set_vars(self, line):
        """Identify 'set VAR=VAL' or 'set "VAR=VAL"' and record in symbol table."""
        # Clean line first
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

    def resolve_slicing(self, text):
        """Resolve %VAR:~start,length% and %VAR:~start%."""
        def slice_repl(match):
            var_name = match.group(1).lower()
            start = int(match.group(2))
            length = match.group(3)
            
            if var_name in self.env_vars:
                val = self.env_vars[var_name]
                if length is not None:
                    length = int(length)
                    if length < 0:
                        return val[start:length]
                    return val[start:start + length]
                else:
                    return val[start:]
            return match.group(0)

        # Regex for slicing: %VAR:~start[,length]%
        pattern = r'%([a-zA-Z0-9_\-\.\:\$]+):~(-?\d+)(?:,(-?\d+))?%'
        return re.sub(pattern, slice_repl, text)

    def resolve_variables(self, text):
        """Resolve simple %VAR% and slicing."""
        # 1. Resolve slicing first
        text = self.resolve_slicing(text)

        # 2. Resolve direct variable references %VAR%
        def var_repl(match):
            vname = match.group(1).lower()
            if vname in self.env_vars:
                return self.env_vars[vname]
            return match.group(0)

        pattern = r'%([a-zA-Z0-9_\-\.\:\$]+)%'
        return re.sub(pattern, var_repl, text)

    def deobfuscate(self, script_content):
        """Execute multi-pass deobfuscation until convergence."""
        current = script_content

        for pass_num in range(1, self.max_passes + 1):
            prev = current
            
            # Step 1: Strip carets and normalize fragmented empty quotes
            current = self.strip_carets(current)
            current = self.strip_empty_quotes(current)
            
            # Step 2: Line by line variable extraction and resolution
            lines = current.splitlines()
            processed_lines = []
            
            for line in lines:
                # Update variable table if it's a SET statement
                self.extract_and_set_vars(line)
                # Resolve variable expansions in the line
                resolved_line = self.resolve_variables(line)
                processed_lines.append(resolved_line)
                
            current = "\n".join(processed_lines)
            
            # Convergence check
            if current == prev:
                # print(f"[*] Deobfuscation converged at pass {pass_num}")
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
