"""
Core Multi-Pass Fixed-Point Deobfuscator Engine.
Deterministic convergence loop with dynamic symbol table resolution and virtual sandbox state.
Synthesizes state-machine techniques across all specialized deobfuscator modules.

Engineered by Maya Thorne.
"""

import re
import time
from typing import Dict, Any, Tuple, List, Optional
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
    zeroize_dict,
    zeroize_bytes,
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
from .batchshield import (
    normalize_batchshield,
    detect_batchshield_signatures,
    BatchShieldNormalizer,
)
from .pandacrypter import (
    normalize_pandacrypter,
    detect_pandacrypter_signatures,
    detect_certutil_signatures,
    PandaCrypterNormalizer,
)
from .exorcism import (
    normalize_exorcism,
    detect_exorcism_signatures,
    ExorcismNormalizer,
)
from .batchtoapp import (
    normalize_batchtoapp,
    detect_batchtoapp_signatures,
    inspect_batchtoapp_pe,
    BatchToAppNormalizer,
)
from .machine1337 import (
    normalize_machine1337,
    detect_machine1337_signatures,
    neutralize_machine1337_headers,
    is_machine1337_header,
    Machine1337Normalizer,
)
from .cmd_deobfuscator import (
    normalize_cmd_deobfuscator,
    detect_cmd_deobfuscator_signatures,
    CMDDeobfuscatorNormalizer,
)
from .simple_obfuscator import (
    normalize_simple_obfuscator,
    detect_simple_obfuscator_signatures,
    SimpleObfuscatorNormalizer,
)
from .jsbatch import (
    normalize_jsbatch,
    detect_jsbatch_signatures,
    JSBatchNormalizer,
)
from .batchstealer import (
    normalize_batchstealer,
    detect_batchstealer_signatures,
    BatchStealerNormalizer,
)
from .wirebits import (
    normalize_wirebits,
    detect_wirebits_signatures,
    neutralize_wirebits_headers,
    WireBitsNormalizer,
    SPLICED_VAR_REF_RE,
)
from .telemetry import assemble_deobfuscator_metadata


def _merge_meta(dest: Dict[str, Any], src: Dict[str, Any], bool_key: Optional[str] = None) -> None:
    """Helper to merge post-convergence metadata without code bloat."""
    if bool_key:
        dest[bool_key] = True
    dest["confidence"] = max(dest.get("confidence", 0.0), src.get("confidence", 0.0))
    dest["indicators"] = list(set(dest.get("indicators", []) + src.get("indicators", [])))
    for k, v in src.items():
        if k in ("confidence", "indicators") or k == bool_key:
            continue
        if isinstance(v, (int, float)) and isinstance(dest.get(k), (int, float)):
            dest[k] = dest.get(k, 0) + v
        elif isinstance(v, list) and isinstance(dest.get(k), list):
            dest[k].extend(v)
        else:
            dest[k] = v


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
                 enable_dosfuscation: bool = True, enable_cradlecrafter: bool = True,
                 enable_bedecode: bool = True, enable_batchshield: bool = True,
                 enable_pandacrypter: bool = True, enable_exorcism: bool = True,
                 enable_batchtoapp: bool = True, enable_machine1337: bool = True,
                 enable_cmd_deobfuscator: bool = True,
                 enable_simple_obfuscator: bool = True,
                 enable_jsbatch: bool = True,
                 enable_batchstealer: bool = True,
                 enable_wirebits: bool = True,
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
        self.enable_batchshield = enable_batchshield
        self.enable_pandacrypter = enable_pandacrypter
        self.enable_exorcism = enable_exorcism
        self.enable_batchtoapp = enable_batchtoapp
        self.enable_machine1337 = enable_machine1337
        self.enable_cmd_deobfuscator = enable_cmd_deobfuscator
        self.enable_simple_obfuscator = enable_simple_obfuscator
        self.enable_jsbatch = enable_jsbatch
        self.enable_batchstealer = enable_batchstealer
        self.enable_wirebits = enable_wirebits
        self.eliminate_dead_code = eliminate_dead_code
        self.env_vars: Dict[str, str] = dict(self.DEFAULT_ENV)
        if custom_env:
            self.env_vars.update({k.lower(): v for k, v in custom_env.items()})
        self.pass_history: List[Dict[str, Any]] = []

    def zeroize(self) -> None:
        """Cryptographically sanitize symbol tables, label maps, and pass history buffers."""
        zeroize_dict(self.env_vars)
        for entry in self.pass_history:
            if isinstance(entry, dict):
                zeroize_dict(entry)
        self.pass_history.clear()

    def __del__(self):
        try:
            self.zeroize()
        except Exception:
            pass

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
                    pat = re.compile(re.escape(old_val), re.IGNORECASE)
                    return pat.sub(lambda _: new_val, val)
            curr = re.sub(r'!([a-zA-Z0-9_\-\.\:\$]+):(\*?)([^=!]+)=([^!]*)!', del_sub_repl, curr)

            # 3. Direct variable references (%VAR% and !VAR!)
            def var_repl(match):
                vname = match.group(1).lower()
                if vname in self.env_vars:
                    return self.env_vars[vname]
                if vname in DYNAMIC_SYSTEM_VARS:
                    return match.group(0)
                if strip_undefined:
                    return ""
                return match.group(0)

            curr = re.sub(r'%([a-zA-Z0-9_\-\.\:\$]+)%', var_repl, curr)
            curr = re.sub(r'!([a-zA-Z0-9_\-\.\:\$]+)!', var_repl, curr)

        if strip_undefined:
            curr = collapse_spaces_outside_quotes(curr)
        return curr

    def deobfuscate(self, script_text: str) -> Tuple[str, Dict[str, Any]]:
        """
        Execute multi-pass deobfuscation until convergence or pass limit.
        Returns:
            Tuple[clean_script_text, forensic_metadata]
        """
        start_time = time.perf_counter()
        curr_text = script_text

        # Heuristic detection for metadata across specialized engines
        batcloak_sig = detect_batcloak_signatures(None, script_text)
        somalifuscator_sig = detect_somalifuscator_signatures(script_text)
        oxidizer_sig = detect_oxidizer_signatures(script_text)
        abobus_sig = detect_abobus_signatures(script_text) if self.enable_abobus else {"is_abobus": False, "confidence": 0.0, "indicators": []}
        dosfuscation_sig = detect_dosfuscation_signatures(script_text)
        cradle_sig = detect_cradle_signatures(script_text)
        bedecode_sig = detect_bedecode_signatures(script_text)
        batchshield_sig = detect_batchshield_signatures(script_text)
        pandacrypter_sig = detect_pandacrypter_signatures(script_text)
        certutil_sig = detect_certutil_signatures(script_text)
        exorcism_sig = detect_exorcism_signatures(script_text) if self.enable_exorcism else {"is_exorcism": False, "confidence": 0.0, "indicators": []}
        batchtoapp_sig = detect_batchtoapp_signatures(script_text) if self.enable_batchtoapp else {"is_batchtoapp": False, "confidence": 0.0, "indicators": []}
        machine1337_sig = detect_machine1337_signatures(None, script_text) if self.enable_machine1337 else {"is_machine1337": False, "confidence": 0.0, "indicators": []}
        cmd_deobfuscator_sig = detect_cmd_deobfuscator_signatures(script_text) if self.enable_cmd_deobfuscator else {"is_cmd_deobfuscator": False, "confidence": 0.0, "indicators": []}
        simple_obfuscator_sig = detect_simple_obfuscator_signatures(script_text) if self.enable_simple_obfuscator else {"is_simple_obfuscator": False, "confidence": 0.0, "indicators": []}
        jsbatch_sig = detect_jsbatch_signatures(script_text) if self.enable_jsbatch else {"is_jsbatch": False, "confidence": 0.0, "indicators": []}
        batchstealer_sig = detect_batchstealer_signatures(script_text) if self.enable_batchstealer else {"is_batchstealer": False, "confidence": 0.0, "indicators": []}
        wirebits_sig = detect_wirebits_signatures(script_text) if self.enable_wirebits else {"is_wirebits": False, "confidence": 0.0, "indicators": []}

        removed_random_vars: List[str] = []
        eliminated_dead_vars: List[str] = []
        somalifuscator_meta, oxidizer_meta, batchtoapp_meta, machine1337_meta = {}, {}, {}, {}
        cmd_deobfuscator_meta, simple_obfuscator_meta, jsbatch_meta = {}, {}, {}
        batchstealer_meta, exorcism_meta, abobus_meta, batchshield_meta = {}, {}, {}, {}
        bedecode_meta, dosfuscation_meta, cradle_meta, pandacrypter_meta, wirebits_meta = {}, {}, {}, {}, {}

        # Step 0: Split multi-line chained statements (&-splits outside quotes)
        if self.split_chains:
            curr_text = split_chained_commands(curr_text)

        # Step 0.5: BatCloak random variable pre-filtering
        if self.enable_batcloak:
            curr_text, removed_random_vars = strip_batcloak_random_vars(curr_text)

        # Step 0.51: JSBatchDeobfuscator alphabet slicing, chained tokens & hybrid polyglot extraction
        if self.enable_jsbatch:
            curr_text, jsbatch_meta = normalize_jsbatch(curr_text, custom_env=self.env_vars)

        # Step 0.52: simple-batch-obfuscator random variable fragment infiltration & chunk assembly
        if self.enable_simple_obfuscator:
            curr_text, simple_obfuscator_meta = normalize_simple_obfuscator(curr_text, custom_env=self.env_vars)

        # Step 0.53: BatchStealer credential harvester and C2 webhook normalizer
        if self.enable_batchstealer:
            curr_text, batchstealer_meta = normalize_batchstealer(curr_text, custom_env=self.env_vars)

        # Step 0.54: BatchObfuscator-wirebits header, escape, casting & char splicing normalization
        if self.enable_wirebits:
            curr_text, wirebits_meta = normalize_wirebits(curr_text, custom_env=self.env_vars)

        # Step 0.55: batobfuscate-machine1337 fake header de-masking, CJK transcode & caret normalization
        if self.enable_machine1337:
            curr_text, machine1337_meta = normalize_machine1337(curr_text, custom_env=self.env_vars)

        # Step 0.6: Somalifuscator Caesar cipher inversion and array normalization
        if self.enable_somalifuscator:
            curr_text, somalifuscator_meta = normalize_somalifuscator(curr_text, custom_env=self.env_vars)

        # Step 0.7: 0xidiz3r zero-literal bootstrap resolution and alphabet normalization
        if self.enable_oxidizer:
            curr_text, oxidizer_meta = normalize_oxidizer(curr_text, custom_env=self.env_vars)

        # Step 0.72: BatchToApp / DosX native wrapper and operator table normalizer
        if self.enable_batchtoapp:
            curr_text, batchtoapp_meta = normalize_batchtoapp(curr_text, custom_env=self.env_vars)

        # Step 0.73: Exorcism control flow normalization, jump trampolines & opaque predicates
        if self.enable_exorcism:
            curr_text, exorcism_meta = normalize_exorcism(curr_text, custom_env=self.env_vars)

        # Step 0.74: PandaCrypter colon noise stripping and Certutil stager payload recovery
        if self.enable_pandacrypter:
            curr_text, pandacrypter_meta = normalize_pandacrypter(curr_text, custom_env=self.env_vars)

        # Step 0.75: Abobus Unicode noise filtering, decoy elimination, and trap chaff removal
        if self.enable_abobus:
            curr_text, abobus_meta = normalize_abobus(curr_text, custom_env=self.env_vars)

        # Step 0.76: BatchShield virtual symbol table & compound env chain deobfuscation
        if self.enable_batchshield:
            curr_text, batchshield_meta = normalize_batchshield(curr_text, custom_env=self.env_vars)

        # Step 0.77: Batch-Encryption-DeCoder (BEDeCode) runtime stub peeling & slice normalization
        if self.enable_bedecode:
            curr_text, bedecode_meta = normalize_bedecode(curr_text, custom_env=self.env_vars)

        # Step 0.78: Invoke-DOSfuscation Bohannon loop unwrapping and delimiter normalization
        if self.enable_dosfuscation:
            curr_text, dosfuscation_meta = normalize_dosfuscation(curr_text, custom_env=self.env_vars)

        # Step 0.79: Invoke-CradleCrafter PowerShell stager reconstruction & Base64 decoding
        if self.enable_cradlecrafter:
            curr_text, cradle_meta = normalize_cradlecrafter(curr_text, custom_env=self.env_vars)

        # Step 0.795: CMD-DeObfuscator chained variables, quote widening, and nested cmd flattening
        if self.enable_cmd_deobfuscator:
            curr_text, cmd_deobfuscator_meta = normalize_cmd_deobfuscator(curr_text, custom_env=self.env_vars)

        # Step 0.8: Pre-scan symbol table for set declarations across script
        for line in curr_text.splitlines():
            self.extract_and_set_vars(line)

        for p in range(1, self.max_passes + 1):
            prev_pass_text = curr_text
            lines = curr_text.splitlines()
            processed_lines = []

            for line in lines:
                l = strip_carets(line)
                l = strip_empty_quotes(l)
                l = self.resolve_variables(l)
                self.extract_and_set_vars(l)
                processed_lines.append(l.strip())

            curr_text = "\n".join(processed_lines)
            diff_chars = abs(len(curr_text) - len(prev_pass_text))
            self.pass_history.append({
                "pass": p,
                "length": len(curr_text),
                "delta": diff_chars,
                "converged": (curr_text == prev_pass_text)
            })

            if curr_text == prev_pass_text:
                break

        # Step 4.4: Post-convergence JSBatch check for newly unmasked slices or polyglot blocks
        if self.enable_jsbatch and ("cscript" in curr_text.lower() or "/* ::" in curr_text or "@codesection" in curr_text.lower() or "%ab9:~" in curr_text.lower()):
            curr_text, post_jsbatch_meta = normalize_jsbatch(curr_text, custom_env=self.env_vars)
            if post_jsbatch_meta.get("is_jsbatch") or post_jsbatch_meta.get("is_polyglot"):
                _merge_meta(jsbatch_meta, post_jsbatch_meta, "is_jsbatch")

        # Step 4.5: Post-convergence CradleCrafter check for newly assembled stagers
        if self.enable_cradlecrafter and ("powershell" in curr_text.lower() or "-enc" in curr_text.lower() or "download" in curr_text.lower()):
            curr_text, post_cradle_meta = normalize_cradlecrafter(curr_text, custom_env=self.env_vars)
            if post_cradle_meta.get("is_cradle"):
                _merge_meta(cradle_meta, post_cradle_meta, "is_cradle")

        # Step 4.6: Post-convergence BEDeCode check for newly emerged table stubs
        if self.enable_bedecode and ("set '" in curr_text.lower() or "%':~" in curr_text or "%'~" in curr_text):
            curr_text, post_bedecode_meta = normalize_bedecode(curr_text, custom_env=self.env_vars)
            if post_bedecode_meta.get("is_bedecode"):
                _merge_meta(bedecode_meta, post_bedecode_meta, "is_bedecode")

        # Step 4.7: Post-convergence BatchShield check for newly emerged compound chains
        if self.enable_batchshield and ("%comspec:~" in curr_text.lower() or "%windir:~" in curr_text.lower() or "%systemroot:~" in curr_text.lower()):
            curr_text, post_batchshield_meta = normalize_batchshield(curr_text, custom_env=self.env_vars)
            if post_batchshield_meta.get("is_batchshield"):
                _merge_meta(batchshield_meta, post_batchshield_meta, "is_batchshield")

        # Step 4.8: Post-convergence PandaCrypter / Certutil check for newly emerged stagers
        if self.enable_pandacrypter and ("certutil" in curr_text.lower() or "-decode" in curr_text.lower() or ":::" in curr_text):
            curr_text, post_panda_meta = normalize_pandacrypter(curr_text, custom_env=self.env_vars)
            if post_panda_meta.get("is_certutil") or post_panda_meta.get("is_pandacrypter"):
                _merge_meta(pandacrypter_meta, post_panda_meta, "is_certutil")

        # Step 4.9: Post-convergence Exorcism control flow normalization for newly unmasked jumps
        if self.enable_exorcism and ("goto :" in curr_text.lower() or "call :" in curr_text.lower() or "if 1==" in curr_text):
            curr_text, post_exorcism_meta = normalize_exorcism(curr_text, custom_env=self.env_vars)
            if post_exorcism_meta.get("is_exorcism") or post_exorcism_meta.get("trampolines_collapsed", 0) > 0:
                _merge_meta(exorcism_meta, post_exorcism_meta, "is_exorcism")

        # Step 4.95: Post-convergence BatchToApp check for newly unmasked operator variables or fake labels
        if self.enable_batchtoapp and (":label_0x" in curr_text or "b2a_exitprocess" in curr_text.lower() or "@shift /0" in curr_text.lower() or ":~4" in curr_text or ":~5" in curr_text or "=^)" in curr_text):
            curr_text, post_b2a_meta = normalize_batchtoapp(curr_text, custom_env=self.env_vars)
            if post_b2a_meta.get("is_batchtoapp"):
                _merge_meta(batchtoapp_meta, post_b2a_meta, "is_batchtoapp")

        # Step 4.96: Post-convergence WireBits check for newly unmasked escape sequences or char splicing
        if self.enable_wirebits and ("\\x" in curr_text or "\\0" in curr_text or "%_1%" in curr_text or "[char]" in curr_text.lower() or SPLICED_VAR_REF_RE.search(curr_text)):
            curr_text, post_wb_meta = normalize_wirebits(curr_text, custom_env=self.env_vars)
            if post_wb_meta.get("is_wirebits"):
                _merge_meta(wirebits_meta, post_wb_meta, "is_wirebits")

        # Step 5: Dead Store Elimination (DSE) for ephemeral alias variables & chaff
        if self.eliminate_dead_code:
            curr_text, eliminated_dead_vars = eliminate_dead_stores(curr_text)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        metadata = assemble_deobfuscator_metadata(
            elapsed_ms=elapsed_ms, pass_history=self.pass_history, env_vars=self.env_vars,
            default_env=self.DEFAULT_ENV, batcloak_sig=batcloak_sig,
            removed_random_vars=removed_random_vars, eliminated_dead_vars=eliminated_dead_vars,
            somalifuscator_meta=somalifuscator_meta, somalifuscator_sig=somalifuscator_sig,
            oxidizer_meta=oxidizer_meta, oxidizer_sig=oxidizer_sig,
            abobus_meta=abobus_meta, abobus_sig=abobus_sig, enable_abobus=self.enable_abobus,
            dosfuscation_meta=dosfuscation_meta, dosfuscation_sig=dosfuscation_sig, enable_dosfuscation=self.enable_dosfuscation,
            cradle_meta=cradle_meta, cradle_sig=cradle_sig, enable_cradlecrafter=self.enable_cradlecrafter,
            bedecode_meta=bedecode_meta, bedecode_sig=bedecode_sig, enable_bedecode=self.enable_bedecode,
            batchshield_meta=batchshield_meta, batchshield_sig=batchshield_sig, enable_batchshield=self.enable_batchshield,
            pandacrypter_meta=pandacrypter_meta, pandacrypter_sig=pandacrypter_sig, certutil_sig=certutil_sig, enable_pandacrypter=self.enable_pandacrypter,
            exorcism_meta=exorcism_meta, exorcism_sig=exorcism_sig, enable_exorcism=self.enable_exorcism,
            batchtoapp_meta=batchtoapp_meta, batchtoapp_sig=batchtoapp_sig, enable_batchtoapp=self.enable_batchtoapp,
            machine1337_meta=machine1337_meta, machine1337_sig=machine1337_sig, enable_machine1337=self.enable_machine1337,
            cmd_deobfuscator_meta=cmd_deobfuscator_meta, cmd_deobfuscator_sig=cmd_deobfuscator_sig, enable_cmd_deobfuscator=self.enable_cmd_deobfuscator,
            simple_obfuscator_meta=simple_obfuscator_meta, simple_obfuscator_sig=simple_obfuscator_sig, enable_simple_obfuscator=self.enable_simple_obfuscator,
            jsbatch_meta=jsbatch_meta, jsbatch_sig=jsbatch_sig, enable_jsbatch=self.enable_jsbatch,
            batchstealer_meta=batchstealer_meta, batchstealer_sig=batchstealer_sig, enable_batchstealer=self.enable_batchstealer,
            wirebits_meta=wirebits_meta, wirebits_sig=wirebits_sig, enable_wirebits=self.enable_wirebits,
        )

        return curr_text, metadata


def deobfuscate_script(script_text: str, max_passes: int = 15, strip_undefined: bool = True,
                       split_chains: bool = True, enable_batcloak: bool = True,
                       enable_somalifuscator: bool = True, enable_oxidizer: bool = True,
                       enable_abobus: bool = True, enable_dosfuscation: bool = True,
                       enable_cradlecrafter: bool = True, enable_bedecode: bool = True,
                       enable_batchshield: bool = True, enable_pandacrypter: bool = True,
                       enable_exorcism: bool = True, enable_batchtoapp: bool = True,
                       enable_machine1337: bool = True, enable_cmd_deobfuscator: bool = True,
                       enable_simple_obfuscator: bool = True,
                       enable_jsbatch: bool = True,
                       enable_batchstealer: bool = True,
                       enable_wirebits: bool = True,
                       eliminate_dead_code: bool = True) -> str:
    """Convenience helper to deobfuscate a script and return clean string."""
    engine = BatchDeobfuscator(
        max_passes=max_passes, strip_undefined=strip_undefined, split_chains=split_chains,
        enable_batcloak=enable_batcloak, enable_somalifuscator=enable_somalifuscator,
        enable_oxidizer=enable_oxidizer, enable_abobus=enable_abobus,
        enable_dosfuscation=enable_dosfuscation, enable_cradlecrafter=enable_cradlecrafter,
        enable_bedecode=enable_bedecode, enable_batchshield=enable_batchshield,
        enable_pandacrypter=enable_pandacrypter, enable_exorcism=enable_exorcism,
        enable_batchtoapp=enable_batchtoapp, enable_machine1337=enable_machine1337,
        enable_cmd_deobfuscator=enable_cmd_deobfuscator,
        enable_simple_obfuscator=enable_simple_obfuscator,
        enable_jsbatch=enable_jsbatch,
        enable_batchstealer=enable_batchstealer,
        enable_wirebits=enable_wirebits,
        eliminate_dead_code=eliminate_dead_code,
    )
    clean_text, _ = engine.deobfuscate(script_text)
    return clean_text


def deobfuscate_bytes(data: bytes, max_passes: int = 15, strip_undefined: bool = True,
                       split_chains: bool = True, enable_batcloak: bool = True,
                       enable_somalifuscator: bool = True, enable_oxidizer: bool = True,
                       enable_abobus: bool = True, enable_dosfuscation: bool = True,
                       enable_cradlecrafter: bool = True, enable_bedecode: bool = True,
                       enable_batchshield: bool = True, enable_pandacrypter: bool = True,
                       enable_exorcism: bool = True, enable_batchtoapp: bool = True,
                       enable_machine1337: bool = True,
                       enable_cmd_deobfuscator: bool = True,
                       enable_simple_obfuscator: bool = True,
                       enable_jsbatch: bool = True,
                       enable_batchstealer: bool = True,
                       enable_wirebits: bool = True,
                       eliminate_dead_code: bool = True) -> Tuple[str, Dict[str, Any]]:
    """
    Deobfuscate raw batch file bytes, neutralizing fake UTF-16LE BOM headers and decoys.
    If binary data is a BatchToApp PE executable, extracts embedded batch script payload.
    If binary data has machine1337 multi-BOM header, extracts clean decoded script.
    If binary data has WireBits header (//4mY2xzDQo= / \xff\xfe&cls\r\n), neutralizes header.
    Returns:
        Tuple[clean_script_text, forensic_metadata]
    """
    b2a_pe = inspect_batchtoapp_pe(data) if enable_batchtoapp else {"is_pe": False, "has_embedded_script": False}
    if b2a_pe.get("has_embedded_script") and b2a_pe.get("extracted_script"):
        text = b2a_pe["extracted_script"]
        header_meta = {"pe_extracted": True, "b2a_pe": b2a_pe}
    elif enable_machine1337 and is_machine1337_header(data)[0]:
        text, header_meta = neutralize_machine1337_headers(data)
    else:
        text, header_meta = normalize_batcloak_headers(data)

    engine = BatchDeobfuscator(
        max_passes=max_passes, strip_undefined=strip_undefined, split_chains=split_chains,
        enable_batcloak=enable_batcloak, enable_somalifuscator=enable_somalifuscator,
        enable_oxidizer=enable_oxidizer, enable_abobus=enable_abobus,
        enable_dosfuscation=enable_dosfuscation, enable_cradlecrafter=enable_cradlecrafter,
        enable_bedecode=enable_bedecode, enable_batchshield=enable_batchshield,
        enable_pandacrypter=enable_pandacrypter, enable_exorcism=enable_exorcism,
        enable_batchtoapp=enable_batchtoapp, enable_machine1337=enable_machine1337,
        enable_cmd_deobfuscator=enable_cmd_deobfuscator,
        enable_simple_obfuscator=enable_simple_obfuscator,
        enable_jsbatch=enable_jsbatch,
        enable_batchstealer=enable_batchstealer,
        enable_wirebits=enable_wirebits,
        eliminate_dead_code=eliminate_dead_code,
    )
    clean_text, meta = engine.deobfuscate(text)
    meta["header_metadata"] = header_meta
    if header_meta.get("is_machine1337"):
        meta["machine1337_telemetry"]["is_machine1337"] = True
        meta["machine1337_telemetry"]["header_stripped"] = True
        meta["machine1337_telemetry"]["header_variant"] = header_meta.get("header_variant", "none")
        meta["machine1337_telemetry"]["stripped_bytes"] = header_meta.get("stripped_bytes", 0)
        if header_meta.get("cls_preamble_stripped"):
            meta["machine1337_telemetry"]["cls_preamble_stripped"] = True
    if enable_batchtoapp and b2a_pe.get("is_batchtoapp"):
        meta["batchtoapp_pe"] = b2a_pe
    return clean_text, meta
