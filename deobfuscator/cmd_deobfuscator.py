"""
CMD-DeObfuscator Multi-Level Chained Environment Variable & Syntax Normalizer.
Resolves deeply nested variable dependency graphs, detects cycles, expands delayed variables,
widens fragmented quotes, flattens redundant nested cmd.exe shells, and normalizes delimiters.
Part of batch-deobfuscator-re toolchain.

Engineered by Maya Thorne.
"""

import re
from typing import Dict, Any, Tuple, List, Set, Optional


def zeroize_dict(target: Dict[str, Any]) -> None:
    """Cryptographically sanitize dictionary buffers in memory."""
    for key in list(target.keys()):
        val = target[key]
        if isinstance(val, dict):
            zeroize_dict(val)
        elif isinstance(val, list):
            for i in range(len(val)):
                val[i] = None
            val.clear()
        elif isinstance(val, bytearray):
            for i in range(len(val)):
                val[i] = 0
        target[key] = None
    target.clear()


def zeroize_bytes(buffer: bytearray) -> None:
    """Cryptographically zeroize raw bytearray buffers in memory."""
    for i in range(len(buffer)):
        buffer[i] = 0


def strip_empty_quote_pairs(line: str) -> Tuple[str, int]:
    """Strip empty double quote pairs inside tokens (e.g. pow""ersh""ell -> powershell)."""
    count = 0
    pattern = re.compile(r'(?<=[a-zA-Z0-9_\-\.\:\$\\\/])""|""(?=[a-zA-Z0-9_\-\.\:\$\\\/])')
    prev = line
    iter_count = 0
    while iter_count < 500:
        iter_count += 1
        new_line, n = pattern.subn('', prev)
        count += n
        if new_line == prev:
            break
        prev = new_line
    return prev, count


def widen_token_quotes(line: str) -> Tuple[str, int]:
    """
    Widen fragmented quotes scattered within words into clean quoted tokens.
    Examples: w"s"c"r"i"p"t -> "wscript", h"t"t"p" -> "http", c"al"c.exe -> "calc.exe".
    Preserves cleanly quoted strings ("hello world") and set assignment statements.
    """
    # Preserve set variable declarations
    stripped = line.strip().lower()
    if stripped.startswith("set ") or stripped.startswith("@set ") or stripped.startswith("set/") or stripped.startswith("@set/"):
        return line, 0

    count = 0
    pat = re.compile(r'((?<!\S)"[^"\r\n]*"(?!\S))|([ \t]+)|([^ \t]+)')
    new_tokens = []

    for m in pat.finditer(line):
        quoted, ws, tok = m.groups()
        if ws:
            new_tokens.append(ws)
        elif quoted:
            new_tokens.append(quoted)
        elif tok:
            # Don't widen tokens with '=' (assignment / options) or caret-escaped quotes '^"'
            if '"' in tok and '=' not in tok and '^"' not in tok:
                trailing_delim = ""
                core = tok
                while core and core[-1] in (',', ';') and not core.endswith('""'):
                    trailing_delim = core[-1] + trailing_delim
                    core = core[:-1]

                if '"' in core:
                    clean_core = core.replace('"', '')
                    new_tokens.append(f'"{clean_core}"{trailing_delim}')
                    count += 1
                else:
                    new_tokens.append(core + trailing_delim)
            else:
                new_tokens.append(tok)

    return "".join(new_tokens), count


def flatten_nested_cmd(line: str, min_depth: int = 2) -> Tuple[str, int]:
    """
    Unwrap redundant nested cmd.exe / cmd invocations.
    Examples: cmd /c cmd /c "whoami" -> whoami, cmd cmd cmd calc.exe -> calc.exe.
    """
    stripped = line.strip()
    if not stripped:
        return line, 0

    leading_at = stripped.startswith("@")
    work = stripped[1:].strip() if leading_at else stripped
    cmd_pattern = re.compile(
        r'^(?:cmd(?:\.exe)?|%comspec%|"%comspec%"|"cmd(?:\.exe)?")(?:\s+(?:/[a-z0-9\:]+))*\s*',
        re.IGNORECASE
    )

    peeled_count = 0
    curr = work

    while peeled_count < 100:
        m = cmd_pattern.match(curr)
        if not m or m.end() == 0:
            break
        matched_str = m.group(0)
        first_token = matched_str.split()[0].replace('"', '').lower()
        if first_token not in ("cmd", "cmd.exe", "%comspec%"):
            break

        rest = curr[m.end():].strip()
        peeled_count += 1
        curr = rest

        if curr.startswith('"') and curr.endswith('"') and curr.count('"') >= 2:
            inner = curr[1:-1].strip()
            if cmd_pattern.match(inner):
                curr = inner

    if peeled_count >= min_depth:
        if curr.startswith('"') and curr.endswith('"'):
            unquoted = curr[1:-1].strip()
            if unquoted:
                curr = unquoted
        return ("@" if leading_at else "") + curr, peeled_count

    return line, 0


# Protected regions for delimiter normalization: quotes, %vars%, and !vars!
PROT_DELIM_PAT = re.compile(
    r'("[^"\r\n]*"|%[a-zA-Z0-9_\-\.\:\$]+(?::[~*]?[^%\r\n]+)?%|![a-zA-Z0-9_\-\.\:\$]+(?::[~*]?[^!\r\n]+)?!)'
)


def normalize_delimiters_outside_quotes(line: str) -> Tuple[str, int]:
    """
    Normalize consecutive delimiters (commas, semicolons, extra spaces) outside quotes
    and variable slices/substitutions (%VAR:~0,1%, !VAR:~0,1!).
    Examples: cmd , , , -> cmd, cmd , , , /c , , whoami -> cmd /c whoami.
    """
    if not line:
        return line, 0

    count = 0
    parts = PROT_DELIM_PAT.split(line)
    new_parts = []

    for i, part in enumerate(parts):
        if not part:
            continue
        # Odd indices match PROT_DELIM_PAT (protected)
        if i % 2 == 1:
            new_parts.append(part)
        else:
            mod = re.sub(r'[\t ]*[,;]+[\t ,;]*', ' ', part)
            if mod != part:
                count += 1
            new_parts.append(mod)

    reconstructed = "".join(new_parts)
    if not reconstructed.endswith('"'):
        cleaned = re.sub(r'[\s,;]+$', '', reconstructed)
        if cleaned != reconstructed:
            count += 1
            reconstructed = cleaned

    return reconstructed, count


def eval_batch_slice(val: str, start_raw: str, len_raw: Optional[str] = None) -> str:
    """Evaluate Windows batch substring slice syntax: %VAR:~start,length% or !VAR:~start,len!."""
    if not val:
        return ""
    try:
        start_str = start_raw.strip().lstrip("+")
        start = int(start_str) if start_str else 0
    except ValueError:
        return val

    n = len(val)
    actual_start = max(0, n + start) if start < 0 else min(n, start)
    if len_raw is None:
        return val[actual_start:]

    try:
        len_str = len_raw.strip().lstrip("+")
        length = int(len_str) if len_str else 0
    except ValueError:
        return val[actual_start:]

    actual_end = min(n, actual_start + length) if length >= 0 else max(actual_start, n + length)
    return val[actual_start:actual_end]


def eval_batch_subst(val: str, star_prefix: str, old_val: str, new_val: str) -> str:
    """Evaluate Windows batch substitution syntax: %VAR:old=new% or %VAR:*old=new%."""
    if not val:
        return ""
    if star_prefix:
        idx = val.lower().find(old_val.lower())
        return (new_val + val[idx + len(old_val):]) if idx != -1 else val
    return re.compile(re.escape(old_val), re.IGNORECASE).sub(lambda _: new_val, val)


def eval_delayed_expansion(text: str, env: Dict[str, str]) -> Tuple[str, int]:
    """Resolve delayed expansion references: !VAR!, !VAR:~start,len!, !VAR:old=new!."""
    resolved_count = 0

    def slice_repl(m):
        nonlocal resolved_count
        name = m.group(1).lower()
        if name in env:
            resolved_count += 1
            return eval_batch_slice(env[name], m.group(2), m.group(3))
        return m.group(0)

    curr = re.sub(r'!([a-zA-Z0-9_\-\.\:\$]+):~([+\-]?\d+)(?:,([+\-]?\d+))?!', slice_repl, text)

    def subst_repl(m):
        nonlocal resolved_count
        name = m.group(1).lower()
        if name in env:
            resolved_count += 1
            return eval_batch_subst(env[name], m.group(2), m.group(3), m.group(4) or "")
        return m.group(0)

    curr = re.sub(r'!([a-zA-Z0-9_\-\.\:\$]+):(\*?)([^=!\r\n]+)=([^!\r\n]*)!', subst_repl, curr)

    def var_repl(m):
        nonlocal resolved_count
        name = m.group(1).lower()
        if name in env:
            resolved_count += 1
            return env[name]
        return m.group(0)

    curr = re.sub(r'!([a-zA-Z0-9_\-\.\:\$]+)!', var_repl, curr)
    return curr, resolved_count


def extract_var_assignments(line: str) -> List[Tuple[str, str]]:
    """Extract (var_name, var_value) from set statements on a line."""
    results: List[Tuple[str, str]] = []
    keyword_pat = re.compile(r'(?:^|[;&@\(\)\s])set(?:\s+(?:/[ap]\s+)?|/[ap]\s*)', re.IGNORECASE)

    for m in keyword_pat.finditer(line):
        idx = m.end()
        if idx >= len(line):
            continue
        if line[idx] == '"':
            q_m = re.match(r'\"([a-zA-Z0-9_\-\.\:\$%]+)=([^\"\r\n]*)\"?', line[idx:])
            if q_m:
                results.append((q_m.group(1).lower(), q_m.group(2)))
                continue

        eq_idx = line.find('=', idx)
        if eq_idx == -1:
            continue
        var_name = line[idx:eq_idx].strip().lower()
        if not re.match(r'^[a-zA-Z0-9_\-\.\:\$%]+$', var_name):
            continue

        val_chars, in_quotes = [], False
        for ch in line[eq_idx + 1:]:
            if ch == '"':
                in_quotes = not in_quotes
                val_chars.append(ch)
            elif not in_quotes and ch in ('&', '|'):
                break
            else:
                val_chars.append(ch)
        results.append((var_name, "".join(val_chars).strip()))

    return results


def build_variable_dependency_graph(
    script_text: str,
    custom_env: Optional[Dict[str, str]] = None
) -> Tuple[Dict[str, str], Dict[str, Set[str]], List[List[str]]]:
    """Build dependency graph of environment variables and detect cycles via DFS."""
    definitions: Dict[str, str] = {}
    for line in script_text.splitlines():
        for var_name, var_val in extract_var_assignments(line):
            definitions[var_name] = var_val

    var_pat = re.compile(r'[%!]([a-zA-Z0-9_\-\.\:\$]+)(?::[~*]?[^%!]+)?(?:=([^%!]*))?[%!]', re.IGNORECASE)
    graph: Dict[str, Set[str]] = {k: set() for k in definitions}

    for k, val in definitions.items():
        for m in var_pat.finditer(val):
            dep = m.group(1).lower()
            if dep in definitions:
                graph[k].add(dep)

    visited: Dict[str, int] = {k: 0 for k in definitions}
    cycles: List[List[str]] = []

    def dfs(node: str, path: List[str]):
        if len(path) >= 100:
            return
        visited[node] = 1
        path.append(node)
        for neighbor in graph.get(node, set()):
            if neighbor not in definitions:
                continue
            if visited[neighbor] == 1:
                idx = path.index(neighbor)
                cycles.append(path[idx:] + [neighbor])
            elif visited[neighbor] == 0:
                dfs(neighbor, path)
        path.pop()
        visited[node] = 2

    for node in definitions:
        if visited[node] == 0:
            dfs(node, [])

    return definitions, graph, cycles


def resolve_chained_environment_variables(
    script_text: str,
    custom_env: Optional[Dict[str, str]] = None,
    max_depth: int = 25
) -> Tuple[str, Dict[str, str], int, int]:
    """
    Resolve chained environment variable dependency graphs via iterative topological solver.
    Guards against infinite loops when cyclic definitions are encountered.
    """
    definitions, graph, cycles = build_variable_dependency_graph(script_text, custom_env)
    symbols: Dict[str, str] = dict(custom_env) if custom_env else {}
    symbols.update(definitions)

    cyclic_nodes = {node for cycle in cycles for node in cycle}
    chains_resolved, depth, prev_symbols = 0, 0, {}

    while depth < max_depth and symbols != prev_symbols:
        prev_symbols = dict(symbols)
        depth += 1

        for var, raw_val in list(symbols.items()):
            if var in cyclic_nodes and depth > 2:
                continue

            val = re.sub(
                r'[%!]([a-zA-Z0-9_\-\.\:\$]+):~([+\-]?\d+)(?:,([+\-]?\d+))?[%!]',
                lambda m: eval_batch_slice(symbols.get(m.group(1).lower(), m.group(0)), m.group(2), m.group(3))
                if m.group(1).lower() in symbols else m.group(0),
                raw_val
            )
            val = re.sub(
                r'[%!]([a-zA-Z0-9_\-\.\:\$]+):(\*?)([^=%\!\r\n]+)=([^%\!\r\n]*)?[%!]',
                lambda m: eval_batch_subst(symbols.get(m.group(1).lower(), m.group(0)), m.group(2), m.group(3), m.group(4) or "")
                if m.group(1).lower() in symbols else m.group(0),
                val
            )

            def repl(m):
                nonlocal chains_resolved
                name = m.group(1).lower()
                if name in symbols and name != var:
                    chains_resolved += 1
                    return symbols[name]
                return m.group(0)

            symbols[var] = re.sub(r'[%!]([a-zA-Z0-9_\-\.\:\$]+)[%!]', repl, val)

    output_lines: List[str] = []
    for line in script_text.splitlines():
        l = re.sub(
            r'[%!]([a-zA-Z0-9_\-\.\:\$]+):~([+\-]?\d+)(?:,([+\-]?\d+))?[%!]',
            lambda m: eval_batch_slice(symbols.get(m.group(1).lower(), m.group(0)), m.group(2), m.group(3))
            if m.group(1).lower() in symbols else m.group(0),
            line
        )
        l = re.sub(
            r'[%!]([a-zA-Z0-9_\-\.\:\$]+):(\*?)([^=%\!\r\n]+)=([^%\!\r\n]*)?[%!]',
            lambda m: eval_batch_subst(symbols.get(m.group(1).lower(), m.group(0)), m.group(2), m.group(3), m.group(4) or "")
            if m.group(1).lower() in symbols else m.group(0),
            l
        )
        l = re.sub(
            r'[%!]([a-zA-Z0-9_\-\.\:\$]+)[%!]',
            lambda m: symbols.get(m.group(1).lower(), m.group(0))
            if m.group(1).lower() in symbols else m.group(0),
            l
        )
        output_lines.append(l)

    return "\n".join(output_lines), symbols, chains_resolved, len(cycles)


def detect_cmd_deobfuscator_signatures(script_text: str) -> Dict[str, Any]:
    """Detect CMD-DeObfuscator evasion signatures and patterns."""
    indicators: List[str] = []
    confidence = 0.0

    # 1. Delayed expansion
    delayed_matches = re.findall(r'![a-zA-Z0-9_\-\.\:\$]+(?:[:~][^!]+)?!', script_text)
    delayed_count = len(delayed_matches)
    if delayed_count > 0:
        indicators.append(f"delayed_expansion_variables({delayed_count})")
        confidence += min(0.35, delayed_count * 0.05)

    # 2. Fragmented quotes (outside set statements and ignoring caret-escaped ^")
    frag_quote_matches = []
    for line in script_text.splitlines():
        str_l = line.strip().lower()
        if str_l.startswith("set ") or str_l.startswith("@set ") or str_l.startswith("set/") or str_l.startswith("@set/"):
            continue
        # Find tokens with interior quotes not preceded by ^
        m = re.findall(r'(?<!\^)[a-zA-Z0-9_\-\.\:\$\\\/]+"[a-zA-Z0-9_\-\.\:\$\\\/"]+|"[a-zA-Z0-9_\-\.\:\$\\\/"]+"[a-zA-Z0-9_\-\.\:\$\\\/]+', line)
        frag_quote_matches.extend(m)

    frag_quote_count = len(frag_quote_matches)
    if frag_quote_count > 0:
        indicators.append(f"fragmented_quotes({frag_quote_count})")
        confidence += min(0.40, frag_quote_count * 0.10)

    # Empty quotes inside tokens: pow""ersh""ell
    empty_matches = re.findall(r'(?<=[a-zA-Z0-9_\-\.\:\$\\\/])""|""(?=[a-zA-Z0-9_\-\.\:\$\\\/])', script_text)
    if empty_matches:
        indicators.append(f"empty_quote_injections({len(empty_matches)})")
        confidence += min(0.30, len(empty_matches) * 0.08)

    # 3. Redundant nested cmd.exe
    nested_cmd_pat = re.compile(r'(?:cmd(?:\.exe)?|%comspec%)\s+(?:/[a-z0-9\:]+\s+)*(?:cmd(?:\.exe)?|%comspec%)|cmd\s+cmd', re.IGNORECASE)
    nested_matches = nested_cmd_pat.findall(script_text)
    nested_cmd_count = len(nested_matches)
    if nested_cmd_count > 0:
        indicators.append(f"redundant_nested_cmd({nested_cmd_count})")
        confidence += min(0.45, nested_cmd_count * 0.15)

    # 4. Delimiter clusters outside quotes and variables
    delim_matches = []
    for line in script_text.splitlines():
        unprot_parts = PROT_DELIM_PAT.split(line)
        for idx, part in enumerate(unprot_parts):
            if idx % 2 == 0 and part:
                found = re.findall(r'[,;]\s*[,;]+', part)
                delim_matches.extend(found)

    delim_cluster_count = len(delim_matches)
    if delim_cluster_count > 0:
        indicators.append(f"delimiter_clusters({delim_cluster_count})")
        confidence += min(0.30, delim_cluster_count * 0.08)

    # 5. Chained environment variables (at least 2 chained references)
    set_vars: Set[str] = set()
    chain_count = 0
    for line in script_text.splitlines():
        for vname, vval in extract_var_assignments(line):
            if any(f"%{s}%" in vval.lower() or f"!{s}!" in vval.lower() for s in set_vars):
                chain_count += 1
            set_vars.add(vname)

    if chain_count >= 2:
        indicators.append(f"chained_env_vars({chain_count})")
        confidence += min(0.40, chain_count * 0.10)

    confidence = min(0.99, round(confidence, 2))
    return {
        "is_cmd_deobfuscator": bool(indicators and confidence >= 0.30),
        "confidence": confidence,
        "indicators": indicators,
        "delayed_count": delayed_count,
        "frag_quote_count": frag_quote_count,
        "nested_cmd_count": nested_cmd_count,
        "delim_cluster_count": delim_cluster_count,
        "chained_var_count": chain_count,
    }


class CMDDeobfuscatorNormalizer:
    """Object-oriented normalizer for CMD-DeObfuscator chained variables and syntax."""

    def __init__(
        self,
        custom_env: Optional[Dict[str, str]] = None,
        enable_chain_resolution: bool = True,
        enable_quote_widening: bool = True,
        enable_cmd_flattening: bool = True,
        enable_delimiter_norm: bool = True,
        max_chain_depth: int = 25,
    ):
        self.custom_env = dict(custom_env) if custom_env else {}
        self.enable_chain_resolution = enable_chain_resolution
        self.enable_quote_widening = enable_quote_widening
        self.enable_cmd_flattening = enable_cmd_flattening
        self.enable_delimiter_norm = enable_delimiter_norm
        self.max_chain_depth = max_chain_depth

    def normalize(self, script_text: str) -> Tuple[str, Dict[str, Any]]:
        """Execute full CMD-DeObfuscator normalization pipeline."""
        signatures = detect_cmd_deobfuscator_signatures(script_text)
        if not signatures["is_cmd_deobfuscator"]:
            return script_text, {
                "signatures": signatures,
                "is_cmd_deobfuscator": False,
                "confidence": signatures["confidence"],
                "indicators": signatures["indicators"],
                "chains_resolved_count": 0,
                "cycles_detected_count": 0,
                "delayed_expansions_resolved": 0,
                "quotes_widened_count": 0,
                "empty_quotes_stripped_count": 0,
                "nested_cmds_flattened_count": 0,
                "delimiters_normalized_count": 0,
            }

        curr_text = script_text
        chains_resolved, cycles_count, delayed_count = 0, 0, 0
        quotes_widened, empty_quotes_stripped = 0, 0
        nested_cmds_flattened, delimiters_normalized = 0, 0

        # Step 1: Empty quote stripping inside tokens
        lines, processed_lines = curr_text.splitlines(), []
        for line in lines:
            l, c = strip_empty_quote_pairs(line)
            empty_quotes_stripped += c
            processed_lines.append(l)
        curr_text = "\n".join(processed_lines)

        # Step 2: Quote widening on fragmented tokens
        if self.enable_quote_widening:
            lines, processed_lines = curr_text.splitlines(), []
            for line in lines:
                l, c = widen_token_quotes(line)
                quotes_widened += c
                processed_lines.append(l)
            curr_text = "\n".join(processed_lines)

        # Step 3: Delimiter & comma normalization outside quotes
        if self.enable_delimiter_norm:
            lines, processed_lines = curr_text.splitlines(), []
            for line in lines:
                l, c = normalize_delimiters_outside_quotes(line)
                delimiters_normalized += c
                processed_lines.append(l)
            curr_text = "\n".join(processed_lines)

        # Step 4: Redundant nested cmd.exe flattening
        if self.enable_cmd_flattening:
            lines, processed_lines = curr_text.splitlines(), []
            for line in lines:
                l, c = flatten_nested_cmd(line)
                nested_cmds_flattened += c
                processed_lines.append(l)
            curr_text = "\n".join(processed_lines)

        # Step 5: Chained environment variable graph resolution
        symbols: Dict[str, str] = {}
        if self.enable_chain_resolution:
            curr_text, symbols, chains_resolved, cycles_count = resolve_chained_environment_variables(
                curr_text, self.custom_env, self.max_chain_depth
            )

        # Step 6: Delayed expansion resolution
        lines, processed_lines = curr_text.splitlines(), []
        for line in lines:
            l, c = eval_delayed_expansion(line, symbols)
            delayed_count += c
            processed_lines.append(l)
        curr_text = "\n".join(processed_lines)

        telemetry: Dict[str, Any] = {
            "signatures": signatures,
            "is_cmd_deobfuscator": signatures["is_cmd_deobfuscator"],
            "confidence": signatures["confidence"],
            "indicators": signatures["indicators"],
            "chains_resolved_count": chains_resolved,
            "cycles_detected_count": cycles_count,
            "delayed_expansions_resolved": delayed_count,
            "quotes_widened_count": quotes_widened,
            "empty_quotes_stripped_count": empty_quotes_stripped,
            "nested_cmds_flattened_count": nested_cmds_flattened,
            "delimiters_normalized_count": delimiters_normalized,
        }

        zeroize_dict(symbols)
        return curr_text, telemetry

    def zeroize(self) -> None:
        """Cryptographically sanitize internal environment and buffers."""
        if hasattr(self, "custom_env") and self.custom_env:
            zeroize_dict(self.custom_env)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.zeroize()

    def __del__(self):
        try:
            self.zeroize()
        except Exception:
            pass


def normalize_cmd_deobfuscator(
    script_text: str,
    custom_env: Optional[Dict[str, str]] = None,
    enable_chain_resolution: bool = True,
    enable_quote_widening: bool = True,
    enable_cmd_flattening: bool = True,
    enable_delimiter_norm: bool = True,
    max_chain_depth: int = 25,
) -> Tuple[str, Dict[str, Any]]:
    """Convenience helper to run CMD-DeObfuscator deobfuscation on script text."""
    normalizer = CMDDeobfuscatorNormalizer(
        custom_env=custom_env,
        enable_chain_resolution=enable_chain_resolution,
        enable_quote_widening=enable_quote_widening,
        enable_cmd_flattening=enable_cmd_flattening,
        enable_delimiter_norm=enable_delimiter_norm,
        max_chain_depth=max_chain_depth,
    )
    return normalizer.normalize(script_text)
