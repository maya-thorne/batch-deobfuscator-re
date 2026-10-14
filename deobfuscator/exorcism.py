#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Exorcism Subroutine Label Jump & Control Flow Normalization Engine.
Specialized analyzer for unconditional goto hopping, spaghetti jumps, trampolines,
opaque predicates, leaf subroutine inlining, and control flow linearization.

Engineered by Maya Thorne.
"""

import re
import json
import shlex
from typing import Dict, Any, Tuple, List, Optional, Set

EXORCISM_INDICATORS = [
    "unconditional_goto_hopping",
    "spaghetti_jumps",
    "trampoline_chains",
    "opaque_predicates",
    "subroutine_calls",
    "command_dispatch_chaining",
]


def zeroize_bytes(b: bytearray) -> None:
    """Cryptographically overwrite a mutable bytearray with zeroes."""
    if isinstance(b, bytearray):
        for i in range(len(b)):
            b[i] = 0


def zeroize_dict(d: Dict[Any, Any]) -> None:
    """Overwrite all values in a dictionary and clear its keys."""
    if not isinstance(d, dict):
        return
    for k in list(d.keys()):
        val = d[k]
        if isinstance(val, bytearray):
            zeroize_bytes(val)
        elif isinstance(val, (str, bytes)):
            d[k] = None
        elif isinstance(val, dict):
            zeroize_dict(val)
        elif isinstance(val, list):
            d[k] = []
    d.clear()


def detect_exorcism_signatures(script_text: str) -> Dict[str, Any]:
    """Multi-indicator heuristic signature detection for Exorcism control flow obfuscation."""
    lines = script_text.splitlines()
    non_empty = [l.strip() for l in lines if l.strip() and not re.match(r'^@?\s*(?:rem\b|::)', l.strip(), re.IGNORECASE)]
    total_lines = len(non_empty)

    goto_pat = re.compile(r'(?:^|[;&|@\s])goto(?:\s+|:)(?::)?([a-zA-Z0-9_\-\.\$]+)', re.IGNORECASE)
    label_pat = re.compile(r'^\s*:([a-zA-Z0-9_\-\.\$]+)\s*$', re.IGNORECASE)
    call_pat = re.compile(r'(?:^|[;&|@\s])call\s+:([a-zA-Z0-9_\-\.\$]+)', re.IGNORECASE)
    opaque_pat = re.compile(r'^\s*(?:@\s*)?if(?:\s+/i)?\s+(?:not\s+)?[^\(\r\n]+?(?:==|EQU|NEQ|LSS|LEQ|GTR|GEQ)', re.IGNORECASE)
    chain_pat = re.compile(r'(?:goto|call)\s+:[a-zA-Z0-9_\-\.\$]+\s*(?:&|&&|\|\|)', re.IGNORECASE)

    gotos = [gm.group(1).lower() for l in non_empty for gm in goto_pat.finditer(l) if gm.group(1).lower() != "eof"]
    labels = [lm.group(1).lower() for l in non_empty for lm in [label_pat.match(l)] if lm]
    calls = [cm.group(1).lower() for l in non_empty for cm in call_pat.finditer(l)]
    opaque_count = sum(1 for l in non_empty if opaque_pat.match(l))
    chain_count = sum(1 for l in non_empty if chain_pat.search(l))
    trampolines = sum(1 for i in range(len(non_empty) - 1) if label_pat.match(non_empty[i]) and re.match(r'^\s*(?:@\s*)?goto\b', non_empty[i + 1], re.IGNORECASE))

    goto_count, label_count, call_count = len(gotos), len(labels), len(calls)
    indicators, confidence = [], 0.0

    if goto_count >= 2:
        indicators.append("unconditional_goto_hopping")
        confidence += min(0.30, 0.08 * goto_count)
    if label_count >= 3 and total_lines > 0 and (label_count / total_lines >= 0.15 or goto_count >= 3):
        indicators.append("spaghetti_jumps")
        confidence += 0.25
    if trampolines >= 1:
        indicators.append("trampoline_chains")
        confidence += min(0.35, 0.15 * trampolines)
    if opaque_count >= 1:
        indicators.append("opaque_predicates")
        confidence += min(0.30, 0.15 * opaque_count)
    if call_count >= 1:
        indicators.append("subroutine_calls")
        confidence += min(0.25, 0.10 * call_count)
    if chain_count >= 1:
        indicators.append("command_dispatch_chaining")
        confidence += 0.15

    confidence = min(1.0, round(confidence, 3))
    return {
        "is_exorcism": (confidence >= 0.35) or (len(indicators) >= 2),
        "confidence": confidence,
        "indicators": indicators,
        "goto_count": goto_count,
        "label_count": label_count,
        "trampoline_count": trampolines,
        "opaque_predicate_count": opaque_count,
        "subroutine_call_count": call_count,
        "chain_count": chain_count,
    }


def flatten_jump_trampolines(script_text: str) -> Tuple[str, Dict[str, Any]]:
    """Resolves and collapses ':hop1 goto :hop2 \\n :hop2 goto :dest' chains to direct targets."""
    lines = script_text.splitlines()
    label_pat = re.compile(r'^\s*:([a-zA-Z0-9_\-\.\$]+)\s*(?:rem.*|::.*)?$', re.IGNORECASE)
    goto_pat = re.compile(r'^\s*(?:@\s*)?goto(?:\s+|:)(?::)?([a-zA-Z0-9_\-\.\$]+)\s*$', re.IGNORECASE)

    trampolines: Dict[str, str] = {}
    i, n = 0, len(lines)
    while i < n:
        lm = label_pat.match(lines[i])
        if lm:
            label_name = lm.group(1).lower()
            j, statements = i + 1, []
            while j < n and not label_pat.match(lines[j]):
                l_str = lines[j].strip()
                if l_str and not re.match(r'^@?\s*(?:rem\b|::)', l_str, re.IGNORECASE):
                    statements.append(l_str)
                j += 1
            if len(statements) == 1:
                gm = goto_pat.match(statements[0])
                if gm and gm.group(1).lower() not in ("eof", label_name):
                    trampolines[label_name] = gm.group(1).lower()
            i = j
        else:
            i += 1

    if not trampolines:
        return script_text, {"trampolines_collapsed": 0, "trampoline_map": {}}

    resolved_map: Dict[str, str] = {}
    for hop_start in trampolines:
        curr, visited = hop_start, set()
        while curr in trampolines:
            if curr in visited:
                break
            visited.add(curr)
            curr = trampolines[curr]
        if curr != hop_start:
            resolved_map[hop_start] = curr

    if not resolved_map:
        return script_text, {"trampolines_collapsed": 0, "trampoline_map": {}}

    ref_pat = re.compile(r'(\b(?:goto(?:\s+|:)(?::)?|call\s+:))([a-zA-Z0-9_\-\.\$]+)', re.IGNORECASE)
    replaced_count = 0

    def repl(m):
        nonlocal replaced_count
        pfx, target = m.group(1), m.group(2).lower()
        if target in resolved_map:
            replaced_count += 1
            return f"{pfx}{resolved_map[target]}"
        return m.group(0)

    new_lines = [ref_pat.sub(repl, line) for line in lines]
    return "\n".join(new_lines), {"trampolines_collapsed": replaced_count, "trampoline_map": resolved_map}


def _eval_batch_condition(lhs: str, op: str, rhs: str, is_ci: bool, is_not: bool) -> Optional[bool]:
    """Helper to statically evaluate a batch constant condition."""
    def unquote(v: str) -> str:
        return v[1:-1] if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")) else v

    raw_lhs, raw_rhs = unquote(lhs), unquote(rhs)
    if lhs == rhs:
        res = (op in ("==", "EQU", "LEQ", "GEQ"))
        return not res if is_not else res

    # If operands contain runtime dynamic variables (%VAR%, !VAR!, %1), do not evaluate statically
    if ("%" in lhs or "%" in rhs or "!" in lhs or "!" in rhs) and (lhs != rhs):
        return None

    try:
        n_lhs, n_rhs = int(raw_lhs), int(raw_rhs)
        table = {
            "==": n_lhs == n_rhs, "EQU": n_lhs == n_rhs, "NEQ": n_lhs != n_rhs,
            "LSS": n_lhs < n_rhs, "LEQ": n_lhs <= n_rhs, "GTR": n_lhs > n_rhs, "GEQ": n_lhs >= n_rhs,
        }
        return not table[op] if is_not else table[op]
    except (ValueError, KeyError):
        pass

    if is_ci:
        raw_lhs, raw_rhs = raw_lhs.lower(), raw_rhs.lower()
    if op in ("==", "EQU"):
        res = (raw_lhs == raw_rhs)
    elif op == "NEQ":
        res = (raw_lhs != raw_rhs)
    else:
        return None
    return not res if is_not else res


def _extract_if_parts(rest: str) -> Optional[Tuple[str, str, str, str]]:
    """Tokenize rest of if statement into (lhs, op, rhs, action)."""
    in_q, op_pos, op_str = False, -1, ""
    i, n = 0, len(rest)
    while i < n:
        ch = rest[i]
        if ch == '"':
            in_q = not in_q
            i += 1
        elif not in_q:
            if rest[i:i+2] == '==':
                op_pos, op_str = i, '=='
                break
            for cand in ('EQU', 'NEQ', 'LSS', 'LEQ', 'GTR', 'GEQ'):
                if rest[i:i+len(cand)].upper() == cand:
                    if (i == 0 or rest[i-1].isspace()) and (i+len(cand) < n and rest[i+len(cand)].isspace()):
                        op_pos, op_str = i, cand
                        break
            if op_str: break
            i += 1
        else:
            i += 1

    if not op_str: return None
    lhs = rest[:op_pos].strip()
    after_op = rest[op_pos + len(op_str):].strip()
    if after_op.startswith('"'):
        close_q = after_op.find('"', 1)
        if close_q != -1:
            rhs = after_op[:close_q+1]
            action = after_op[close_q+1:].strip()
        else: return None
    else:
        m = re.match(r'^([^\s\(]+)(?:\s+(.*)|\s*(\([\s\S]*))$', after_op)
        if m:
            rhs = m.group(1)
            action = (m.group(2) or m.group(3) or '').strip()
        else:
            m2 = re.match(r'^([^\s\(]+)\s*$', after_op)
            if m2:
                rhs = m2.group(1)
                action = ''
            else:
                return None
    return lhs, op_str, rhs, action


def normalize_opaque_predicates(script_text: str) -> Tuple[str, Dict[str, Any]]:
    """Evaluates constant conditions to straighten branch flow or prune dead conditional blocks."""
    lines = script_text.splitlines()
    new_lines, predicates_normalized = [], 0
    if_prefix_pat = re.compile(r'^\s*(?:@\s*)?if(?:\s+(/i))?(?:\s+(not))?\s+(.+)$', re.IGNORECASE)

    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()
        m_prefix = if_prefix_pat.match(stripped)
        if m_prefix:
            is_ci = bool(m_prefix.group(1))
            is_not = bool(m_prefix.group(2))
            rest = m_prefix.group(3).strip()
            parts = _extract_if_parts(rest)
            if parts:
                lhs, op, rhs, action = parts
                cond_val = _eval_batch_condition(lhs, op, rhs, is_ci, is_not)
                if cond_val is not None:
                    predicates_normalized += 1
                    if action == "(":
                        true_block, j, paren = [], i + 1, 1
                        while j < n and paren > 0:
                            l = lines[j]
                            if ")" in l and "else" in l.lower():
                                paren -= 1
                                break
                            if ")" in l:
                                paren -= 1
                                if paren == 0: break
                            true_block.append(l)
                            j += 1
                        else_block, has_else = [], False
                        if j < n and "else" in lines[j].lower():
                            has_else, j, paren = True, j + 1, 1
                            while j < n and paren > 0:
                                l = lines[j]
                                if ")" in l:
                                    paren -= 1
                                    if paren == 0: break
                                else_block.append(l)
                                j += 1
                        chosen = true_block if cond_val else (else_block if has_else else [])
                        for b in chosen:
                            if b.strip(): new_lines.append(b.strip())
                        i = j + 1
                        continue
                    else:
                        m_else = re.search(r'\s+else(?:\s+|$)', action, re.IGNORECASE)
                        if m_else:
                            t_act = action[:m_else.start()].strip()
                            f_act = action[m_else.end():].strip()
                            if t_act.startswith("(") and t_act.endswith(")"): t_act = t_act[1:-1].strip()
                            if f_act.startswith("(") and f_act.endswith(")"): f_act = f_act[1:-1].strip()
                            chosen = t_act if cond_val else f_act
                            if chosen: new_lines.append(chosen)
                        elif cond_val:
                            act = action[1:-1].strip() if action.startswith("(") and action.endswith(")") else action
                            if act: new_lines.append(act)
                        i += 1
                        continue

        new_lines.append(line)
        i += 1

    return "\n".join(new_lines), {"predicates_normalized": predicates_normalized}


def inline_subroutines(script_text: str) -> Tuple[str, Dict[str, Any]]:
    """Inlines non-recursive leaf 'call :sub [args]' routines with parameter substitutions."""
    lines = script_text.splitlines()
    label_pat = re.compile(r'^\s*:([a-zA-Z0-9_\-\.\$]+)\s*(?:rem.*|::.*)?$', re.IGNORECASE)
    return_pat = re.compile(r'^\s*(?:@\s*)?(?:goto(?:\s+|:):?eof|exit\s*/b(?:\s+\d+)?)\s*$', re.IGNORECASE)
    call_sub_pat = re.compile(r'^\s*(?:@\s*)?call\s+:([a-zA-Z0-9_\-\.\$]+)(?:\s+(.*))?$', re.IGNORECASE)

    blocks: Dict[str, List[str]] = {}
    curr_label, curr_lines = None, []
    for line in lines:
        lm = label_pat.match(line)
        if lm:
            if curr_label: blocks[curr_label] = list(curr_lines)
            curr_label, curr_lines = lm.group(1).lower(), []
        elif curr_label:
            curr_lines.append(line)
    if curr_label: blocks[curr_label] = list(curr_lines)

    leaf_subs: Dict[str, List[str]] = {}
    for lbl, blk in blocks.items():
        active = [l for l in blk if l.strip() and not re.match(r'^@?\s*(?:rem\b|::)', l.strip(), re.IGNORECASE)]
        if not active or any(call_sub_pat.search(l) for l in active):
            continue
        if any(return_pat.match(l) for l in active) or len(active) <= 5:
            leaf_subs[lbl] = [l for l in blk if not return_pat.match(l)]

    if not leaf_subs:
        return script_text, {"subroutines_inlined_count": 0, "inlined_subroutines": []}

    new_lines, inlined_count, inlined_names = [], 0, set()
    for line in lines:
        cm = call_sub_pat.match(line)
        if cm and cm.group(1).lower() in leaf_subs:
            sub_name, raw_args = cm.group(1).lower(), cm.group(2) or ""
            try:
                args = shlex.split(raw_args, posix=False)
            except Exception:
                args = raw_args.split()
            inlined_count += 1
            inlined_names.add(sub_name)
            for bline in leaf_subs[sub_name]:
                s = bline.replace("%*", raw_args.strip()).replace("%0", f":{sub_name}")
                for idx in range(1, 10):
                    val = args[idx - 1] if idx <= len(args) else ""
                    unq = val[1:-1] if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")) else val
                    s = s.replace(f"%~{idx}", unq).replace(f"%{idx}", val)
                new_lines.append(s)
            continue
        new_lines.append(line)

    return "\n".join(new_lines), {"subroutines_inlined_count": inlined_count, "inlined_subroutines": list(inlined_names)}


def linearize_control_flow(script_text: str) -> Tuple[str, Dict[str, Any]]:
    """Linearizes execution path following unconditional gotos/fallthroughs and prunes obsolete gotos."""
    lines = script_text.splitlines()
    label_pat = re.compile(r'^\s*:([a-zA-Z0-9_\-\.\$]+)\s*(?:rem.*|::.*)?$', re.IGNORECASE)
    goto_pat = re.compile(r'^\s*(?:@\s*)?goto(?:\s+|:)(?::)?([a-zA-Z0-9_\-\.\$]+)\s*$', re.IGNORECASE)
    exit_pat = re.compile(r'^\s*(?:@\s*)?(?:exit(?:\s+/b(?:\s+\d+)?)?|goto(?:\s+|:):?eof)\s*$', re.IGNORECASE)

    class CFGBlock:
        def __init__(self, name: str):
            self.name, self.raw_name, self.lines = name.lower(), name, []
            self.terminator, self.jump_target = "FALLTHROUGH", None

    blocks: List[CFGBlock] = [CFGBlock("__entry__")]
    curr_b = blocks[0]
    for line in lines:
        lm = label_pat.match(line)
        if lm:
            curr_b = CFGBlock(lm.group(1))
            blocks.append(curr_b)
        else:
            curr_b.lines.append(line)

    bmap = {b.name: b for b in blocks}
    for b in blocks:
        active = [l for l in b.lines if l.strip() and not re.match(r'^@?\s*(?:rem\b|::)', l.strip(), re.IGNORECASE)]
        if active:
            gm = goto_pat.match(active[-1])
            if gm:
                b.terminator, b.jump_target = "GOTO", gm.group(1).lower()
            elif exit_pat.match(active[-1]):
                b.terminator = "EXIT"

    linear_blocks, visited, curr = [], set(), blocks[0]
    while curr:
        if curr.name in visited: break
        visited.add(curr.name)
        linear_blocks.append(curr)

        if curr.terminator == "GOTO" and curr.jump_target and curr.jump_target in bmap and curr.jump_target not in visited and curr.jump_target != "eof":
            curr = bmap[curr.jump_target]
            continue
        elif curr.terminator != "EXIT":
            curr_idx = blocks.index(curr)
            if curr_idx + 1 < len(blocks) and blocks[curr_idx + 1].name not in visited:
                curr = blocks[curr_idx + 1]
                continue
        unvisited = [b for b in blocks if b.name not in visited and (b.lines or b.name != "__entry__")]
        curr = unvisited[0] if unvisited else None

    reordered = 0 if [b.name for b in linear_blocks] == [b.name for b in blocks] else len(linear_blocks)
    fallthrough_gotos_removed, result_lines = 0, []

    for idx, b in enumerate(linear_blocks):
        if b.name != "__entry__": result_lines.append(f":{b.raw_name}")
        nxt = linear_blocks[idx + 1] if idx + 1 < len(linear_blocks) else None
        b_lines = list(b.lines)
        if b.terminator == "GOTO" and b.jump_target and nxt and b.jump_target == nxt.name:
            for rev_idx in range(len(b_lines) - 1, -1, -1):
                if goto_pat.match(b_lines[rev_idx]):
                    b_lines.pop(rev_idx)
                    fallthrough_gotos_removed += 1
                    break
        result_lines.extend(b_lines)

    return "\n".join(result_lines), {"blocks_reordered_count": reordered, "fallthrough_gotos_removed": fallthrough_gotos_removed}


def prune_unreachable_blocks(script_text: str) -> Tuple[str, Dict[str, Any]]:
    """Eliminates unreachable decoy blocks and labels with in-degree 0 from entry point."""
    lines = script_text.splitlines()
    label_pat = re.compile(r'^\s*:([a-zA-Z0-9_\-\.\$]+)\s*(?:rem.*|::.*)?$', re.IGNORECASE)
    goto_pat = re.compile(r'\bgoto(?:\s+|:)(?::)?([a-zA-Z0-9_\-\.\$]+)', re.IGNORECASE)
    call_pat = re.compile(r'\bcall\s+:([a-zA-Z0-9_\-\.\$]+)', re.IGNORECASE)
    exit_pat = re.compile(r'^\s*(?:@\s*)?(?:exit(?:\s+/b(?:\s+\d+)?)?|goto(?:\s+|:):?eof)\s*$', re.IGNORECASE)

    class CFGNode:
        def __init__(self, name: str):
            self.name, self.raw_name, self.lines, self.outgoing = name.lower(), name, [], set()

    nodes: List[CFGNode] = [CFGNode("__entry__")]
    curr_n = nodes[0]
    for line in lines:
        lm = label_pat.match(line)
        if lm:
            curr_n = CFGNode(lm.group(1))
            nodes.append(curr_n)
        else:
            curr_n.lines.append(line)

    node_map = {n.name: n for n in nodes}
    for idx, n in enumerate(nodes):
        for line in n.lines:
            for gm in goto_pat.finditer(line):
                if gm.group(1).lower() != "eof": n.outgoing.add(gm.group(1).lower())
            for cm in call_pat.finditer(line):
                if cm.group(1).lower() != "eof": n.outgoing.add(cm.group(1).lower())
        active = [l for l in n.lines if l.strip() and not re.match(r'^@?\s*(?:rem\b|::)', l.strip(), re.IGNORECASE)]
        if not (active and (exit_pat.match(active[-1]) or re.match(r'^\s*(?:@\s*)?goto\b', active[-1], re.IGNORECASE))):
            if idx + 1 < len(nodes): n.outgoing.add(nodes[idx + 1].name)

    reachable, queue = {"__entry__"}, ["__entry__"]
    while queue:
        c = queue.pop(0)
        if c in node_map:
            for out in node_map[c].outgoing:
                if out in node_map and out not in reachable:
                    reachable.add(out)
                    queue.append(out)

    pruned_labels, kept_lines = [], []
    for n in nodes:
        if n.name in reachable:
            if n.name != "__entry__": kept_lines.append(f":{n.raw_name}")
            kept_lines.extend(n.lines)
        elif n.name != "__entry__":
            pruned_labels.append(n.raw_name)

    return "\n".join(kept_lines), {"pruned_blocks_count": len(pruned_labels), "pruned_labels": pruned_labels}


def emulate_exorcism_dispatch(script_text: str) -> List[Dict[str, Any]]:
    """Simulates cmd.exe!FindFixAndRun command dispatch, normalizing chained commands."""
    lines, dispatch_events, dispatch_id = script_text.splitlines(), [], 1
    for line_idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or re.match(r'^@?\s*(?:rem\b|::|:)', stripped, re.IGNORECASE):
            continue

        parts, curr_chars, curr_op, in_q = [], [], None, False
        i, n = 0, len(stripped)
        while i < n:
            ch = stripped[i]
            if ch == '"':
                in_q = not in_q
                curr_chars.append(ch)
                i += 1
            elif not in_q and stripped[i:i+2] in ("&&", "||"):
                sub = "".join(curr_chars).strip()
                if sub: parts.append((curr_op, sub))
                curr_op, curr_chars, i = stripped[i:i+2], [], i + 2
            elif not in_q and ch == '&':
                sub = "".join(curr_chars).strip()
                if sub: parts.append((curr_op, sub))
                curr_op, curr_chars, i = "&", [], i + 1
            else:
                curr_chars.append(ch)
                i += 1
        if curr_chars:
            sub = "".join(curr_chars).strip()
            if sub: parts.append((curr_op, sub))

        for op, cmd_part in parts:
            clean = cmd_part.lstrip("@").strip()
            if not clean: continue
            try:
                tokens = shlex.split(clean, posix=False)
            except Exception:
                tokens = clean.split()
            cmd_name = tokens[0] if tokens else ""
            args = tokens[1:] if len(tokens) > 1 else []
            dispatch_events.append({
                "dispatch_id": dispatch_id,
                "line_number": line_idx + 1,
                "operator": op,
                "command": cmd_name,
                "args": args,
                "raw_command": clean,
            })
            dispatch_id += 1

    return dispatch_events


def export_exorcism_trace(dispatch_events: List[Dict[str, Any]], output_path: Optional[str] = None) -> str:
    """Exports structured JSON traces compatible with Exorcism cmd_hook.json."""
    trace_data = {
        "version": "1.11.0",
        "engine": "exorcism-dispatch-tracer",
        "total_dispatches": len(dispatch_events),
        "events": dispatch_events,
    }
    json_str = json.dumps(trace_data, indent=2)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
    return json_str


def normalize_exorcism(script_text: str, custom_env: Optional[Dict[str, str]] = None) -> Tuple[str, Dict[str, Any]]:
    """Main normalization entry point for Exorcism control flow obfuscated scripts."""
    sig = detect_exorcism_signatures(script_text)
    tramp_text, tramp_meta = flatten_jump_trampolines(script_text)
    pred_text, pred_meta = normalize_opaque_predicates(tramp_text)
    inlined_text, inline_meta = inline_subroutines(pred_text)
    linear_text, linear_meta = linearize_control_flow(inlined_text)
    clean_text, prune_meta = prune_unreachable_blocks(linear_text)
    dispatch_events = emulate_exorcism_dispatch(clean_text)

    telemetry = {
        "is_exorcism": sig["is_exorcism"],
        "confidence": sig["confidence"],
        "indicators": sig["indicators"],
        "signatures": sig,
        "trampolines_collapsed": tramp_meta.get("trampolines_collapsed", 0),
        "trampoline_map": tramp_meta.get("trampoline_map", {}),
        "predicates_normalized": pred_meta.get("predicates_normalized", 0),
        "subroutines_inlined_count": inline_meta.get("subroutines_inlined_count", 0),
        "inlined_subroutines": inline_meta.get("inlined_subroutines", []),
        "blocks_reordered_count": linear_meta.get("blocks_reordered_count", 0),
        "fallthrough_gotos_removed": linear_meta.get("fallthrough_gotos_removed", 0),
        "pruned_blocks_count": prune_meta.get("pruned_blocks_count", 0),
        "pruned_labels": prune_meta.get("pruned_labels", []),
        "dispatch_events_count": len(dispatch_events),
    }
    return clean_text, telemetry


class ExorcismNormalizer:
    """Object-oriented wrapper for Exorcism control flow normalizer."""

    def __init__(self, custom_env: Optional[Dict[str, str]] = None):
        self.custom_env = custom_env or {}
        self.last_telemetry: Dict[str, Any] = {}

    def normalize(self, script_text: str) -> str:
        clean_text, tele = normalize_exorcism(script_text, self.custom_env)
        self.last_telemetry = tele
        return clean_text

    def get_telemetry(self) -> Dict[str, Any]:
        return self.last_telemetry
