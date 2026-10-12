#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Standardized Telemetry & Metrics Suite for Batch Deobfuscation Benchmarks.
Calculates Shannon entropy, compression ratio, caret stripping ratio,
symbol resolution density, convergence speed, readability index, and composite scores.
"""

import math
import re
from typing import Dict, List, Any
from collections import Counter


def calculate_shannon_entropy(text: str) -> float:
    """
    Calculate Shannon entropy (bits per character) for a given text.
    H = - sum(p * log2(p))
    """
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def calculate_size_compression_ratio(raw_text: str, clean_text: str) -> float:
    """
    Calculate the percentage size reduction / compression achieved by deobfuscation.
    Returns percentage (0.0 to 100.0+), positive when obfuscation noise was removed.
    """
    if not raw_text:
        return 0.0
    delta = len(raw_text) - len(clean_text)
    ratio = (delta / len(raw_text)) * 100.0
    return round(ratio, 2)


def calculate_caret_stripping_ratio(raw_text: str, clean_text: str) -> float:
    """
    Calculate the percentage of obfuscation carets stripped from the original script.
    If no carets existed originally, returns 100.0.
    """
    raw_carets = raw_text.count('^')
    if raw_carets == 0:
        return 100.0
    clean_carets = clean_text.count('^')
    stripped = max(0, raw_carets - clean_carets)
    return round((stripped / raw_carets) * 100.0, 2)


def calculate_symbol_resolution_density(symbols_resolved: int, clean_text: str) -> float:
    """
    Calculate the density of resolved symbols per line of clean deobfuscated output.
    """
    lines = max(1, len([l for l in clean_text.splitlines() if l.strip()]))
    return round(symbols_resolved / lines, 2)


def calculate_convergence_speed(passes_executed: int, max_passes: int, elapsed_ms: float) -> Dict[str, Any]:
    """
    Evaluate multi-pass convergence efficiency and latency profile.
    """
    speed_score = round(max(0.0, min(100.0, 100.0 - (passes_executed - 1) * 10.0)), 2)
    ms_per_pass = round(elapsed_ms / max(1, passes_executed), 3)
    return {
        "passes_executed": passes_executed,
        "max_passes": max_passes,
        "speed_score": speed_score,
        "elapsed_ms": round(elapsed_ms, 3),
        "ms_per_pass": ms_per_pass,
    }


def calculate_readability_clarity_index(clean_text: str) -> float:
    """
    Heuristic Clarity Index (0.0 to 100.0) evaluating readability of deobfuscated script:
      - Alphanumeric / whitespace density vs punctuation noise (40 pts)
      - Standard batch command keyword recognizability (30 pts)
      - Line length distribution sanity (15 pts)
      - Clean variable expansion syntax (15 pts)
    """
    if not clean_text or not clean_text.strip():
        return 0.0

    total_chars = len(clean_text)
    alnum_space_chars = sum(1 for c in clean_text if c.isalnum() or c.isspace())
    char_clarity_ratio = alnum_space_chars / total_chars
    char_score = min(40.0, char_clarity_ratio * 45.0)

    # Keywords recognition
    recognized_keywords = [
        "echo", "set", "cmd", "whoami", "powershell", "start",
        "curl", "certutil", "reg", "ping", "dir", "tasklist",
        "net", "if", "exit", "localgroup", "administrators",
    ]
    lower_text = clean_text.lower()
    matches = sum(1 for kw in recognized_keywords if kw in lower_text)
    keyword_score = min(30.0, matches * 7.5)

    # Line formatting penalty for ultra-long single lines (> 200 chars)
    lines = [l for l in clean_text.splitlines() if l.strip()]
    if lines:
        avg_line_len = sum(len(l) for l in lines) / len(lines)
        if avg_line_len <= 120:
            format_score = 15.0
        elif avg_line_len <= 200:
            format_score = 10.0
        else:
            format_score = 5.0
    else:
        format_score = 0.0

    # Variable syntax cleanliness: check remaining undefined or unclosed %
    odd_percents = clean_text.count('%') % 2
    syntax_score = 15.0 if odd_percents == 0 else 7.5

    total = char_score + keyword_score + format_score + syntax_score
    return round(min(100.0, max(0.0, total)), 1)


def calculate_composite_score(
    token_accuracy: float,
    converged: bool,
    passes: int,
    max_passes: int,
    clarity_index: float,
    compression_ratio: float
) -> float:
    """
    Standardized Composite Benchmark Score (0.0 to 100.0):
      - Token Accuracy: 60 pts
      - Fixed-point Convergence: 15 pts
      - Pass Efficiency: 10 pts
      - Clarity Index: 10 pts
      - Compression / Noise Reduction: 5 pts
    """
    token_pts = max(0.0, min(1.0, token_accuracy)) * 60.0
    conv_pts = 15.0 if converged else 0.0
    pass_eff_pts = max(0.0, min(10.0, 10.0 - (passes - 1) * 1.5))
    clarity_pts = (max(0.0, min(100.0, clarity_index)) / 100.0) * 10.0
    comp_pts = min(5.0, max(0.0, compression_ratio * 0.1))

    total = token_pts + conv_pts + pass_eff_pts + clarity_pts + comp_pts
    return round(min(100.0, max(0.0, total)), 1)


def calculate_all_metrics(
    raw_text: str,
    clean_text: str,
    meta: Dict[str, Any],
    expected_tokens: List[str]
) -> Dict[str, Any]:
    """
    Aggregate all benchmark telemetry metrics for a single script deobfuscation run.
    """
    entropy_before = calculate_shannon_entropy(raw_text)
    entropy_after = calculate_shannon_entropy(clean_text)
    entropy_delta = round(entropy_before - entropy_after, 4)

    compression_ratio = calculate_size_compression_ratio(raw_text, clean_text)
    caret_stripping_ratio = calculate_caret_stripping_ratio(raw_text, clean_text)
    
    symbols_resolved = meta.get("symbols_resolved_count", 0)
    symbol_density = calculate_symbol_resolution_density(symbols_resolved, clean_text)

    passes = meta.get("passes_executed", 1)
    converged = meta.get("converged", False)
    elapsed_ms = meta.get("elapsed_ms", 0.0)
    convergence_speed = calculate_convergence_speed(passes, 15, elapsed_ms)

    # Oracle token matching (case-insensitive)
    found = []
    missing = []
    clean_lower = clean_text.lower()
    for token in expected_tokens:
        if token.lower() in clean_lower:
            found.append(token)
        else:
            missing.append(token)

    token_accuracy = (len(found) / len(expected_tokens)) if expected_tokens else 1.0
    clarity_index = calculate_readability_clarity_index(clean_text)

    composite_score = calculate_composite_score(
        token_accuracy=token_accuracy,
        converged=converged,
        passes=passes,
        max_passes=15,
        clarity_index=clarity_index,
        compression_ratio=compression_ratio,
    )

    return {
        "entropy_before": entropy_before,
        "entropy_after": entropy_after,
        "entropy_delta": entropy_delta,
        "compression_ratio": compression_ratio,
        "caret_stripping_ratio": caret_stripping_ratio,
        "symbol_density": symbol_density,
        "convergence_speed": convergence_speed,
        "clarity_index": clarity_index,
        "token_accuracy": round(token_accuracy * 100.0, 1),
        "tokens_found": found,
        "tokens_missing": missing,
        "composite_score": composite_score,
        "converged": converged,
        "passes_executed": passes,
        "elapsed_ms": elapsed_ms,
    }
