"""
Entropy Heatmap Analysis and Spatial Distribution Module.
Provides Shannon entropy profiling, sliding-window analysis, line-by-line distribution,
and color-gradient mapping for real-time batch script obfuscation visualization.
Part of batch-deobfuscator security toolchain.
"""

import math
from typing import Dict, List, Any, Optional, Union
from collections import Counter


def zeroize_bytes(buf: bytearray) -> None:
    """Overwrite a mutable bytearray buffer with zeros in place."""
    if not isinstance(buf, bytearray):
        return
    for i in range(len(buf)):
        buf[i] = 0


def zeroize_dict(d: dict) -> None:
    """Recursively scrub sensitive keys and clear dictionary contents."""
    if not isinstance(d, dict):
        return
    for k in list(d.keys()):
        val = d[k]
        if isinstance(val, bytearray):
            zeroize_bytes(val)
        elif isinstance(val, dict):
            zeroize_dict(val)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    zeroize_dict(item)
                elif isinstance(item, bytearray):
                    zeroize_bytes(item)
        d[k] = None
    d.clear()


def calculate_shannon_entropy(data: Union[str, bytes, bytearray]) -> float:
    """
    Compute Shannon entropy (bits per symbol) for string or binary data.
    H = - sum(p * log2(p))
    Returns 0.0 for empty data.
    """
    if not data:
        return 0.0
    if isinstance(data, (bytes, bytearray)):
        total = len(data)
        counts = Counter(data)
    else:
        total = len(data)
        counts = Counter(data)

    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def entropy_to_color(entropy: float, max_entropy: float = 6.0) -> Dict[str, str]:
    """
    Map an entropy value (typically 0.0 to 6.5+ for text/batch scripts)
    to a continuous cyber-forensic color gradient.
    Low (< 2.5): Safe Emerald Green (#10b981)
    Mild (2.5 - 3.8): Cyan Blue (#06b6d4)
    Moderate (3.8 - 4.6): Warning Amber (#f59e0b)
    High (4.6 - 5.5): Threat Orange-Red (#f43f5e)
    Critical (>= 5.5): High-Entropy Purple-Crimson (#8b5cf6 / #e11d48)
    """
    clamped = max(0.0, min(entropy, max_entropy))
    ratio = clamped / max_entropy if max_entropy > 0 else 0.0

    if ratio < 0.35:
        # Green (#10b981) to Cyan (#06b6d4)
        t = ratio / 0.35
        r = int(16 + t * (6 - 16))
        g = int(185 + t * (182 - 185))
        b = int(129 + t * (212 - 129))
        level = "low"
    elif ratio < 0.65:
        # Cyan (#06b6d4) to Amber (#f59e0b)
        t = (ratio - 0.35) / 0.30
        r = int(6 + t * (245 - 6))
        g = int(182 + t * (158 - 182))
        b = int(212 + t * (11 - 212))
        level = "moderate"
    elif ratio < 0.85:
        # Amber (#f59e0b) to Red-Pink (#f43f5e)
        t = (ratio - 0.65) / 0.20
        r = int(245 + t * (244 - 245))
        g = int(158 + t * (63 - 158))
        b = int(11 + t * (94 - 11))
        level = "high"
    else:
        # Red-Pink (#f43f5e) to Purple (#a855f7)
        t = (ratio - 0.85) / 0.15
        r = int(244 + t * (168 - 244))
        g = int(63 + t * (85 - 63))
        b = int(94 + t * (247 - 94))
        level = "critical"

    hex_color = f"#{r:02x}{g:02x}{b:02x}"
    return {
        "hex": hex_color,
        "rgb": f"rgb({r}, {g}, {b})",
        "rgba": f"rgba({r}, {g}, {b}, 0.85)",
        "level": level,
        "ratio": round(ratio, 3),
    }


def calculate_line_entropy(text: str, max_preview_len: int = 80) -> List[Dict[str, Any]]:
    """
    Compute per-line Shannon entropy and classification for a script.
    Preserves line indices and provides color tags for frontend rendering.
    """
    if not text:
        return []

    lines = text.splitlines()
    results = []
    for idx, line in enumerate(lines, start=1):
        line_len = len(line)
        line_ent = calculate_shannon_entropy(line)
        color_info = entropy_to_color(line_ent)
        clean_preview = line.strip()
        if len(clean_preview) > max_preview_len:
            clean_preview = clean_preview[:max_preview_len] + "..."

        results.append({
            "line": idx,
            "length": line_len,
            "entropy": line_ent,
            "level": color_info["level"],
            "hex": color_info["hex"],
            "rgba": color_info["rgba"],
            "ratio": color_info["ratio"],
            "preview": clean_preview,
        })
    return results


def calculate_sliding_window_entropy(
    text: str,
    window_size: int = 32,
    step: int = 16
) -> List[Dict[str, Any]]:
    """
    Compute sliding-window Shannon entropy across raw script content.
    Identifies localized entropy spikes within dense lines or obfuscated payloads.
    """
    if not text:
        return []

    total_len = len(text)
    if total_len <= window_size:
        ent = calculate_shannon_entropy(text)
        color_info = entropy_to_color(ent)
        return [{
            "offset": 0,
            "length": total_len,
            "entropy": ent,
            "hex": color_info["hex"],
            "level": color_info["level"],
        }]

    windows = []
    for offset in range(0, total_len, step):
        chunk = text[offset : offset + window_size]
        if not chunk:
            break
        ent = calculate_shannon_entropy(chunk)
        color_info = entropy_to_color(ent)
        windows.append({
            "offset": offset,
            "length": len(chunk),
            "entropy": ent,
            "hex": color_info["hex"],
            "level": color_info["level"],
        })
    return windows


def calculate_block_entropy(text: str, num_blocks: int = 50) -> List[Dict[str, Any]]:
    """
    Divide a script into a fixed number of spatial blocks for compact horizontal heatmap visualization.
    """
    if not text:
        return []

    total_len = len(text)
    if total_len == 0:
        return []

    block_size = max(1, math.ceil(total_len / num_blocks))
    blocks = []
    for i in range(0, total_len, block_size):
        chunk = text[i : i + block_size]
        ent = calculate_shannon_entropy(chunk)
        color_info = entropy_to_color(ent)
        blocks.append({
            "block_index": len(blocks),
            "start": i,
            "end": min(total_len, i + block_size),
            "length": len(chunk),
            "entropy": ent,
            "hex": color_info["hex"],
            "rgba": color_info["rgba"],
            "level": color_info["level"],
        })
    return blocks


def detect_entropy_anomalies(
    line_entropies: List[Dict[str, Any]],
    threshold_sigma: float = 1.6
) -> List[Dict[str, Any]]:
    """
    Detect statistical entropy anomalies (lines exceeding mean + sigma * std_dev).
    Pinpoints embedded base64 blobs, compressed payloads, or Caesar-scrambled sections.
    """
    if not line_entropies:
        return []

    non_empty = [e for e in line_entropies if e["length"] > 4]
    if not non_empty:
        return []

    values = [e["entropy"] for e in non_empty]
    mean_val = sum(values) / len(values)
    variance = sum((v - mean_val) ** 2 for v in values) / len(values)
    std_dev = math.sqrt(variance)

    anomalies = []
    spike_cutoff = mean_val + (threshold_sigma * std_dev)
    for entry in non_empty:
        if entry["entropy"] >= spike_cutoff and entry["entropy"] > 4.2:
            anomalies.append({
                "line": entry["line"],
                "entropy": entry["entropy"],
                "z_score": round((entry["entropy"] - mean_val) / (std_dev if std_dev > 0 else 1.0), 2),
                "preview": entry["preview"],
                "hex": entry["hex"],
                "level": "critical" if entry["entropy"] >= 5.5 else "high",
            })
    return anomalies


def analyze_entropy_profile(
    raw_script: str,
    clean_script: Optional[str] = None,
    num_blocks: int = 50
) -> Dict[str, Any]:
    """
    Generate an all-in-one entropy analysis report for the web dashboard.
    Computes global entropy, per-line entropy, block heatmaps, statistical summaries,
    and before/after entropy delta if clean_script is provided.
    """
    raw_global = calculate_shannon_entropy(raw_script)
    line_entries = calculate_line_entropy(raw_script)
    block_entries = calculate_block_entropy(raw_script, num_blocks=num_blocks)
    anomalies = detect_entropy_anomalies(line_entries)

    lengths = [e["length"] for e in line_entries] if line_entries else [0]
    entropies = [e["entropy"] for e in line_entries if e["length"] > 0]
    mean_ent = round(sum(entropies) / len(entropies), 4) if entropies else 0.0
    max_ent = max(entropies) if entropies else 0.0
    min_ent = min(entropies) if entropies else 0.0

    report: Dict[str, Any] = {
        "global_entropy": raw_global,
        "mean_line_entropy": mean_ent,
        "max_line_entropy": max_ent,
        "min_line_entropy": min_ent,
        "total_lines": len(line_entries),
        "total_chars": len(raw_script),
        "lines": line_entries,
        "blocks": block_entries,
        "anomalies": anomalies,
        "color": entropy_to_color(raw_global),
    }

    if clean_script is not None:
        clean_global = calculate_shannon_entropy(clean_script)
        clean_lines = calculate_line_entropy(clean_script)
        delta_h = round(raw_global - clean_global, 4)
        pct_reduction = round((delta_h / raw_global) * 100.0, 2) if raw_global > 0 else 0.0
        report["clean_global_entropy"] = clean_global
        report["entropy_delta"] = delta_h
        report["entropy_reduction_pct"] = pct_reduction
        report["clean_total_lines"] = len(clean_lines)
        report["clean_total_chars"] = len(clean_script)
        report["clean_color"] = entropy_to_color(clean_global)

    return report
