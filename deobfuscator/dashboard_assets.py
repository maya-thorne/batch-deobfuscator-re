"""
Embedded Single-Page Application (SPA) Web Dashboard Assets.
Delivers a self-contained, high-performance cyber-forensics dark UI with zero external CDN dependencies.
Complies with zero-leakage asset integrity policies.
Part of batch-deobfuscator security toolchain.
"""

from .dashboard_styles import DASHBOARD_CSS
from .dashboard_scripts import DASHBOARD_JS


def get_dashboard_html(version: str = "1.20.0") -> str:
    """Return the complete standalone HTML5 single-page application."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>batch-deobfuscator // Forensic Dashboard v{version}</title>
<style>
{DASHBOARD_CSS}
</style>
</head>
<body>

<header>
  <div class="brand">
    <div class="brand-icon">RE</div>
    <div class="brand-title">BATCH-DEOBFUSCATOR // FORENSIC DASHBOARD</div>
    <div class="brand-ver">v{version}</div>
  </div>
  <div class="header-badges">
    <div class="badge"><div class="badge-dot"></div> 18 SPECIALIZED ENGINES</div>
    <div class="badge"><div class="badge-dot"></div> CCCS SERVICE READY</div>
    <div class="badge" id="hostBadge">127.0.0.1</div>
  </div>
</header>

<div class="toolbar">
  <div class="tool-group">
    <label for="sampleSelect">Corpus Preset:</label>
    <select id="sampleSelect">
      <option value="">-- Load Obfuscation Sample --</option>
    </select>
    <label for="passInput" style="margin-left: 8px;">Max Passes:</label>
    <input type="number" id="passInput" value="15" min="1" max="50" style="width: 55px;">
  </div>
  <div class="tool-group">
    <button class="btn-primary" id="btnDeobfuscate">⚡ Deobfuscate (Ctrl+Enter)</button>
    <button class="btn-secondary" id="btnAnalyze">🔍 Analyze Only</button>
    <button class="btn-secondary" id="btnClear">Clear</button>
  </div>
</div>

<div class="stats-strip">
  <div class="stat-card">
    <div class="stat-label">Raw Entropy (H)</div>
    <div class="stat-val rose" id="statRawEntropy">0.0000</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Clean Entropy (H)</div>
    <div class="stat-val cyan" id="statCleanEntropy">0.0000</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Entropy Delta (ΔH)</div>
    <div class="stat-val green" id="statDeltaEntropy">0.00%</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Passes Executed</div>
    <div class="stat-val amber" id="statPasses">0</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Symbols Resolved</div>
    <div class="stat-val cyan" id="statSymbols">0</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Size Compression</div>
    <div class="stat-val green" id="statCompression">0.0%</div>
  </div>
</div>

<div class="main-workspace">
  <!-- Left Column: Input and Entropy Profiler -->
  <div class="pane">
    <div class="pane-header">
      <span>SOURCE BATCH SCRIPT (OBFUSCATED)</span>
      <span id="rawMeta" style="font-family: var(--font-mono); color: var(--text-muted);">0 lines, 0 chars</span>
    </div>
    <div class="editor-container">
      <textarea id="rawInput" spellcheck="false" placeholder="Paste obfuscated batch script (.bat / .cmd) here, or select a preset sample..."></textarea>
    </div>
    
    <!-- Spatial Entropy Heatmap Bar -->
    <div class="heatmap-container">
      <div class="heatmap-title">
        <span>SPATIAL ENTROPY HEATMAP (SHANNON DISTRIBUTION)</span>
        <span id="heatmapPeak">Peak: 0.00</span>
      </div>
      <div class="heatmap-strip" id="heatmapStrip"></div>
      <div class="entropy-legend">
        <div class="legend-item"><div class="legend-box" style="background:#10b981;"></div> Safe (&lt;2.5)</div>
        <div class="legend-item"><div class="legend-box" style="background:#06b6d4;"></div> Mild (2.5-3.8)</div>
        <div class="legend-item"><div class="legend-box" style="background:#f59e0b;"></div> Mod (3.8-4.6)</div>
        <div class="legend-item"><div class="legend-box" style="background:#f43f5e;"></div> High (4.6-5.5)</div>
        <div class="legend-item"><div class="legend-box" style="background:#a855f7;"></div> Critical (&gt;5.5)</div>
      </div>
    </div>

    <!-- Line-by-Line Entropy Inspector -->
    <div class="line-inspector" id="lineInspector"></div>
  </div>

  <!-- Right Column: Deobfuscated Output & Analysis -->
  <div class="pane">
    <div class="pane-header">
      <div class="pane-tabs">
        <button class="tab-btn active" data-tab="output">Deobfuscated Script</button>
        <button class="tab-btn" data-tab="diff">Unified Diff</button>
        <button class="tab-btn" data-tab="matrix">Engine Detections (18)</button>
        <button class="tab-btn" data-tab="cccs">CCCS Traits</button>
      </div>
      <div>
        <button class="btn-secondary" id="btnCopy" style="padding: 2px 8px; font-size: 11px;">Copy</button>
        <button class="btn-secondary" id="btnDownload" style="padding: 2px 8px; font-size: 11px;">Save .bat</button>
      </div>
    </div>

    <div class="editor-container">
      <pre class="code-view" id="outputView"></pre>
      <pre class="code-view" id="diffView" style="display:none;"></pre>
      <div class="engine-matrix" id="engineMatrix" style="display:none;"></div>
      <div class="engine-matrix" id="cccsMatrix" style="display:none;"></div>
    </div>
  </div>
</div>

<footer>
  <div class="status-msg" id="statusMessage">Ready. Load a sample or paste batch code to begin forensic analysis.</div>
  <div>Ctrl+Enter: Deobfuscate | Maya Thorne Forensics Engine</div>
</footer>

<script>
{DASHBOARD_JS}
</script>
</body>
</html>
"""
