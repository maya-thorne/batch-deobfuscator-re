"""
Embedded CSS Styles for the Forensic Web Dashboard.
Cyber-forensics dark theme with zero external CDN dependencies.
Part of batch-deobfuscator security toolchain.
"""

DASHBOARD_CSS = """
:root {
  --bg-primary: #0b0f19;
  --bg-secondary: #111827;
  --bg-tertiary: #1f2937;
  --bg-panel: #0d1322;
  --border-color: #243047;
  --border-focus: #38bdf8;
  --text-primary: #f1f5f9;
  --text-secondary: #94a3b8;
  --text-muted: #64748b;
  --accent-cyan: #06b6d4;
  --accent-blue: #38bdf8;
  --accent-green: #10b981;
  --accent-amber: #f59e0b;
  --accent-rose: #f43f5e;
  --accent-purple: #a855f7;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background-color: var(--bg-primary);
  color: var(--text-primary);
  font-family: var(--font-sans);
  line-height: 1.5;
  height: 100vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
header {
  background-color: var(--bg-secondary);
  border-bottom: 1px solid var(--border-color);
  padding: 10px 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-shrink: 0;
}
.brand {
  display: flex;
  align-items: center;
  gap: 12px;
}
.brand-icon {
  width: 28px;
  height: 28px;
  background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: var(--font-mono);
  font-weight: bold;
  font-size: 14px;
  color: #fff;
}
.brand-title {
  font-size: 16px;
  font-weight: 700;
  letter-spacing: 0.5px;
  color: var(--text-primary);
}
.brand-ver {
  font-family: var(--font-mono);
  font-size: 11px;
  background: var(--bg-tertiary);
  color: var(--accent-cyan);
  padding: 2px 7px;
  border-radius: 12px;
  border: 1px solid var(--border-color);
}
.header-badges {
  display: flex;
  gap: 8px;
}
.badge {
  font-size: 11px;
  font-family: var(--font-mono);
  padding: 3px 8px;
  border-radius: 4px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  color: var(--text-secondary);
  display: flex;
  align-items: center;
  gap: 5px;
}
.badge-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--accent-green);
}
.toolbar {
  background: var(--bg-panel);
  border-bottom: 1px solid var(--border-color);
  padding: 8px 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-shrink: 0;
}
.tool-group {
  display: flex;
  align-items: center;
  gap: 8px;
}
label {
  font-size: 12px;
  color: var(--text-secondary);
  font-weight: 500;
}
select, input, button {
  font-family: inherit;
  font-size: 12px;
  background: var(--bg-tertiary);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  padding: 5px 10px;
  outline: none;
}
select:focus, input:focus {
  border-color: var(--border-focus);
}
.btn-primary {
  background: linear-gradient(135deg, #0284c7, #0369a1);
  color: #ffffff;
  border: 1px solid #38bdf8;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s ease;
}
.btn-primary:hover {
  background: linear-gradient(135deg, #0369a1, #075985);
}
.btn-secondary {
  cursor: pointer;
  background: var(--bg-tertiary);
}
.btn-secondary:hover {
  background: #334155;
}
.stats-strip {
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border-color);
  padding: 8px 20px;
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 12px;
  flex-shrink: 0;
}
.stat-card {
  background: var(--bg-panel);
  border: 1px solid var(--border-color);
  border-radius: 5px;
  padding: 6px 12px;
  display: flex;
  flex-direction: column;
}
.stat-label {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  margin-bottom: 2px;
}
.stat-val {
  font-size: 16px;
  font-weight: 700;
  font-family: var(--font-mono);
  color: var(--text-primary);
  display: flex;
  align-items: center;
  gap: 6px;
}
.stat-val.cyan { color: var(--accent-cyan); }
.stat-val.green { color: var(--accent-green); }
.stat-val.rose { color: var(--accent-rose); }
.stat-val.amber { color: var(--accent-amber); }
.main-workspace {
  flex: 1;
  display: grid;
  grid-template-columns: 1fr 1fr;
  overflow: hidden;
  background: var(--bg-primary);
}
.pane {
  display: flex;
  flex-direction: column;
  overflow: hidden;
  border-right: 1px solid var(--border-color);
}
.pane:last-child {
  border-right: none;
}
.pane-header {
  background: var(--bg-secondary);
  padding: 6px 14px;
  border-bottom: 1px solid var(--border-color);
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 12px;
  font-weight: 600;
}
.pane-tabs {
  display: flex;
  gap: 4px;
}
.tab-btn {
  background: transparent;
  border: 1px solid transparent;
  color: var(--text-secondary);
  padding: 3px 8px;
  font-size: 11px;
  border-radius: 3px;
  cursor: pointer;
}
.tab-btn.active {
  background: var(--bg-tertiary);
  border-color: var(--border-color);
  color: var(--text-primary);
}
.editor-container {
  flex: 1;
  position: relative;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
textarea, .code-view {
  flex: 1;
  width: 100%;
  background: var(--bg-primary);
  color: #e2e8f0;
  border: none;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.5;
  padding: 12px;
  resize: none;
  outline: none;
  overflow: auto;
  white-space: pre;
}
.code-view {
  background: #090d16;
}
.diff-add { background: rgba(16, 185, 129, 0.15); color: #6ee7b7; }
.diff-del { background: rgba(244, 63, 94, 0.15); color: #fda4af; }
.diff-info { color: #38bdf8; font-weight: bold; }
.heatmap-container {
  background: var(--bg-panel);
  border-top: 1px solid var(--border-color);
  padding: 10px 14px;
  display: flex;
  flex-direction: column;
  gap: 6px;
  flex-shrink: 0;
}
.heatmap-title {
  display: flex;
  justify-content: space-between;
  font-size: 11px;
  color: var(--text-secondary);
  font-family: var(--font-mono);
}
.heatmap-strip {
  height: 18px;
  border-radius: 3px;
  display: flex;
  overflow: hidden;
  border: 1px solid var(--border-color);
  background: #030712;
}
.heatmap-block {
  flex: 1;
  transition: opacity 0.1s;
  cursor: pointer;
}
.heatmap-block:hover {
  opacity: 0.7;
}
.entropy-legend {
  display: flex;
  gap: 12px;
  font-size: 10px;
  color: var(--text-muted);
  align-items: center;
}
.legend-item {
  display: flex;
  align-items: center;
  gap: 4px;
}
.legend-box {
  width: 10px;
  height: 10px;
  border-radius: 2px;
}
.line-inspector {
  max-height: 140px;
  overflow-y: auto;
  border-top: 1px solid var(--border-color);
  background: #070b14;
  font-family: var(--font-mono);
  font-size: 11px;
}
.line-entry {
  display: flex;
  align-items: center;
  padding: 2px 10px;
  border-bottom: 1px solid rgba(255,255,255,0.03);
}
.line-entry:hover {
  background: rgba(255,255,255,0.05);
}
.line-num { width: 36px; color: var(--text-muted); }
.line-ent { width: 60px; font-weight: 600; }
.line-txt { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-secondary); }
.engine-matrix {
  padding: 12px;
  overflow-y: auto;
  flex: 1;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 8px;
  background: #070b14;
}
.engine-card {
  background: var(--bg-panel);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  padding: 8px 10px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.engine-card.active {
  border-color: var(--accent-rose);
  background: rgba(244, 63, 94, 0.05);
}
.engine-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.engine-name {
  font-weight: 600;
  font-size: 12px;
  color: var(--text-primary);
}
.engine-pill {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 10px;
  font-family: var(--font-mono);
  background: var(--bg-tertiary);
  color: var(--text-muted);
}
.engine-card.active .engine-pill {
  background: var(--accent-rose);
  color: #fff;
}
.engine-desc {
  font-size: 11px;
  color: var(--text-secondary);
}
.engine-tag {
  font-size: 10px;
  color: var(--accent-cyan);
  font-family: var(--font-mono);
}
footer {
  background: var(--bg-secondary);
  border-top: 1px solid var(--border-color);
  padding: 4px 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 11px;
  color: var(--text-muted);
  flex-shrink: 0;
}
.status-msg {
  display: flex;
  align-items: center;
  gap: 6px;
}
.status-spin {
  display: inline-block;
  width: 10px;
  height: 10px;
  border: 2px solid var(--accent-cyan);
  border-top-color: transparent;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
"""
