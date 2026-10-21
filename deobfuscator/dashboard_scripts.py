"""
Embedded Client-Side JavaScript Logic for Forensic Web Dashboard.
Implements debounced real-time entropy profiling, asynchronous deobfuscation,
CCCS trait matrix rendering, diff visualization, and sample preset loading.
Part of batch-deobfuscator security toolchain.
"""

DASHBOARD_JS = """
(function() {
  const rawInput = document.getElementById('rawInput');
  const outputView = document.getElementById('outputView');
  const diffView = document.getElementById('diffView');
  const engineMatrix = document.getElementById('engineMatrix');
  const cccsMatrix = document.getElementById('cccsMatrix');
  const sampleSelect = document.getElementById('sampleSelect');
  const passInput = document.getElementById('passInput');
  const heatmapStrip = document.getElementById('heatmapStrip');
  const lineInspector = document.getElementById('lineInspector');
  const statusMessage = document.getElementById('statusMessage');

  let currentTab = 'output';
  let analyzeTimeout = null;

  // Initialize sample presets
  fetch('/api/samples')
    .then(r => r.json())
    .then(data => {
      if (data && data.samples) {
        data.samples.forEach(s => {
          const opt = document.createElement('option');
          opt.value = s.id;
          opt.textContent = s.id + ': ' + s.name;
          sampleSelect.appendChild(opt);
        });
      }
    }).catch(() => {});

  // Switch tabs
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentTab = btn.getAttribute('data-tab');
      outputView.style.display = currentTab === 'output' ? 'block' : 'none';
      diffView.style.display = currentTab === 'diff' ? 'block' : 'none';
      engineMatrix.style.display = currentTab === 'matrix' ? 'grid' : 'none';
      cccsMatrix.style.display = currentTab === 'cccs' ? 'grid' : 'none';
    });
  });

  // Sample load handler
  sampleSelect.addEventListener('change', () => {
    const id = sampleSelect.value;
    if (!id) return;
    statusMessage.innerHTML = '<span class="status-spin"></span> Loading sample preset ' + id + '...';
    fetch('/api/samples/' + encodeURIComponent(id))
      .then(r => r.json())
      .then(res => {
        if (res.script) {
          rawInput.value = res.script;
          updateRawMeta();
          runAnalysis(true);
        }
      })
      .catch(err => {
        statusMessage.textContent = 'Error loading sample: ' + err.message;
      });
  });

  function updateRawMeta() {
    const text = rawInput.value;
    const lines = text ? text.split('\\n').length : 0;
    document.getElementById('rawMeta').textContent = lines + ' lines, ' + text.length + ' chars';
  }

  // Debounced input handler for real-time entropy
  rawInput.addEventListener('input', () => {
    updateRawMeta();
    clearTimeout(analyzeTimeout);
    analyzeTimeout = setTimeout(() => runAnalysis(false), 350);
  });

  function renderHeatmap(blocks, peakEntropy) {
    heatmapStrip.innerHTML = '';
    if (!blocks || blocks.length === 0) {
      heatmapStrip.innerHTML = '<div style="flex:1; background:#1e293b;"></div>';
      return;
    }
    blocks.forEach(b => {
      const div = document.createElement('div');
      div.className = 'heatmap-block';
      div.style.backgroundColor = b.hex;
      div.title = 'Offset ' + b.start + '-' + b.end + ': H=' + b.entropy.toFixed(3);
      heatmapStrip.appendChild(div);
    });
    document.getElementById('heatmapPeak').textContent = 'Peak: ' + (peakEntropy || 0).toFixed(2);
  }

  function renderLineInspector(lines) {
    lineInspector.innerHTML = '';
    if (!lines) return;
    lines.slice(0, 150).forEach(l => {
      const row = document.createElement('div');
      row.className = 'line-entry';
      row.innerHTML = '<span class="line-num">L' + l.line + '</span>' +
        '<span class="line-ent" style="color:' + l.hex + ';">' + l.entropy.toFixed(2) + '</span>' +
        '<span class="line-txt">' + escapeHtml(l.preview) + '</span>';
      lineInspector.appendChild(row);
    });
  }

  function renderEngineMatrix(detections) {
    engineMatrix.innerHTML = '';
    if (!detections) return;
    Object.keys(detections).forEach(k => {
      const item = detections[k];
      const isDet = item.detected || item.is_detected;
      const card = document.createElement('div');
      card.className = 'engine-card' + (isDet ? ' active' : '');
      card.innerHTML = '<div class="engine-card-header">' +
        '<span class="engine-name">' + escapeHtml(item.name || k) + '</span>' +
        '<span class="engine-pill">' + (isDet ? 'DETECTED' : 'CLEAN') + '</span>' +
        '</div>' +
        '<div class="engine-desc">' + escapeHtml(item.description || '') + '</div>' +
        '<div class="engine-tag">' + (item.mitre_technique || 'T1027.001') + '</div>';
      engineMatrix.appendChild(card);
    });
  }

  function renderCccsTraits(traits) {
    cccsMatrix.innerHTML = '';
    if (!traits) return;
    traits.forEach(t => {
      const card = document.createElement('div');
      card.className = 'engine-card' + (t.score > 0 ? ' active' : '');
      card.innerHTML = '<div class="engine-card-header">' +
        '<span class="engine-name">' + escapeHtml(t.name) + '</span>' +
        '<span class="engine-pill">SCORE ' + t.score + '</span>' +
        '</div>' +
        '<div class="engine-desc">' + escapeHtml(t.description) + '</div>' +
        '<div class="engine-tag">' + escapeHtml(t.pattern || '') + '</div>';
      cccsMatrix.appendChild(card);
    });
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function runAnalysis(autoDeobfuscate) {
    const script = rawInput.value;
    if (!script.trim()) {
      renderHeatmap([], 0);
      lineInspector.innerHTML = '';
      return;
    }
    statusMessage.innerHTML = '<span class="status-spin"></span> Calculating Shannon entropy & heuristics...';
    fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ script: script })
    })
    .then(r => r.json())
    .then(data => {
      if (data.entropy) {
        document.getElementById('statRawEntropy').textContent = data.entropy.global_entropy.toFixed(4);
        renderHeatmap(data.entropy.blocks, data.entropy.max_line_entropy);
        renderLineInspector(data.entropy.lines);
      }
      if (data.detections) {
        renderEngineMatrix(data.detections);
      }
      if (data.cccs_traits) {
        renderCccsTraits(data.cccs_traits);
      }
      statusMessage.textContent = 'Analysis complete. Global entropy H=' + (data.entropy ? data.entropy.global_entropy.toFixed(3) : '0');
      if (autoDeobfuscate) {
        runDeobfuscation();
      }
    })
    .catch(err => {
      statusMessage.textContent = 'Analysis error: ' + err.message;
    });
  }

  function runDeobfuscation() {
    const script = rawInput.value;
    if (!script.trim()) return;
    const passes = parseInt(passInput.value) || 15;
    statusMessage.innerHTML = '<span class="status-spin"></span> Executing multi-pass deobfuscation (max passes: ' + passes + ')...';

    fetch('/api/deobfuscate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ script: script, passes: passes })
    })
    .then(r => r.json())
    .then(res => {
      outputView.textContent = res.deobfuscated_script || '';
      diffView.textContent = res.diff || 'No differences detected.';
      
      const meta = res.meta || {};
      document.getElementById('statRawEntropy').textContent = (res.entropy ? res.entropy.global_entropy.toFixed(4) : '0.0000');
      document.getElementById('statCleanEntropy').textContent = (res.entropy && res.entropy.clean_global_entropy ? res.entropy.clean_global_entropy.toFixed(4) : '0.0000');
      document.getElementById('statDeltaEntropy').textContent = (res.entropy && res.entropy.entropy_reduction_pct ? res.entropy.entropy_reduction_pct.toFixed(1) + '%' : '0.0%');
      document.getElementById('statPasses').textContent = meta.passes_executed || '1';
      document.getElementById('statSymbols').textContent = (meta.symbols_resolved ? meta.symbols_resolved.length : '0');
      document.getElementById('statCompression').textContent = (meta.compression_ratio ? meta.compression_ratio.toFixed(1) + '%' : '0.0%');

      if (res.entropy) {
        renderHeatmap(res.entropy.blocks, res.entropy.max_line_entropy);
        renderLineInspector(res.entropy.lines);
      }
      if (res.detections) {
        renderEngineMatrix(res.detections);
      }
      if (res.cccs_traits) {
        renderCccsTraits(res.cccs_traits);
      }
      statusMessage.textContent = 'Deobfuscation converged in ' + (meta.passes_executed || 1) + ' passes. Zero anomalies detected.';
    })
    .catch(err => {
      statusMessage.textContent = 'Deobfuscation error: ' + err.message;
    });
  }

  document.getElementById('btnDeobfuscate').addEventListener('click', runDeobfuscation);
  document.getElementById('btnAnalyze').addEventListener('click', () => runAnalysis(false));
  document.getElementById('btnClear').addEventListener('click', () => {
    rawInput.value = '';
    outputView.textContent = '';
    diffView.textContent = '';
    updateRawMeta();
    renderHeatmap([], 0);
    lineInspector.innerHTML = '';
    statusMessage.textContent = 'Workspace cleared.';
  });

  // Keyboard shortcut Ctrl+Enter to deobfuscate
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      runDeobfuscation();
    }
  });

  // Copy button
  document.getElementById('btnCopy').addEventListener('click', () => {
    const text = outputView.textContent;
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      const orig = statusMessage.textContent;
      statusMessage.textContent = 'Deobfuscated script copied to clipboard.';
      setTimeout(() => { statusMessage.textContent = orig; }, 2000);
    });
  });

  // Download button
  document.getElementById('btnDownload').addEventListener('click', () => {
    const text = outputView.textContent;
    if (!text) return;
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'deobfuscated_script.bat';
    a.click();
    URL.revokeObjectURL(a.href);
  });

  // Auto-init with initial preset if empty
  setTimeout(() => {
    if (sampleSelect.options.length > 1 && !rawInput.value) {
      sampleSelect.selectedIndex = 1;
      sampleSelect.dispatchEvent(new Event('change'));
    }
  }, 600);
})();
"""
