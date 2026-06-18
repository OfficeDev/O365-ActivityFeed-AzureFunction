'use strict';
// Builds a single, self-contained shareable HTML report from the sample
// snapshots + the app's CSS/JS. Output: web/sample-report.html (no external
// assets, no file loading — opens and renders the delta immediately).
const fs = require('fs');
const path = require('path');

const dir = path.join(__dirname, '..');
const css = fs.readFileSync(path.join(dir, 'styles.css'), 'utf8');
const js = fs.readFileSync(path.join(dir, 'app.js'), 'utf8');
const baseJson = fs.readFileSync(path.join(dir, 'sample-baseline.json'), 'utf8');
const curJson = fs.readFileSync(path.join(dir, 'sample-current.json'), 'utf8');

// Escape </script> sequences so embedded JSON can't break out of the script tag.
const safe = (s) => s.replace(/<\/script>/gi, '<\\/script>');

const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SIT Tuning &mdash; Round-over-Round Delta (Sample)</title>
  <style>
${css}
.sample-banner{background:rgba(76,154,255,.1);border:1px solid var(--accent);color:var(--text);border-radius:8px;padding:10px 14px;margin:0 0 18px;font-size:.88rem;}
  </style>
</head>
<body>
  <header class="app-header">
    <h1>SIT Tuning &mdash; Round-over-Round Delta</h1>
    <p class="subtitle">
      Comparison of a baseline run against a post-tuning run, showing how much the
      new SIT regex suppressions reduced noise.
    </p>
  </header>

  <div class="sample-banner">
    <strong>Sample report.</strong> Baseline <code>baseline-pretuning</code> vs. new run
    <code>post-tuning</code>. This is a self-contained snapshot &mdash; no data is loaded from a server.
  </div>

  <section id="results" class="results">
    <h2>Headline delta</h2>
    <div id="metricCards" class="metric-cards"></div>

    <div class="grid-2">
      <div class="panel">
        <h3>Noise occurrences by SIT rule</h3>
        <div id="sitRuleChart" class="bar-chart"></div>
      </div>
      <div class="panel">
        <h3>Detections by workload</h3>
        <div id="workloadChart" class="bar-chart"></div>
      </div>
    </div>

    <div class="panel">
      <h3>Top suppressed / changed noise patterns</h3>
      <table id="noiseTable" class="data-table">
        <thead>
          <tr>
            <th>Pattern</th><th>SIT rule</th><th>Workload</th>
            <th class="num">Baseline</th><th class="num">New</th><th class="num">&Delta;</th><th>Status</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>

    <div class="panel">
      <h3>Validated findings (true-positive guardrail)</h3>
      <p class="hint">Watch for unexpected <strong>drops</strong> here &mdash; tuning should cut noise, not real sensitive data.</p>
      <table id="validatedTable" class="data-table">
        <thead>
          <tr>
            <th>Finding</th><th>Type</th><th>SIT rule</th><th>Risk</th>
            <th class="num">Baseline</th><th class="num">New</th><th class="num">&Delta;</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </section>

  <script id="data-baseline" type="application/json">${safe(baseJson)}</script>
  <script id="data-current" type="application/json">${safe(curJson)}</script>
  <!-- Hidden control stubs so the shared app.js event wiring finds its targets. -->
  <div hidden>
    <button id="compareBtn"></button>
    <button id="swapBtn"></button>
    <button id="clearBtn"></button>
    <div id="emptyState"></div>
  </div>
  <script>
${js}
  </script>
  <script>
    // Bootstrap: parse the embedded snapshots and render immediately.
    (function () {
      const base = JSON.parse(document.getElementById('data-baseline').textContent);
      const cur = JSON.parse(document.getElementById('data-current').textContent);
      runs.baseline = parseRun(base, base.label || 'baseline');
      runs.current = parseRun(cur, cur.label || 'current');
      renderCards(runs.baseline.metrics, runs.current.metrics);
      renderRuleChart(runs.baseline.metrics, runs.current.metrics);
      renderWorkloadChart(runs.baseline.metrics, runs.current.metrics);
      renderNoiseTable(runs.baseline.metrics, runs.current.metrics);
      renderValidatedTable(runs.baseline.metrics, runs.current.metrics);
    })();
  </script>
</body>
</html>
`;

const out = path.join(dir, 'sample-report.html');
fs.writeFileSync(out, html, 'utf8');
console.log('Wrote', out, '(' + Math.round(html.length / 1024) + ' KB)');
