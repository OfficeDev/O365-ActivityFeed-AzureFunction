'use strict';

// ---------------------------------------------------------------------------
// State: two loaded runs keyed by slot ("baseline" | "current").
// ---------------------------------------------------------------------------
const runs = { baseline: null, current: null };

// ---------------------------------------------------------------------------
// Parsing: accept either a run snapshot written by credpattern.ps1
//   { label, generatedAt, rawDetectionCount, chunkAnalyses: [...] }
// or a raw SIT_ChunkAnalyses.json array
//   [ { chunk_index, parsed_json, analysis_result }, ... ]
// ---------------------------------------------------------------------------
function parseRun(json, fileName) {
  let meta = { label: fileName, generatedAt: null, rawDetectionCount: null, dlpPolicy: null, profile: null };
  let chunkEntries;

  if (Array.isArray(json)) {
    chunkEntries = json;
  } else if (json && Array.isArray(json.chunkAnalyses)) {
    chunkEntries = json.chunkAnalyses;
    meta = {
      label: json.label || fileName,
      generatedAt: json.generatedAt || null,
      rawDetectionCount: Number.isFinite(json.rawDetectionCount) ? json.rawDetectionCount : null,
      dlpPolicy: json.dlpPolicy || null,
      profile: json.profile || null,
    };
  } else {
    throw new Error('Unrecognized file shape: expected a run snapshot or SIT_ChunkAnalyses.json array.');
  }

  // Pull the parsed analysis object out of each chunk entry.
  const analyses = [];
  for (const entry of chunkEntries) {
    if (!entry) continue;
    let result = entry.analysis_result !== undefined ? entry.analysis_result : entry;
    if (typeof result === 'string') {
      try { result = JSON.parse(result); } catch { continue; }
    }
    if (result && typeof result === 'object') analyses.push(result);
  }

  return { meta, analyses, metrics: aggregate(analyses, meta) };
}

// ---------------------------------------------------------------------------
// Aggregation: roll the per-chunk arrays up into one set of comparable metrics.
// Headline numbers are computed from the structured arrays (defensible and
// independent of the AI's self-reported totals).
// ---------------------------------------------------------------------------
function num(v) { const n = Number(v); return Number.isFinite(n) ? n : 0; }
function normKey(s) { return (s == null ? '' : String(s)).trim(); }
function workloadOf(s) { const w = normKey(s); return w === '' ? 'Unspecified' : w; }
function ruleOf(s) { const r = normKey(s); return r === '' ? 'Unspecified' : r; }

function aggregate(analyses, meta) {
  const m = {
    rawDetectionCount: meta.rawDetectionCount,
    chunkCount: analyses.length,
    noiseOccurrences: 0,
    uniqueNoisePatterns: 0,
    validatedInstances: 0,
    credentialPairInstances: 0,
    fpReductionWeighted: 0,
    noiseByRule: new Map(),       // rule -> occurrences
    detectionsByWorkload: new Map(), // workload -> noise + validated occurrences
    noiseByPattern: new Map(),    // pattern -> { pattern, rule, workload, count }
    validatedByKey: new Map(),    // key -> { pattern, type, rule, risk, count }
    riskCounts: { HIGH: 0, MEDIUM: 0, LOW: 0 },
  };

  let fpWeightSum = 0;

  for (const a of analyses) {
    for (const n of (a.noise_patterns || [])) {
      const occ = num(n.occurrence_count) || 1;
      const rule = ruleOf(n.triggering_sit_rule);
      const wl = workloadOf(n.source_workload);
      m.noiseOccurrences += occ;
      m.noiseByRule.set(rule, (m.noiseByRule.get(rule) || 0) + occ);
      bumpWorkload(m, wl, occ, 0);

      const key = normKey(n.pattern) || `${rule}:${occ}`;
      const prev = m.noiseByPattern.get(key) || { pattern: normKey(n.pattern) || '(unnamed)', rule, workload: wl, count: 0 };
      prev.count += occ;
      m.noiseByPattern.set(key, prev);

      const fp = num(n.estimated_fp_reduction);
      if (fp > 0) { m.fpReductionWeighted += fp * occ; fpWeightSum += occ; }
    }

    for (const v of (a.validated_credentials || [])) {
      const cnt = num(v.count) || 1;
      const rule = ruleOf(v.triggering_sit_rule);
      const wl = workloadOf(v.source_workload);
      const risk = (normKey(v.risk_level).toUpperCase() || 'LOW');
      m.validatedInstances += cnt;
      bumpWorkload(m, wl, 0, cnt);
      if (risk.startsWith('HIGH')) m.riskCounts.HIGH += cnt;
      else if (risk.startsWith('MED')) m.riskCounts.MEDIUM += cnt;
      else m.riskCounts.LOW += cnt;

      const key = normKey(v.pattern) || `${rule}:${v.type}`;
      const prev = m.validatedByKey.get(key) || {
        pattern: normKey(v.pattern) || '(unnamed)', type: normKey(v.type) || '—',
        rule, risk, count: 0,
      };
      prev.count += cnt;
      m.validatedByKey.set(key, prev);
    }

    for (const p of (a.credential_pairs || [])) {
      m.credentialPairInstances += num(p.count) || 1;
    }
  }

  m.uniqueNoisePatterns = m.noiseByPattern.size;
  m.fpReductionWeighted = fpWeightSum > 0 ? m.fpReductionWeighted / fpWeightSum : 0;
  m.totalDetections = m.rawDetectionCount != null
    ? m.rawDetectionCount
    : (m.noiseOccurrences + m.validatedInstances + m.credentialPairInstances);
  return m;
}

function bumpWorkload(m, wl, noise, validated) {
  const e = m.detectionsByWorkload.get(wl) || { noise: 0, validated: 0 };
  e.noise += noise; e.validated += validated;
  m.detectionsByWorkload.set(wl, e);
}

// ---------------------------------------------------------------------------
// File loading wiring (drag/drop + click).
// ---------------------------------------------------------------------------
document.querySelectorAll('.dropzone').forEach((dz) => {
  const slot = dz.dataset.slot;
  const input = dz.querySelector('input[type=file]');

  // The dropzone is a <label> wrapping the input, so a click already opens the
  // file picker natively — don't call input.click() again or the dialog opens
  // twice (forcing the user to pick the file twice).
  input.addEventListener('change', () => {
    if (input.files[0]) loadFile(slot, input.files[0]);
    // Clear so re-selecting the same file still fires 'change'.
    input.value = '';
  });

  ['dragenter', 'dragover'].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('dragover'); }));
  ['dragleave', 'drop'].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('dragover'); }));
  dz.addEventListener('drop', (e) => {
    const f = e.dataTransfer.files[0];
    if (f) loadFile(slot, f);
  });
});

function loadFile(slot, file) {
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const json = JSON.parse(reader.result);
      runs[slot] = parseRun(json, file.name);
      markLoaded(slot, file.name, runs[slot]);
    } catch (err) {
      runs[slot] = null;
      const meta = document.querySelector(`.file-meta[data-slot="${slot}"]`);
      meta.innerHTML = `<span style="color:var(--bad)">Failed to parse: ${escapeHtml(err.message)}</span>`;
      document.querySelector(`.dropzone[data-slot="${slot}"]`).classList.remove('loaded');
    }
    refreshButtons();
  };
  reader.readAsText(file);
}

function markLoaded(slot, name, run) {
  const dz = document.querySelector(`.dropzone[data-slot="${slot}"]`);
  dz.classList.add('loaded');
  dz.querySelector('.dz-text').textContent = name;
  const meta = document.querySelector(`.file-meta[data-slot="${slot}"]`);
  const when = run.meta.generatedAt ? ` &middot; ${escapeHtml(run.meta.generatedAt)}` : '';
  const profile = run.meta.profile ? ` &middot; profile: ${escapeHtml(run.meta.profile)}` : '';
  const policy = run.meta.dlpPolicy ? ` &middot; policy: ${escapeHtml(run.meta.dlpPolicy)}` : '';
  meta.innerHTML = `<strong>${run.metrics.chunkCount}</strong> chunks &middot; ` +
    `<strong>${fmt(run.metrics.totalDetections)}</strong> detections${when}${profile}${policy}`;
}

function refreshButtons() {
  const both = runs.baseline && runs.current;
  document.getElementById('compareBtn').disabled = !both;
  document.getElementById('swapBtn').disabled = !(runs.baseline || runs.current);
  document.getElementById('clearBtn').disabled = !(runs.baseline || runs.current);
}

function setDeltaStatus(text, kind) {
  const el = document.getElementById('deltaStatus');
  if (!el) return;
  el.textContent = text || '';
  el.className = 'status-pill' + (kind ? ' ' + kind : '');
}

document.getElementById('compareBtn').addEventListener('click', renderComparison);
document.getElementById('swapBtn').addEventListener('click', () => {
  [runs.baseline, runs.current] = [runs.current, runs.baseline];
  ['baseline', 'current'].forEach((slot) => {
    const r = runs[slot];
    const dz = document.querySelector(`.dropzone[data-slot="${slot}"]`);
    const meta = document.querySelector(`.file-meta[data-slot="${slot}"]`);
    if (r) { dz.classList.add('loaded'); dz.querySelector('.dz-text').textContent = r.meta.label; markLoaded(slot, r.meta.label, r); }
    else { dz.classList.remove('loaded'); meta.textContent = ''; dz.querySelector('.dz-text').textContent = 'Drop a file or click to browse'; }
  });
  refreshButtons();
  if (runs.baseline && runs.current) renderComparison();
});
document.getElementById('clearBtn').addEventListener('click', () => location.reload());

// Light-theme styles for the delta components in the standalone export.
const DELTA_EXPORT_CSS = `
  .report-body h2 { font-size: 20px; color:#0b1a33; margin: 1.6em 0 .6em; }
  .report-body h3 { font-size: 16px; color:#0b1a33; margin: 0 0 12px; }
  .metric-cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:12px; margin: 8px 0 4px; }
  .card { background:#fff; border:1px solid #d0d7de; border-radius:10px; padding:14px 16px; }
  .card .label { color:#6e7781; font-size:.8rem; text-transform:uppercase; letter-spacing:.03em; }
  .card .values { display:flex; align-items:baseline; gap:8px; margin-top:6px; }
  .card .new-val { font-size:1.7rem; font-weight:700; color:#0b1a33; }
  .card .base-val { color:#6e7781; font-size:.9rem; }
  .card .delta { margin-top:6px; font-size:.9rem; font-weight:600; }
  .delta.good, .num .down, .bar-val .down { color:#1a7f37; }
  .delta.bad, .num .up, .bar-val .up { color:#cf222e; }
  .delta.warn { color:#9a6700; }
  .delta.neutral { color:#6e7781; }
  .grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin:16px 0; }
  .report-body .panel { background:#fff; border:1px solid #d0d7de; border-radius:10px; padding:18px 20px; margin:16px 0; }
  .bar-chart { display:flex; flex-direction:column; gap:10px; }
  .bar-row { display:grid; grid-template-columns:130px 1fr auto; gap:10px; align-items:center; font-size:.85rem; }
  .bar-row .bar-label { color:#57606a; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .bar-track { position:relative; height:22px; background:#eaeef2; border-radius:5px; overflow:hidden; }
  .bar-fill { position:absolute; top:0; left:0; height:100%; border-radius:5px; }
  .bar-fill.base { background:rgba(140,150,165,.55); }
  .bar-fill.cur { background:#3b6fd4; opacity:.85; }
  .bar-cur-wrap { position:relative; height:22px; }
  .bar-val { font-variant-numeric:tabular-nums; min-width:96px; text-align:right; color:#24292f; }
  .data-table { width:100%; border-collapse:collapse; font-size:.85rem; }
  .data-table th, .data-table td { padding:7px 10px; text-align:left; border-bottom:1px solid #d0d7de; }
  .data-table th { color:#57606a; font-weight:600; background:#f3f5f8; }
  .data-table td.num, .data-table th.num { text-align:right; font-variant-numeric:tabular-nums; }
  .data-table tr:nth-child(even) td { background:#f8fafc; }
  .data-table .pattern { font-family:Consolas,Menlo,monospace; font-size:.8rem; max-width:340px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .tag { display:inline-block; padding:2px 10px; border-radius:999px; font-size:.72rem; font-weight:600; border:1px solid transparent; }
  .tag.removed, .tag.down { background:rgba(26,127,55,.12); color:#1a7f37; }
  .tag.new, .tag.up { background:rgba(207,34,46,.12); color:#cf222e; }
  .tag.same { background:#eaeef2; color:#57606a; }
  .tag.risk-high { background:rgba(207,34,46,.16); color:#cf222e; }
  .tag.risk-med { background:rgba(154,103,0,.16); color:#9a6700; }
  .tag.risk-low { background:#eaeef2; color:#57606a; }
  .hint { color:#6e7781; font-size:.85rem; }`;

function exportDelta() {
  const results = document.getElementById('results');
  if (!results || results.hidden || !runs.baseline || !runs.current) return;
  const bm = runs.baseline.meta || {};
  const cm = runs.current.meta || {};
  const policy = cm.dlpPolicy || bm.dlpPolicy || '';
  const profile = cm.profile || bm.profile || '';
  const heading = profile
    ? `SIT Delta Comparison \u2014 ${profile}`
    : 'SIT Delta Comparison';
  const metaBits = [];
  if (profile) metaBits.push(`Profile: ${profile}`);
  if (policy) metaBits.push(`DLP policy: ${policy}`);
  metaBits.push(`Baseline: ${bm.label || 'baseline'}`);
  metaBits.push(`New: ${cm.label || 'current'}`);
  try {
    const name = window.exportStandaloneHtml({
      title: heading,
      heading,
      eyebrow: 'SIT Tuning Studio \u00b7 Delta comparison',
      meta: metaBits,
      bodyHtml: results.innerHTML,
      extraCss: DELTA_EXPORT_CSS,
      fileBase: `delta-${profile || policy || 'comparison'}`,
    });
    setDeltaStatus(`Exported ${name}`, 'ok');
  } catch (e) {
    setDeltaStatus('Export failed', 'bad');
  }
}

document.getElementById('exportBtn').addEventListener('click', exportDelta);

// ---------------------------------------------------------------------------
// Rendering the comparison.
// ---------------------------------------------------------------------------
function renderComparison() {
  const b = runs.baseline.metrics;
  const c = runs.current.metrics;

  document.getElementById('emptyState').hidden = true;
  document.getElementById('results').hidden = false;

  renderCards(b, c);
  renderRuleChart(b, c);
  renderWorkloadChart(b, c);
  renderNoiseTable(b, c);
  renderValidatedTable(b, c);
  document.getElementById('exportBtn').disabled = false;
  document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
}

// "lowerIsBetter" decides which direction is colored green.
function renderCards(b, c) {
  const cards = [
    { label: 'Total detections', base: b.totalDetections, cur: c.totalDetections, lowerIsBetter: true },
    { label: 'Noise occurrences', base: b.noiseOccurrences, cur: c.noiseOccurrences, lowerIsBetter: true },
    { label: 'Unique noise patterns', base: b.uniqueNoisePatterns, cur: c.uniqueNoisePatterns, lowerIsBetter: true },
    { label: 'Validated findings', base: b.validatedInstances, cur: c.validatedInstances, lowerIsBetter: false, guardrail: true },
    { label: 'Linked finding pairs', base: b.credentialPairInstances, cur: c.credentialPairInstances, lowerIsBetter: false, guardrail: true },
    { label: 'Avg est. FP reduction', base: b.fpReductionWeighted, cur: c.fpReductionWeighted, lowerIsBetter: false, pct: true },
  ];

  document.getElementById('metricCards').innerHTML = cards.map((card) => {
    const delta = card.cur - card.base;
    const pctChange = card.base !== 0 ? (delta / card.base) * 100 : (card.cur !== 0 ? 100 : 0);
    const cls = deltaClass(delta, card.lowerIsBetter, card.guardrail);
    const arrow = delta < 0 ? '▼' : (delta > 0 ? '▲' : '■');
    const curDisp = card.pct ? `${card.cur.toFixed(0)}%` : fmt(card.cur);
    const baseDisp = card.pct ? `${card.base.toFixed(0)}%` : fmt(card.base);
    const deltaDisp = card.pct
      ? `${arrow} ${fmtSigned(delta.toFixed(0))} pts`
      : `${arrow} ${fmtSigned(delta)} (${fmtSigned(pctChange.toFixed(1))}%)`;
    return `
      <div class="card">
        <div class="label">${card.label}</div>
        <div class="values">
          <span class="new-val">${curDisp}</span>
          <span class="base-val">from ${baseDisp}</span>
        </div>
        <div class="delta ${cls}">${deltaDisp}</div>
      </div>`;
  }).join('');
}

function deltaClass(delta, lowerIsBetter, guardrail) {
  if (delta === 0) return 'neutral';
  const improved = lowerIsBetter ? delta < 0 : delta > 0;
  if (guardrail && delta < 0) return 'warn'; // a drop in true positives is a warning
  return improved ? 'good' : 'bad';
}

function renderRuleChart(b, c) {
  const keys = unionTopKeys(b.noiseByRule, c.noiseByRule, 8);
  const max = Math.max(1, ...keys.map((k) => Math.max(b.noiseByRule.get(k) || 0, c.noiseByRule.get(k) || 0)));
  document.getElementById('sitRuleChart').innerHTML = keys.map((k) =>
    barRow(k, b.noiseByRule.get(k) || 0, c.noiseByRule.get(k) || 0, max)).join('') || emptyMsg();
}

function renderWorkloadChart(b, c) {
  const total = (m, k) => { const e = m.get(k); return e ? e.noise + e.validated : 0; };
  const keys = unionTopKeys(b.detectionsByWorkload, c.detectionsByWorkload, 8, (m, k) => total(m, k));
  const max = Math.max(1, ...keys.map((k) => Math.max(total(b.detectionsByWorkload, k), total(c.detectionsByWorkload, k))));
  document.getElementById('workloadChart').innerHTML = keys.map((k) =>
    barRow(k, total(b.detectionsByWorkload, k), total(c.detectionsByWorkload, k), max)).join('') || emptyMsg();
}

function barRow(label, baseVal, curVal, max) {
  const basePct = (baseVal / max) * 100;
  const curPct = (curVal / max) * 100;
  const delta = curVal - baseVal;
  const dCls = delta < 0 ? 'down' : (delta > 0 ? 'up' : '');
  const arrow = delta < 0 ? '▼' : (delta > 0 ? '▲' : '');
  return `
    <div class="bar-row">
      <div class="bar-label" title="${escapeHtml(label)}">${escapeHtml(label)}</div>
      <div class="bar-cur-wrap">
        <div class="bar-track"><div class="bar-fill base" style="width:${basePct}%"></div></div>
        <div class="bar-track" style="margin-top:3px"><div class="bar-fill cur" style="width:${curPct}%"></div></div>
      </div>
      <div class="bar-val">${fmt(baseVal)} &rarr; ${fmt(curVal)} <span class="${dCls}">${arrow}${fmtSigned(delta)}</span></div>
    </div>`;
}

function renderNoiseTable(b, c) {
  const keys = new Set([...b.noiseByPattern.keys(), ...c.noiseByPattern.keys()]);
  const rows = [];
  for (const k of keys) {
    const bp = b.noiseByPattern.get(k);
    const cp = c.noiseByPattern.get(k);
    const baseVal = bp ? bp.count : 0;
    const curVal = cp ? cp.count : 0;
    const ref = cp || bp;
    rows.push({ pattern: ref.pattern, rule: ref.rule, workload: ref.workload, baseVal, curVal, delta: curVal - baseVal });
  }
  // Most impactful first: biggest absolute change.
  rows.sort((x, y) => Math.abs(y.delta) - Math.abs(x.delta));

  const tbody = document.querySelector('#noiseTable tbody');
  tbody.innerHTML = rows.slice(0, 40).map((r) => {
    let status, tagCls;
    if (r.baseVal > 0 && r.curVal === 0) { status = 'Removed'; tagCls = 'removed'; }
    else if (r.baseVal === 0 && r.curVal > 0) { status = 'New'; tagCls = 'new'; }
    else if (r.delta < 0) { status = 'Reduced'; tagCls = 'down'; }
    else if (r.delta > 0) { status = 'Increased'; tagCls = 'up'; }
    else { status = 'Unchanged'; tagCls = 'same'; }
    const dCls = r.delta < 0 ? 'down' : (r.delta > 0 ? 'up' : '');
    return `<tr>
      <td class="pattern" title="${escapeHtml(r.pattern)}">${escapeHtml(r.pattern)}</td>
      <td>${escapeHtml(r.rule)}</td>
      <td>${escapeHtml(r.workload)}</td>
      <td class="num">${fmt(r.baseVal)}</td>
      <td class="num">${fmt(r.curVal)}</td>
      <td class="num"><span class="${dCls}">${fmtSigned(r.delta)}</span></td>
      <td><span class="tag ${tagCls}">${status}</span></td>
    </tr>`;
  }).join('') || `<tr><td colspan="7" class="hint">No noise patterns found.</td></tr>`;
}

function renderValidatedTable(b, c) {
  const keys = new Set([...b.validatedByKey.keys(), ...c.validatedByKey.keys()]);
  const rows = [];
  for (const k of keys) {
    const bv = b.validatedByKey.get(k);
    const cv = c.validatedByKey.get(k);
    const ref = cv || bv;
    const baseVal = bv ? bv.count : 0;
    const curVal = cv ? cv.count : 0;
    rows.push({ ...ref, baseVal, curVal, delta: curVal - baseVal });
  }
  rows.sort((x, y) => y.curVal - x.curVal || Math.abs(y.delta) - Math.abs(x.delta));

  const tbody = document.querySelector('#validatedTable tbody');
  tbody.innerHTML = rows.slice(0, 40).map((r) => {
    const riskCls = r.risk.startsWith('HIGH') ? 'risk-high' : (r.risk.startsWith('MED') ? 'risk-med' : 'risk-low');
    // For true positives, a drop (negative delta) is a guardrail concern → red.
    const dCls = r.delta < 0 ? 'up' : (r.delta > 0 ? 'down' : '');
    return `<tr>
      <td class="pattern" title="${escapeHtml(r.pattern)}">${escapeHtml(r.pattern)}</td>
      <td>${escapeHtml(r.type)}</td>
      <td>${escapeHtml(r.rule)}</td>
      <td><span class="tag ${riskCls}">${escapeHtml(r.risk)}</span></td>
      <td class="num">${fmt(r.baseVal)}</td>
      <td class="num">${fmt(r.curVal)}</td>
      <td class="num"><span class="${dCls}">${fmtSigned(r.delta)}</span></td>
    </tr>`;
  }).join('') || `<tr><td colspan="7" class="hint">No validated credentials found.</td></tr>`;
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------
function unionTopKeys(mapA, mapB, limit, valueFn) {
  const keys = new Set([...mapA.keys(), ...mapB.keys()]);
  const val = (m, k) => valueFn ? valueFn(m, k) : (m.get(k) || 0);
  return [...keys]
    .sort((x, y) => Math.max(val(mapA, y), val(mapB, y)) - Math.max(val(mapA, x), val(mapB, x)))
    .slice(0, limit);
}

function emptyMsg() { return `<div class="hint">No data.</div>`; }
function fmt(n) { return Number(n).toLocaleString(); }
function fmtSigned(n) { const v = Number(n); return (v > 0 ? '+' : '') + v.toLocaleString(); }
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (ch) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}
