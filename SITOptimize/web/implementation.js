'use strict';

/* ============================================================================
   SIT Tuning - Implementation Guide
   Lists run snapshots (via /api/reports) and, on demand, asks the local PS
   server to turn a run's noise-reduction report into a Purview implementation
   plan (/api/implementation). The server renders the markdown to HTML and
   caches the plan per run; "Regenerate" forces a fresh generation.
   ============================================================================ */

const $ = (id) => document.getElementById(id);

const state = {
  reports: [],
  current: null, // { markdown, html, ... }
  cfg: { endpoint: '', model: '' },
};

function setStatus(text, kind) {
  const el = $('planStatus');
  el.textContent = text || '';
  el.className = 'status-pill' + (kind ? ' ' + kind : '');
}

async function api(path) {
  const res = await fetch(path);
  let data = null;
  try { data = await res.json(); } catch { /* ignore */ }
  if (!res.ok) {
    const msg = (data && (data.error || data.message)) || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString();
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

async function loadConfig() {
  try {
    const h = await api('/api/health');
    state.cfg.endpoint = h.endpoint || '';
    state.cfg.model = h.model || '';
  } catch { /* health is optional for listing */ }
}

async function loadRuns() {
  const sel = $('runSelect');
  try {
    const r = await api('/api/reports');
    // Only runs that actually have a report can produce a plan.
    const reports = ((r && r.reports) || []).filter((p) => p.hasReport);
    state.reports = reports;
    sel.innerHTML = '';
    if (reports.length === 0) {
      $('emptyState').hidden = false;
      sel.innerHTML = '<option value="">(no reports found)</option>';
      $('genBtn').disabled = true;
      $('regenBtn').disabled = true;
      return;
    }
    $('emptyState').hidden = true;
    $('genBtn').disabled = false;
    $('regenBtn').disabled = false;
    for (let i = 0; i < reports.length; i++) {
      const p = reports[i];
      const opt = document.createElement('option');
      opt.value = String(i);
      const when = fmtDate(p.generatedAt || p.mtime);
      opt.textContent = `${p.profile}  \u2014  ${when}`;
      sel.appendChild(opt);
    }
    sel.value = '0';
  } catch (e) {
    sel.innerHTML = '<option value="">(server unavailable)</option>';
    $('emptyState').hidden = true;
    $('genBtn').disabled = true;
    $('regenBtn').disabled = true;
    setStatus('No studio server on this origin', 'bad');
  }
}

function renderMeta(p, cached) {
  const bits = [];
  if (p.profile) bits.push(`<strong>${escapeHtml(p.profile)}</strong>`);
  if (p.dlpPolicy) bits.push(`policy <code>${escapeHtml(p.dlpPolicy)}</code>`);
  if (p.generatedAt) bits.push(`run ${fmtDate(p.generatedAt)}`);
  if (cached) bits.push('cached plan');
  $('planMeta').innerHTML = bits.join(' \u00b7 ');
}

async function generate(refresh) {
  const idx = Number($('runSelect').value);
  const meta = state.reports[idx];
  if (!meta) return;

  $('genBtn').disabled = true;
  $('regenBtn').disabled = true;
  setStatus(refresh ? 'Regenerating plan\u2026' : 'Generating plan\u2026', 'busy');
  $('copyMdBtn').disabled = true;
  $('exportBtn').disabled = true;

  const params = new URLSearchParams({ slug: meta.slug, file: meta.file });
  if (refresh) params.set('refresh', '1');
  if (state.cfg.endpoint) params.set('endpoint', state.cfg.endpoint);
  if (state.cfg.model) params.set('model', state.cfg.model);

  try {
    const r = await api(`/api/implementation?${params.toString()}`);
    if (!r.ok) {
      setStatus(r.error || 'Failed to generate plan', 'bad');
      return;
    }
    state.current = r;
    renderMeta(meta, r.cached);
    $('planBody').innerHTML = r.html || '<p class="hint">(empty plan)</p>';
    $('planPanel').hidden = false;
    $('copyMdBtn').disabled = !r.markdown;
    $('exportBtn').disabled = !r.html;
    setStatus(r.cached ? 'Loaded cached plan' : 'Plan ready', 'ok');
  } catch (e) {
    setStatus(e.message, 'bad');
  } finally {
    $('genBtn').disabled = false;
    $('regenBtn').disabled = false;
  }
}

async function copyMarkdown() {
  if (!state.current || !state.current.markdown) return;
  try {
    await navigator.clipboard.writeText(state.current.markdown);
    setStatus('Markdown copied', 'ok');
  } catch {
    setStatus('Copy failed', 'bad');
  }
}

function exportHtml() {
  if (!state.current || !state.current.html) return;
  const idx = Number($('runSelect').value);
  const meta = state.reports[idx] || {};
  const policy = state.current.dlpPolicy || meta.dlpPolicy || meta.profile || '';
  const heading = policy
    ? `Purview DLP Implementation Plan \u2014 ${policy}`
    : 'Purview DLP Implementation Plan';
  const metaBits = [];
  if (meta.profile) metaBits.push(`Profile: ${meta.profile}`);
  if (policy) metaBits.push(`DLP policy: ${policy}`);
  if (meta.generatedAt) metaBits.push(`Run: ${fmtDate(meta.generatedAt)}`);
  try {
    const name = window.exportStandaloneHtml({
      title: heading,
      heading,
      eyebrow: 'SIT Tuning Studio \u00b7 Implementation Guide',
      meta: metaBits,
      bodyHtml: state.current.html,
      fileBase: `impl-${meta.profile || policy || 'plan'}`,
    });
    setStatus(`Exported ${name}`, 'ok');
  } catch (e) {
    setStatus('Export failed', 'bad');
  }
}

async function init() {
  $('genBtn').addEventListener('click', () => generate(false));
  $('regenBtn').addEventListener('click', () => generate(true));
  $('copyMdBtn').addEventListener('click', copyMarkdown);
  $('exportBtn').addEventListener('click', exportHtml);
  await loadConfig();
  await loadRuns();
}

document.addEventListener('DOMContentLoaded', init);
