'use strict';

/* ============================================================================
   SIT Tuning - Report Viewer
   Lists report snapshots from the per-profile cache (via the local PS server)
   and renders the server-converted HTML. No markdown library in the browser.
   ============================================================================ */

const $ = (id) => document.getElementById(id);

const state = {
  reports: [],
  current: null, // { markdown, html, ... }
};

function setStatus(text, kind) {
  const el = $('viewerStatus');
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

async function loadReports() {
  const sel = $('reportSelect');
  try {
    const r = await api('/api/reports');
    const reports = (r && r.reports) || [];
    state.reports = reports;
    sel.innerHTML = '';
    if (reports.length === 0) {
      $('emptyState').hidden = false;
      $('reportPanel').hidden = true;
      sel.innerHTML = '<option value="">(no reports found)</option>';
      $('reportMeta').textContent = '';
      $('copyMdBtn').disabled = true;
      $('exportBtn').disabled = true;
      return;
    }
    $('emptyState').hidden = true;
    for (let i = 0; i < reports.length; i++) {
      const p = reports[i];
      const opt = document.createElement('option');
      opt.value = String(i);
      const when = fmtDate(p.generatedAt || p.mtime);
      opt.textContent = `${p.profile}  \u2014  ${when}` + (p.hasReport ? '' : '  (no report)');
      sel.appendChild(opt);
    }
    sel.value = '0';
    await showSelected();
  } catch (e) {
    sel.innerHTML = '<option value="">(server unavailable)</option>';
    $('emptyState').hidden = true;
    setStatus('No studio server on this origin', 'bad');
  }
}

function renderMeta(p) {
  const bits = [];
  if (p.profile) bits.push(`<strong>${escapeHtml(p.profile)}</strong>`);
  if (p.dlpPolicy) bits.push(`policy <code>${escapeHtml(p.dlpPolicy)}</code>`);
  if (p.generatedAt) bits.push(fmtDate(p.generatedAt));
  if (p.rawDetectionCount != null) bits.push(`${p.rawDetectionCount} detections`);
  if (p.chunkCount != null) bits.push(`${p.chunkCount} chunks`);
  $('reportMeta').innerHTML = bits.join(' \u00b7 ');
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

async function showSelected() {
  const idx = Number($('reportSelect').value);
  const meta = state.reports[idx];
  if (!meta) return;
  renderMeta(meta);
  if (!meta.hasReport) {
    $('reportPanel').hidden = true;
    $('copyMdBtn').disabled = true;
    $('exportBtn').disabled = true;
    setStatus('This run has no saved report', 'warn');
    return;
  }
  setStatus('Loading report\u2026', 'busy');
  try {
    const r = await api(`/api/report?slug=${encodeURIComponent(meta.slug)}&file=${encodeURIComponent(meta.file)}`);
    if (!r.ok) {
      setStatus(r.error || 'Failed to load report', 'bad');
      return;
    }
    state.current = r;
    $('reportBody').innerHTML = r.html || '<p class="hint">(empty report)</p>';
    $('reportPanel').hidden = false;
    $('copyMdBtn').disabled = !r.markdown;
    $('exportBtn').disabled = !r.html;
    setStatus('', '');
  } catch (e) {
    setStatus(e.message, 'bad');
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
  const idx = Number($('reportSelect').value);
  const meta = state.reports[idx] || {};
  const policy = state.current.dlpPolicy || meta.dlpPolicy || '';
  const heading = meta.profile
    ? `SIT Noise-Reduction Report \u2014 ${meta.profile}`
    : 'SIT Noise-Reduction Report';
  const metaBits = [];
  if (meta.profile) metaBits.push(`Profile: ${meta.profile}`);
  if (policy) metaBits.push(`DLP policy: ${policy}`);
  if (meta.generatedAt) metaBits.push(`Generated: ${fmtDate(meta.generatedAt)}`);
  if (meta.rawDetectionCount != null) metaBits.push(`${meta.rawDetectionCount} detections`);
  try {
    const name = window.exportStandaloneHtml({
      title: heading,
      heading,
      eyebrow: 'SIT Tuning Studio \u00b7 Report',
      meta: metaBits,
      bodyHtml: state.current.html,
      fileBase: `report-${meta.profile || 'sit'}`,
    });
    setStatus(`Exported ${name}`, 'ok');
  } catch (e) {
    setStatus('Export failed', 'bad');
  }
}

function init() {
  $('reportSelect').addEventListener('change', showSelected);
  $('refreshBtn').addEventListener('click', loadReports);
  $('copyMdBtn').addEventListener('click', copyMarkdown);
  $('exportBtn').addEventListener('click', exportHtml);
  loadReports();
}

document.addEventListener('DOMContentLoaded', init);
