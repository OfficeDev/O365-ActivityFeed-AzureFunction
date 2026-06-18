'use strict';

/* ============================================================================
   SIT Tuning - Standalone HTML export
   Wraps a rendered report/plan (.report-body HTML) in a self-contained, light,
   print-friendly HTML document with inline styles, and triggers a download.
   Shared by the Report Viewer and the Implementation Guide so exported pages
   can be opened or printed by anyone, with no server or stylesheet needed.
   ============================================================================ */

(function () {
  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  // Minimal, self-contained light theme for the exported document. Kept inline
  // so the file renders identically on any machine with no external assets.
  const EXPORT_CSS = `
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font: 16px/1.6 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #1b1f24;
    background: #f6f8fa;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }
  .wrap { max-width: 960px; margin: 0 auto; padding: 40px 28px 80px; }
  .doc-header { border-bottom: 2px solid #d0d7de; padding-bottom: 18px; margin-bottom: 28px; }
  .doc-header .eyebrow {
    margin: 0 0 6px; font-size: 12px; letter-spacing: .12em; text-transform: uppercase;
    color: #6e7781; font-weight: 600;
  }
  .doc-header h1 { margin: 0 0 8px; font-size: 26px; line-height: 1.25; color: #0b1a33; }
  .doc-header .meta { margin: 0; font-size: 13px; color: #57606a; }
  .doc-header .meta code {
    background: #eaeef2; padding: 1px 6px; border-radius: 5px; font-size: 12px;
  }
  .report-body h1, .report-body h2, .report-body h3, .report-body h4 {
    color: #0b1a33; line-height: 1.3; margin: 1.6em 0 .5em;
  }
  .report-body h1 { font-size: 24px; border-bottom: 1px solid #d0d7de; padding-bottom: .3em; }
  .report-body h2 { font-size: 20px; border-bottom: 1px solid #e3e8ee; padding-bottom: .25em; }
  .report-body h3 { font-size: 17px; }
  .report-body h4 { font-size: 15px; }
  .report-body p, .report-body li { color: #24292f; }
  .report-body a { color: #0a58ca; }
  .report-body code {
    background: #eaeef2; color: #b5258b; padding: .12em .4em; border-radius: 5px;
    font: 13px/1.4 "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  }
  .report-body pre {
    background: #1b1f24; color: #e6edf3; padding: 14px 16px; border-radius: 8px;
    overflow: auto; font: 13px/1.5 "SFMono-Regular", Consolas, Menlo, monospace;
  }
  .report-body pre code { background: none; color: inherit; padding: 0; }
  .report-body table {
    border-collapse: collapse; width: 100%; margin: 1em 0; font-size: 14px;
  }
  .report-body th, .report-body td {
    border: 1px solid #d0d7de; padding: 8px 10px; text-align: left; vertical-align: top;
  }
  .report-body th { background: #eaeef2; font-weight: 600; color: #0b1a33; }
  .report-body tr:nth-child(even) td { background: #f3f5f8; }
  .report-body blockquote {
    margin: 1em 0; padding: .4em 1em; border-left: 4px solid #d0d7de; color: #57606a;
  }
  .report-body hr { border: none; border-top: 1px solid #d0d7de; margin: 2em 0; }
  .doc-footer {
    margin-top: 48px; padding-top: 16px; border-top: 1px solid #d0d7de;
    font-size: 12px; color: #8b949e;
  }
  @media print {
    body { background: #fff; }
    .wrap { padding: 0; max-width: none; }
    .report-body pre, .report-body table { page-break-inside: avoid; }
  }`;

  function buildDocument(opts) {
    const title = opts.title || 'SIT Tuning export';
    const eyebrow = opts.eyebrow || 'SIT Tuning Studio';
    const heading = opts.heading || title;
    const metaBits = (opts.meta || []).filter(Boolean).map(escapeHtml);
    const stamp = new Date().toLocaleString();
    const metaHtml = metaBits.length
      ? `<p class="meta">${metaBits.join(' &middot; ')}</p>` : '';
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>${escapeHtml(title)}</title>
<style>${EXPORT_CSS}</style>
${opts.extraCss ? `<style>${opts.extraCss}</style>` : ''}
</head>
<body>
<div class="wrap">
  <header class="doc-header">
    <p class="eyebrow">${escapeHtml(eyebrow)}</p>
    <h1>${escapeHtml(heading)}</h1>
    ${metaHtml}
  </header>
  <article class="report-body">
${opts.bodyHtml || '<p>(empty)</p>'}
  </article>
  <footer class="doc-footer">Exported from SIT Tuning Studio on ${escapeHtml(stamp)}.</footer>
</div>
</body>
</html>`;
  }

  function slugify(s) {
    return String(s || 'export')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 60) || 'export';
  }

  function stampForFile() {
    const d = new Date();
    const p = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
  }

  // Public API: build the standalone document and trigger a download.
  // opts = { title, heading, eyebrow, meta:[...], bodyHtml, fileBase }
  function exportStandaloneHtml(opts) {
    const html = buildDocument(opts || {});
    const base = slugify(opts && (opts.fileBase || opts.heading || opts.title));
    const filename = `${base}-${stampForFile()}.html`;
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    return filename;
  }

  window.exportStandaloneHtml = exportStandaloneHtml;
})();
