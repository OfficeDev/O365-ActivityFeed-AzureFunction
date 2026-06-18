'use strict';

/* ============================================================================
   SIT Tuning - Profile Studio
   Talks to the local PowerShell server (studio-server.ps1) over same-origin
   /api endpoints. No API key is ever handled in the browser.
   ============================================================================ */

const $ = (id) => document.getElementById(id);

const REQUIRED_KEYS = [
  'noise_patterns',
  'validated_credentials',
  'credential_pairs',
  'low_frequency_patterns',
  'regex_refinements',
  'multi_encoded_artifacts',
  'workload_context',
  'exclusion_rules',
];

const state = {
  connected: false,
  profile: null, // last generated/edited fields
  profiles: [], // existing saved profiles
};

/* ---------- small helpers ---------- */
function setStatus(el, text, kind) {
  el.textContent = text || '';
  el.className = 'status-pill' + (kind ? ' ' + kind : '');
}

async function api(path, body) {
  const opts = body
    ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
    : { method: 'GET' };
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch { /* ignore */ }
  if (!res.ok) {
    const msg = (data && (data.error || data.message)) || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

function model() {
  return ($('model').value || 'gpt-5.4').trim();
}

function endpoint() {
  // Empty string => let the server use its configured default.
  return ($('endpoint').value || '').trim();
}

/* ---------- connection ---------- */
async function checkServer(silent) {
  try {
    const h = await api('/api/health');
    state.connected = true;
    $('offlineCallout').hidden = true;
    // Prefill the endpoint with the server default if the user hasn't typed one.
    if (h.endpoint && !$('endpoint').value) $('endpoint').value = h.endpoint;
    if (h.model && (!$('model').value || $('model').value === 'gpt-5.4')) $('model').value = h.model;
    if (h.keySet) {
      setStatus($('connStatus'), `Connected \u2014 ${h.model || 'model'} ready`, 'ok');
    } else {
      setStatus($('connStatus'), 'Server up, but AZURE_OPENAI_API_KEY is not set', 'warn');
    }
    return true;
  } catch (e) {
    state.connected = false;
    $('offlineCallout').hidden = false;
    if (!silent) setStatus($('connStatus'), 'No studio server on this origin', 'bad');
    return false;
  }
}

/* ---------- existing profiles ---------- */
async function loadProfileList() {
  const sel = $('existingSelect');
  try {
    const r = await api('/api/profiles');
    const profiles = (r && r.profiles) || [];
    state.profiles = profiles;
    sel.innerHTML = '';
    if (profiles.length === 0) {
      sel.innerHTML = '<option value="">(no profiles found)</option>';
      $('existingMeta').textContent = '';
      return;
    }
    for (const p of profiles) {
      const opt = document.createElement('option');
      opt.value = p.name;
      opt.textContent = p.name + (p.dlpPolicy ? `  \u2014  ${p.dlpPolicy}` : '');
      sel.appendChild(opt);
    }
    showExistingMeta();
  } catch (e) {
    sel.innerHTML = '<option value="">(server unavailable)</option>';
  }
}

function showExistingMeta() {
  const name = $('existingSelect').value;
  const p = (state.profiles || []).find((x) => x.name === name);
  $('existingMeta').textContent = p && p.description ? p.description : '';
}

async function runExisting() {
  const name = $('existingSelect').value;
  if (!name) {
    setStatus($('existingStatus'), 'Pick a profile first', 'bad');
    return;
  }
  const body = {
    name,
    dlpPolicy: $('exPolicy').value.trim() || undefined,
    tenantId: $('exTenant').value.trim() || undefined,
    daysBack: $('exDaysBack').value ? Number($('exDaysBack').value) : undefined,
    maxEvents: $('exMaxEvents').value ? Number($('exMaxEvents').value) : undefined,
    fullPull: $('exFullPull').checked,
    endpoint: endpoint() || undefined,
    model: model(),
  };
  $('runExistingBtn').disabled = true;
  setStatus($('existingStatus'), 'Launching credpattern.ps1\u2026', 'busy');
  try {
    const r = await api('/api/run', body);
    if (r.ok) {
      setStatus($('existingStatus'), `Launched ${name} in a new window`, 'ok');
    } else {
      setStatus($('existingStatus'), r.error || 'Failed to launch', 'bad');
    }
  } catch (e) {
    setStatus($('existingStatus'), e.message, 'bad');
  } finally {
    $('runExistingBtn').disabled = false;
  }
}

async function editExisting() {
  const name = $('existingSelect').value;
  if (!name) {
    setStatus($('existingStatus'), 'Pick a profile first', 'bad');
    return;
  }
  $('editExistingBtn').disabled = true;
  setStatus($('existingStatus'), 'Loading profile\u2026', 'busy');
  try {
    const r = await api('/api/profile?name=' + encodeURIComponent(name));
    if (!r.ok) {
      setStatus($('existingStatus'), r.error || 'Could not load profile', 'bad');
      return;
    }
    fillEditor({
      name: r.name || name,
      description: r.description || '',
      dlpPolicy: r.dlpPolicy || '',
      findingNoun: r.findingNoun || '',
      extractionInstruction: r.extractionInstruction || '',
      consolidationInstruction: r.consolidationInstruction || '',
      reportMergeInstruction: r.reportMergeInstruction || '',
    });
    setStatus($('existingStatus'), `Loaded ${name} into the builder below`, 'ok');
    $('editorPanel').hidden = false;
    $('testPanel').hidden = false;
    $('runPanel').hidden = false;
    $('editorPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (e) {
    setStatus($('existingStatus'), e.message, 'bad');
  } finally {
    $('editExistingBtn').disabled = false;
  }
}

/* ---------- key validation in the extraction prompt ---------- */
function validateKeys() {
  const text = $('outExtraction').value || '';
  const missing = REQUIRED_KEYS.filter((k) => !text.includes(`"${k}"`));
  const box = $('keyCheck');
  if (missing.length === 0) {
    box.className = 'key-check ok';
    box.textContent = '\u2713 All required JSON container keys present \u2014 compatible with the delta tool.';
  } else {
    box.className = 'key-check bad';
    box.textContent = '\u26a0 Missing required keys: ' + missing.join(', ') +
      '. The delta tool / report consolidation need these exact keys.';
  }
}

/* ---------- agent: draft profile ---------- */
async function generate() {
  const spec = {
    display: $('sitDisplay').value.trim(),
    name: $('sitName').value.trim(),
    dlpPolicy: $('dlpPolicy').value.trim(),
    findingNoun: $('findingNoun').value.trim(),
    detects: $('sitDetects').value.trim(),
    noise: $('sitNoise').value.trim(),
    validity: $('sitValidity').value.trim(),
    model: model(),
    endpoint: endpoint() || undefined,
  };
  // Minimum input: just name the SIT. Everything else is inferred by the agent.
  if (!spec.display && !spec.detects) {
    setStatus($('genStatus'), 'Name the sensitive information type first', 'bad');
    return;
  }
  if (spec.name && !/^[A-Za-z0-9_-]+$/.test(spec.name)) {
    setStatus($('genStatus'), 'Profile name must be alphanumeric (A-Z, 0-9, _, -)', 'bad');
    return;
  }

  $('generateBtn').disabled = true;
  $('regenBtn') && ($('regenBtn').disabled = true);
  setStatus($('genStatus'), 'Drafting profile with the agent\u2026', 'busy');
  try {
    const r = await api('/api/agent', spec);
    if (!r.ok) {
      setStatus($('genStatus'), r.error || 'Agent failed', 'bad');
      return;
    }
    fillEditor({
      name: r.name || spec.name,
      description: r.description || spec.display,
      dlpPolicy: r.dlpPolicy || spec.dlpPolicy,
      findingNoun: r.findingNoun || spec.findingNoun,
      extractionInstruction: r.extractionInstruction || '',
      consolidationInstruction: r.consolidationInstruction || '',
      reportMergeInstruction: r.reportMergeInstruction || '',
    });
    setStatus($('genStatus'), 'Draft ready \u2014 review and edit below', 'ok');
    $('editorPanel').hidden = false;
    $('testPanel').hidden = false;
    $('runPanel').hidden = false;
    $('editorPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (e) {
    setStatus($('genStatus'), e.message, 'bad');
  } finally {
    $('generateBtn').disabled = false;
    $('regenBtn') && ($('regenBtn').disabled = false);
  }
}

function fillEditor(p) {
  state.profile = p;
  $('outName').value = p.name;
  $('outDesc').value = p.description;
  $('outPolicy').value = p.dlpPolicy;
  $('outNoun').value = p.findingNoun;
  $('outExtraction').value = p.extractionInstruction;
  $('outConsolidation').value = p.consolidationInstruction;
  $('outMerge').value = p.reportMergeInstruction;
  validateKeys();
}

function collectEditor() {
  return {
    name: $('outName').value.trim(),
    description: $('outDesc').value.trim(),
    dlpPolicy: $('outPolicy').value.trim(),
    findingNoun: $('outNoun').value.trim(),
    extractionInstruction: $('outExtraction').value,
    consolidationInstruction: $('outConsolidation').value,
    reportMergeInstruction: $('outMerge').value,
  };
}

/* ---------- save to profiles/ ---------- */
async function saveProfile() {
  const p = collectEditor();
  if (!/^[A-Za-z0-9_-]+$/.test(p.name)) {
    setStatus($('exportStatus'), 'Name must be alphanumeric', 'bad');
    return;
  }
  $('saveBtn').disabled = true;
  setStatus($('exportStatus'), 'Saving\u2026', 'busy');
  try {
    const r = await api('/api/save', { ...p, model: model() });
    if (r.ok) {
      setStatus($('exportStatus'), `Saved ${r.file} \u2014 loads cleanly`, 'ok');
      showRunCmd(p.name);
    } else {
      setStatus($('exportStatus'), 'Saved but failed to load: ' + (r.loadError || 'unknown'), 'warn');
    }
  } catch (e) {
    setStatus($('exportStatus'), e.message, 'bad');
  } finally {
    $('saveBtn').disabled = false;
  }
}

/* ---------- download .psd1 (client-side, no server needed) ---------- */
function esc1(s) {
  return (s || '').replace(/^'@/gm, " '@");
}
function buildPsd1(p) {
  const name = p.name.replace(/'/g, "''");
  const desc = p.description.replace(/'/g, "''");
  const policy = p.dlpPolicy.replace(/'/g, "''");
  const noun = p.findingNoun.replace(/'/g, "''");
  return `@{
    # ---------------------------------------------------------------------
    # Analysis profile: ${name}
    # Generated by the SIT Tuning Profile Studio.
    # ---------------------------------------------------------------------
    # Keep the JSON container keys in ExtractionInstruction identical across
    # every profile (noise_patterns, validated_credentials, credential_pairs,
    # ...). The web delta tool and report consolidation rely on them.
    # Select this profile with:  .\\credpattern.ps1 -AnalysisProfile ${name}
    # ---------------------------------------------------------------------

    Name        = '${name}'
    Description = '${desc}'
    DlpPolicy   = '${policy}'
    FindingNoun = '${noun}'

    ExtractionInstruction = @'
${esc1(p.extractionInstruction)}
'@

    ConsolidationInstruction = @'
${esc1(p.consolidationInstruction)}
'@

    ReportMergeInstruction = @'
${esc1(p.reportMergeInstruction)}
'@
}
`;
}

async function downloadPsd1() {
  const p = collectEditor();
  if (!p.name) {
    setStatus($('exportStatus'), 'Name is required', 'bad');
    return;
  }
  const text = buildPsd1(p);

  // Preferred: let the user pick a local location with a Save dialog
  // (File System Access API) instead of auto-dumping to the Downloads folder.
  if (window.showSaveFilePicker) {
    try {
      const handle = await window.showSaveFilePicker({
        suggestedName: `${p.name}.psd1`,
        types: [{ description: 'PowerShell data file', accept: { 'text/plain': ['.psd1'] } }],
      });
      const writable = await handle.createWritable();
      await writable.write(text);
      await writable.close();
      setStatus($('exportStatus'), `Saved ${handle.name} to the location you chose`, 'ok');
      showRunCmd(p.name);
      return;
    } catch (e) {
      if (e && e.name === 'AbortError') {
        setStatus($('exportStatus'), 'Save cancelled', '');
        return;
      }
      // fall through to classic download on any other error
    }
  }

  // Fallback for browsers without the File System Access API
  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${p.name}.psd1`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  setStatus($('exportStatus'), `Downloaded ${p.name}.psd1`, 'ok');
  showRunCmd(p.name);
}

function runCmdText(name) {
  let cmd = `.\\credpattern.ps1 -AnalysisProfile ${name}`;
  const ep = endpoint();
  const m = model();
  if (ep) cmd += ` -OpenAIEndpoint '${ep.replace(/'/g, "''")}'`;
  if (m && m !== 'gpt-5.4') cmd += ` -Model '${m.replace(/'/g, "''")}'`;
  return cmd;
}

function showRunCmd(name) {
  const el = $('runCmd');
  el.textContent = runCmdText(name);
  el.hidden = false;
}

async function copyRunCmd() {
  const name = $('outName').value.trim();
  const cmd = runCmdText(name);
  try {
    await navigator.clipboard.writeText(cmd);
    setStatus($('exportStatus'), 'Run command copied', 'ok');
  } catch {
    showRunCmd(name);
  }
}

/* ---------- test the extraction prompt ---------- */
async function testRun() {
  const extraction = $('outExtraction').value;
  const sample = $('sampleText').value.trim();
  if (!sample) {
    setStatus($('testStatus'), 'Paste some sample detection text first', 'bad');
    return;
  }
  $('testRunBtn').disabled = true;
  setStatus($('testStatus'), 'Running extraction\u2026', 'busy');
  try {
    const r = await api('/api/test', { extraction, sample, model: model(), endpoint: endpoint() || undefined });
    $('testResult').hidden = false;
    if (r.parsedOk && r.parsed) {
      $('testJson').textContent = JSON.stringify(r.parsed, null, 2);
      renderTestSummary(r.parsed);
      setStatus($('testStatus'), 'Parsed valid JSON', 'ok');
    } else {
      $('testJson').textContent = r.raw || '(no output)';
      $('testSummary').innerHTML = '<p class="hint">Model output was not valid JSON. Tighten the "Return ONLY valid JSON" wording in the extraction prompt.</p>';
      setStatus($('testStatus'), 'Output was not valid JSON', 'warn');
    }
  } catch (e) {
    setStatus($('testStatus'), e.message, 'bad');
  } finally {
    $('testRunBtn').disabled = false;
  }
}

function renderTestSummary(j) {
  const noise = (j.noise_patterns || []).length;
  const validated = (j.validated_credentials || []).length;
  const pairs = (j.credential_pairs || []).length;
  const lowFreq = (j.low_frequency_patterns || []).length;
  const refine = (j.regex_refinements || []).length;
  const noiseOcc = (j.noise_patterns || []).reduce((s, n) => s + (Number(n.occurrence_count) || 0), 0);
  $('testSummary').innerHTML = `
    <ul class="summary-list">
      <li><strong>${noise}</strong> noise pattern(s) &mdash; ${noiseOcc} occurrence(s)</li>
      <li><strong>${validated}</strong> validated finding(s)</li>
      <li><strong>${pairs}</strong> linked finding pair(s)</li>
      <li><strong>${lowFreq}</strong> low-frequency pattern(s)</li>
      <li><strong>${refine}</strong> regex refinement(s)</li>
    </ul>`;
}

/* ---------- run the full pipeline ---------- */
async function runPipeline() {
  const p = collectEditor();
  const name = p.name;
  if (!name) {
    setStatus($('runStatus'), 'Name the profile first', 'bad');
    return;
  }
  if (!/^[A-Za-z0-9_-]+$/.test(name)) {
    setStatus($('runStatus'), 'Name must be alphanumeric (A-Z, 0-9, _, -)', 'bad');
    return;
  }

  $('runBtn').disabled = true;
  // Always (re)save the current profile into profiles/ first so the pipeline
  // can never be launched against a missing or stale .psd1.
  setStatus($('runStatus'), 'Saving profile to profiles/\u2026', 'busy');
  try {
    const saved = await api('/api/save', { ...p, model: model() });
    if (!saved.ok) {
      setStatus($('runStatus'), 'Profile saved but failed to load: ' + (saved.loadError || 'unknown'), 'bad');
      return;
    }
  } catch (e) {
    setStatus($('runStatus'), 'Could not save profile: ' + e.message, 'bad');
    $('runBtn').disabled = false;
    return;
  }

  const body = {
    name,
    dlpPolicy: $('runPolicy').value.trim() || undefined,
    tenantId: $('runTenant').value.trim() || undefined,
    daysBack: $('runDaysBack').value ? Number($('runDaysBack').value) : undefined,
    maxEvents: $('runMaxEvents').value ? Number($('runMaxEvents').value) : undefined,
    fullPull: $('runFullPull').checked,
    endpoint: endpoint() || undefined,
    model: model(),
  };
  setStatus($('runStatus'), 'Launching credpattern.ps1\u2026', 'busy');
  try {
    const r = await api('/api/run', body);
    if (r.ok) {
      setStatus($('runStatus'), `Saved profiles/${name}.psd1 and launched in a new window`, 'ok');
    } else {
      setStatus($('runStatus'), r.error || 'Failed to launch', 'bad');
    }
  } catch (e) {
    setStatus($('runStatus'), e.message, 'bad');
  } finally {
    $('runBtn').disabled = false;
  }
}

/* ---------- wire up ---------- */
function init() {
  $('testConnBtn').addEventListener('click', () => checkServer(false));
  $('generateBtn').addEventListener('click', generate);
  $('regenBtn').addEventListener('click', generate);
  $('saveBtn').addEventListener('click', saveProfile);
  $('exportBtn').addEventListener('click', downloadPsd1);
  $('copyCmdBtn').addEventListener('click', copyRunCmd);
  $('outExtraction').addEventListener('input', validateKeys);
  $('testRunBtn').addEventListener('click', testRun);
  $('runBtn').addEventListener('click', runPipeline);

  // Existing profiles
  $('refreshProfilesBtn').addEventListener('click', loadProfileList);
  $('existingSelect').addEventListener('change', showExistingMeta);
  $('runExistingBtn').addEventListener('click', runExisting);
  $('editExistingBtn').addEventListener('click', editExisting);

  // Default DLP policy suggestion from name
  $('sitName').addEventListener('input', () => {
    if (!$('dlpPolicy').value && $('sitName').value.trim()) {
      $('dlpPolicy').placeholder = `*${$('sitName').value.trim()}*`;
    }
  });

  checkServer(true);
  loadProfileList();
}

document.addEventListener('DOMContentLoaded', init);
