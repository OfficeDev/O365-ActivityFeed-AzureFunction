'use strict';

const $ = (id) => document.getElementById(id);
let state = null;

function toast(message) {
  const element = $('toast'); element.textContent = message; element.classList.add('show');
  setTimeout(() => element.classList.remove('show'), 2400);
}

function setNotice(message, error = false) {
  const element = $('notice'); element.hidden = !message; element.textContent = message || ''; element.classList.toggle('error', error);
}

async function api(url, options = {}) {
  const response = await fetch(url, { ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
  const result = await response.json();
  if (!response.ok || result.ok === false) throw new Error(result.error || `Request failed (${response.status}).`);
  return result;
}

function overrideDescription(overrides) {
  const names = [];
  if (overrides.endpoint) names.push('endpoint');
  if (overrides.reportModel) names.push('reporting model');
  if (overrides.analysisModel) names.push('analysis model');
  return names;
}

function render(result, populateForm = true) {
  state = result;
  if (populateForm) {
    $('foundry-endpoint').value = result.saved.endpoint || '';
    $('report-model').value = result.saved.reportModel || '';
    $('analysis-model').value = result.saved.analysisModel || '';
  }
  $('effective-endpoint').textContent = result.effective?.endpoint || 'Not configured';
  $('effective-report-model').textContent = result.effective?.reportModel || 'Not configured';
  $('effective-analysis-model').textContent = result.effective?.analysisModel || 'Not configured';
  $('secret-status').textContent = result.secret.configured ? 'Configured' : 'Not configured';
  $('secret-status').className = result.secret.configured ? 'good' : 'bad';
  $('runtime-status').textContent = result.secret.configured ? 'Foundry configured' : 'Secret required';
  $('runtime-status').className = `badge ${result.secret.configured ? 'safe' : 'dirty'}`;
  $('save-state').textContent = result.restartRequired ? 'Restart required' : 'Active';
  $('save-state').className = `badge ${result.restartRequired ? 'dirty' : 'safe'}`;
  $('restart-note').hidden = !result.restartRequired;
  const names = overrideDescription(result.environmentOverrides || {});
  $('override-warning').hidden = names.length === 0;
  $('override-warning').textContent = names.length ? `Environment variables currently override the saved ${names.join(', ')}. Update those variables or remove the override before restarting if the saved values should become active.` : '';
}

async function load() {
  try { render(await api('/api/configuration/foundry')); setNotice(''); }
  catch (error) { setNotice(error.message, true); $('runtime-status').textContent = 'Unavailable'; }
}

$('foundry-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('save-foundry'); button.disabled = true; $('save-message').textContent = 'Saving non-secret settings…'; setNotice('');
  try {
    const result = await api('/api/configuration/foundry', { method: 'PUT', body: JSON.stringify({ endpoint: $('foundry-endpoint').value, reportModel: $('report-model').value, analysisModel: $('analysis-model').value }) });
    render({ ...result, effective: state.effective }, false);
    $('save-message').textContent = result.restartRequired ? 'Saved. Restart the server to apply.' : 'Saved. The running values are already active.';
    toast('Foundry configuration saved');
  } catch (error) { setNotice(error.message, true); $('save-message').textContent = ''; }
  finally { button.disabled = false; }
});

document.querySelectorAll('.copy-command').forEach((button) => button.addEventListener('click', async () => {
  const text = $(button.dataset.copy).textContent;
  try { await navigator.clipboard.writeText(text); toast('Command copied'); }
  catch { toast('Copy unavailable'); }
}));

load();
