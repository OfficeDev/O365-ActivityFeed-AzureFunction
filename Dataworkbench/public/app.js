(() => {
  'use strict';
  const $ = (s) => document.querySelector(s);
  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const facetDefinitions = [
    ['workloads', 'Workload'], ['sits', 'Sensitive info type'], ['policies', 'DLP policy'],
    ['departments', 'Department'], ['users', 'User'], ['senders', 'Sender'],
  ];
  const state = {
    result: null, flows: [], live: false, currentPlan: null,
    selected: Object.fromEntries(facetDefinitions.map(([name]) => [name, new Set()])),
  };
  let toastTimer;

  function toast(message) { const el = $('#toast'); el.textContent = message; el.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove('show'), 2800); }
  async function request(url, options = {}) { const res = await fetch(url, options); const data = await res.json(); if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`); return data; }
  async function post(url, body) { return request(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }); }
  function filters() { return { dateFrom: $('#date-from').value || undefined, dateTo: $('#date-to').value ? `${$('#date-to').value}T23:59:59.999Z` : undefined, minConfidence: Number($('#confidence').value), ...Object.fromEntries(facetDefinitions.map(([name]) => [name, [...state.selected[name]]])) }; }

  async function health() { const data = await request('/api/health'); state.live = data.liveApplyEnabled; $('#mode-badge').textContent = state.live ? 'Graph writes enabled' : 'Graph writes locked'; $('#mode-badge').title = state.live ? 'Microsoft Graph writes are enabled and still require explicit confirmation.' : 'Synchronization, local saves, planning, and dry runs remain available. Microsoft Graph writes are locked.'; $('#mode-badge').className = `badge ${state.live ? 'live' : 'safe'}`; }
  async function runQuery() {
    $('#query').disabled = $('#filter-query').disabled = true;
    try { const data = await post('/api/dlp/query', filters()); if (!data.ok) throw new Error(data.error); state.result = data; renderResult(); }
    catch (error) { clearResult(error.message); }
    finally { $('#query').disabled = $('#filter-query').disabled = false; }
  }
  function showNotice(message) { const n = $('#notice'); n.textContent = message; n.classList.remove('hidden'); }
  function clearResult(message) {
    state.result = null;
    $('#stat-matched').textContent = '—'; $('#stat-total').textContent = 'No query results';
    $('#stat-users').textContent = '—'; $('#stat-incidents').textContent = '—'; $('#stat-events').textContent = '—';
    $('#plan').disabled = true; $('#save-job').disabled = true; $('#enrich-departments').disabled = true; $('#enrich-departments').textContent = 'Enrich departments';
    $('#rows').innerHTML = '<tr><td colspan="10" class="empty">No DLP alert events are available.</td></tr>';
    showNotice(message);
  }
  function triageDetail(triage) {
    if (!triage) return 'Run Detection Assurance to add AI triage.';
    const patterns = Array.isArray(triage.falsePositivePatterns) ? triage.falsePositivePatterns : [];
    return `<div class="triage-summary">${esc(triage.securityComment || '')}</div>${patterns.length ? `<details class="fp-patterns"><summary>${patterns.length} false-positive pattern${patterns.length === 1 ? '' : 's'}</summary>${patterns.map((pattern) => `<article class="fp-pattern"><header><strong>${esc(pattern.patternFamily)}</strong><span>${esc(pattern.confidence)} confidence${pattern.occurrenceCount ? ` · ${pattern.occurrenceCount} occurrence${pattern.occurrenceCount === 1 ? '' : 's'}` : ''}</span></header><div class="fp-context">${esc([pattern.triggeringSitRule, pattern.workload, pattern.location].filter(Boolean).join(' · '))}</div>${pattern.bindingBasis ? `<p><b>Binding:</b> ${pattern.bindingBasis === 'evidence-reference' ? 'Exact evidence reference' : pattern.bindingBasis === 'prior-same-scope-fallback' ? 'Prior assessment with identical period and incident lineage' : 'Conservative analysis-batch association'}</p>` : ''}<p><b>Why false positive:</b> ${esc(pattern.reasonFalsePositive)}</p>${pattern.supportingIndicators?.length ? `<p><b>Indicators:</b> ${pattern.supportingIndicators.map(esc).join(' · ')}</p>` : ''}<p><b>Purview change:</b> ${esc(pattern.suppressionStrategy)}</p><p><b>Retain detection when:</b> ${esc(pattern.falseNegativeGuardrail)}</p></article>`).join('')}</details>` : '<div class="fp-missing">No incident-specific or batch-associated false-positive pattern was returned. Use the assessment report before designing a Purview change.</div>'}`;
  }
  function renderResult() {
    const d = state.result; $('#notice').classList.add('hidden');
    $('#stat-matched').textContent = d.matchedCount.toLocaleString(); $('#stat-total').textContent = `of ${d.totalDetections.toLocaleString()} detections`;
    $('#stat-users').textContent = d.affectedUsers.length.toLocaleString(); $('#stat-incidents').textContent = d.incidentIds.length.toLocaleString(); $('#stat-events').textContent = d.scannedEvents.toLocaleString();
    $('#plan').disabled = d.matchedCount === 0; $('#save-job').disabled = d.matchedCount === 0;
    const enrich = $('#enrich-departments'); enrich.disabled = d.affectedUsers.length === 0; enrich.textContent = `Enrich departments (${d.affectedUsers.length})`;
    $('#rows').innerHTML = d.rows.length ? d.rows.map((r) => `<tr><td>${esc((r.observedUtc || '').slice(0, 10))}</td><td title="${esc(r.user)}">${esc(r.user || '—')}</td><td>${esc(r.department || '—')}</td><td title="${esc(r.sensitiveTypeName)}">${esc(r.sensitiveTypeName || '—')}</td><td>${esc(r.confidence ?? '—')}</td><td>${esc(r.workload || '—')}</td><td title="${esc(r.policy)}">${esc(r.policy || '—')}</td><td>${r.incidentId ? `<a href="${esc(r.incidentUrl)}" target="_blank" rel="noopener">${esc(r.incidentId)}</a>` : '—'}</td><td>${r.sitTriage ? `<span class="risk-pill risk-${esc(r.sitTriage.priority.toLowerCase())}">${esc(r.sitTriage.priority)}</span>` : 'Not triaged'}</td><td class="sit-comment">${triageDetail(r.sitTriage)}</td></tr>`).join('') : '<tr><td colspan="10" class="empty">No detections match this scope.</td></tr>';
    renderFacets(d.facets || {});
    if (d.truncated) showNotice('The JSONL scan reached its configured cap. Narrow the query before applying remediation.');
  }

  function renderFacets(facets) {
    $('#facets').innerHTML = facetDefinitions.map(([name, label], index) => {
      const values = facets[name] || []; const selected = state.selected[name];
      return `<details class="facet" ${index < 3 ? 'open' : ''} data-facet="${name}"><summary><span>${esc(label)}</span><small>${selected.size ? `${selected.size} selected` : values.length}</small></summary><div class="facet-options">${values.length > 6 ? `<input class="facet-search" data-search="${name}" placeholder="Filter ${esc(label.toLowerCase())}s…">` : ''}<div data-options="${name}">${facetOptions(name, values, '')}</div></div></details>`;
    }).join('');
    bindFacetOptions();
    document.querySelectorAll('[data-search]').forEach((input) => input.addEventListener('input', () => {
      const name = input.dataset.search; const holder = document.querySelector(`[data-options="${name}"]`);
      holder.innerHTML = facetOptions(name, state.result?.facets?.[name] || [], input.value); bindFacetOptions(holder);
    }));
  }
  function bindFacetOptions(root = document) {
    root.querySelectorAll('[data-facet-value]').forEach((input) => input.addEventListener('change', () => {
      const selected = state.selected[input.dataset.facetValue]; input.checked ? selected.add(input.value) : selected.delete(input.value);
      const details = input.closest('[data-facet]'); const summary = details?.querySelector('summary small');
      if (summary) summary.textContent = selected.size ? `${selected.size} selected` : (state.result?.facets?.[input.dataset.facetValue]?.length || 0);
    }));
  }
  function facetOptions(name, values, search) {
    const needle = String(search || '').toLowerCase(); const selected = state.selected[name];
    return values.filter((item) => !needle || String(item.value).toLowerCase().includes(needle)).map((item) => `<label class="facet-option"><input type="checkbox" data-facet-value="${name}" value="${esc(item.value)}" ${selected.has(item.value) ? 'checked' : ''}><span title="${esc(item.value)}">${esc(item.value)}</span><small>${item.count.toLocaleString()}</small></label>`).join('') || '<div class="empty">No values</div>';
  }

  async function enrichDepartments() {
    const users = state.result?.affectedUsers || [];
    if (!users.length) return toast('Run a query with affected users first.');
    const button = $('#enrich-departments'); button.disabled = true; button.textContent = 'Resolving through Graph…';
    showNotice(`Resolving departments for ${users.length.toLocaleString()} affected user(s). Complete Microsoft Graph authentication if prompted.`);
    try {
      const data = await post('/api/dlp/enrich-departments', { upns: users.map((user) => user.userId) });
      if (!data.ok) throw new Error(data.error || 'Department enrichment failed.');
      toast(`Resolved ${data.resolved} department${data.resolved === 1 ? '' : 's'}; ${data.unresolved} unresolved.`);
      await runQuery();
    } catch (error) {
      showNotice(error.message); toast(error.message);
    } finally {
      const count = state.result?.affectedUsers?.length || 0; button.disabled = count === 0; button.textContent = count ? `Enrich departments (${count})` : 'Enrich departments';
    }
  }

  function openDrawer() { $('#overlay').classList.remove('hidden'); $('#drawer').classList.add('open'); $('#drawer').setAttribute('aria-hidden', 'false'); }
  function closeDrawer() { $('#overlay').classList.add('hidden'); $('#drawer').classList.remove('open'); $('#drawer').setAttribute('aria-hidden', 'true'); }
  async function buildPlan() {
    const sits = filters().sits.length ? filters().sits : [...new Set((state.result?.rows || []).map((r) => r.sensitiveTypeName).filter(Boolean))];
    if (!sits.length) return toast('Select at least one sensitive information type.');
    openDrawer(); $('#drawer-body').innerHTML = '<div class="empty">Building a redacted remediation plan…</div>';
    try { const plan = await post('/api/remediation/plan', { ...filters(), sits, scopeLabel: 'Studio query', scopeKind: 'manual' }); if (!plan.ok) throw new Error(plan.error); state.currentPlan = plan; renderPlan(plan); }
    catch (error) { $('#drawer-body').innerHTML = `<div class="warn">${esc(error.message)}</div>`; }
  }
  function renderPlan(plan) {
    const t = plan.totals; $('#drawer-body').innerHTML = `<div class="plan-stats"><div class="plan-stat"><strong>${t.detections.toLocaleString()}</strong><span>DETECTIONS</span></div><div class="plan-stat"><strong>${t.users.toLocaleString()}</strong><span>USERS</span></div><div class="plan-stat"><strong>${t.incidents.toLocaleString()}</strong><span>INCIDENTS</span></div></div>
      <p class="plan-summary">Review the redacted scope, choose the actions to perform, and confirm live execution only after validating the intended recipients and outcomes.</p>
      <div class="section"><h3>Selected sensitive information types</h3><div class="chips">${plan.scope.sits.map((s) => `<span class="chip">${esc(s)}</span>`).join('')}</div></div>
      ${plan.warnings.length ? `<div class="section warn">${plan.warnings.map(esc).join('<br>')}</div>` : ''}
      <div class="section"><h3>Actions on apply</h3><p class="section-intro">Only selected actions run. Notifications use the affected users listed in this plan and never include detected values.</p><div class="action-list">
        <label class="action-option"><input id="action-incidents" type="checkbox" checked><span><strong>Tag and update incidents</strong><small>Add review tags, move matching incidents to in progress, and attach each available Detection Assurance security comment.</small></span></label>
        <label class="action-option"><input id="action-email" type="checkbox"><span><strong>Email affected users</strong><small>Send a standard privacy-safe review request from the signed-in operator.</small></span></label>
        <label class="action-option"><input id="action-teams" type="checkbox"><span><strong>Notify affected users in Microsoft Teams</strong><small>Create or reuse a one-to-one chat and send the reviewed message below.</small></span></label>
        <label class="action-option"><input id="action-resolve" type="checkbox"><span><strong>Resolve low-risk incidents</strong><small>Resolve only low-severity incidents as false positives. Incident updates must also be selected.</small></span></label>
      </div><label id="teams-message-field" class="action-message hidden"><span>Reviewed Teams message</span><textarea id="teams-message" rows="4" maxlength="4000">Please review the data protection activity associated with your account. Sensitive values are not included in this notification.</textarea><small>Do not enter detected values, credentials, document content, or other sensitive artifacts.</small></label></div>
      <div class="section"><h3>Affected users</h3><p class="section-intro">The first ${Math.min(8, plan.users.length)} of ${plan.users.length} scoped user${plan.users.length === 1 ? '' : 's'} ${plan.users.length === 1 ? 'is' : 'are'} shown. Live notification caps still apply.</p><div class="card-list">${plan.users.slice(0, 8).map((u) => `<div class="mini-card"><strong>${esc(u.userId)}</strong><div class="mini-meta"><span>${esc(u.department || 'Department unresolved')}</span><span>${u.detectionCount} detection${u.detectionCount === 1 ? '' : 's'}</span><span>${u.incidentCount} incident${u.incidentCount === 1 ? '' : 's'}</span></div></div>`).join('') || '<div class="empty">No affected users</div>'}</div></div>
      <div class="live-box"><strong>${state.live ? 'Live execution is enabled' : 'Live execution is locked'}</strong><p>Plan generation does not mutate Microsoft Graph. Live execution requires server enablement, the exact confirmation phrase, and a final browser confirmation.</p><input id="confirmation" placeholder="Type APPLY DLP REMEDIATION"><button id="apply" class="button danger full" ${state.live ? '' : 'disabled'}>Apply selected actions</button></div>`;
    const teamsToggle = $('#action-teams'); const incidentToggle = $('#action-incidents'); const resolveToggle = $('#action-resolve');
    teamsToggle?.addEventListener('change', () => $('#teams-message-field').classList.toggle('hidden', !teamsToggle.checked));
    incidentToggle?.addEventListener('change', () => { resolveToggle.disabled = !incidentToggle.checked; if (!incidentToggle.checked) resolveToggle.checked = false; });
    $('#apply')?.addEventListener('click', applyPlan);
  }
  async function applyPlan() {
    if (!state.currentPlan) return;
    if (!confirm('This will perform LIVE Microsoft Graph mutations. Continue?')) return;
    const button = $('#apply'); button.disabled = true; button.textContent = 'Applying…';
    try { const data = await post('/api/remediation/apply', { planId: state.currentPlan.planId, confirmation: $('#confirmation').value, actions: { updateIncidents: $('#action-incidents').checked, emailUsers: $('#action-email').checked, teamsUsers: $('#action-teams').checked, teamsMessage: $('#teams-message').value, resolveLowRisk: $('#action-resolve').checked } }); if (!data.ok) throw new Error(data.error || data.stderr || 'Apply failed'); toast('Remediation completed'); renderPlan(state.currentPlan); }
    catch (error) { toast(error.message); button.disabled = false; button.textContent = 'Apply live remediation'; }
  }

  async function collect() {
    if (!confirm('Start an interactive Microsoft Graph DLP synchronization?')) return;
    $('#collect').disabled = true; showNotice('DLP synchronization is running. Complete Microsoft Graph authentication if prompted.');
    try {
      const data = await post('/api/dlp/collect', {});
      if (!data.ok) throw new Error(data.error || data.output?.join('\n') || 'Collection failed');
      const alerts = Number(data.summary?.alertCount || 0); const events = Number(data.summary?.newEventCount || 0);
      if (!alerts) {
        const context = [data.summary?.account, data.summary?.tenantId].filter(Boolean).join(' / ');
        const candidates = Number(data.summary?.candidateAlertCount || 0);
        clearResult(`Synchronization completed, but Microsoft Graph returned ${candidates} DLP candidate alerts and no alerts in the configured 90-day window.${context ? ` Authenticated context: ${context}.` : ''} Verify the signed-in tenant and DLP alert permissions.`);
        return;
      }
      toast(`DLP synchronization completed: ${alerts} alerts, ${events} new events`); await runQuery();
    } catch (e) { clearResult(`DLP synchronization failed: ${e.message}`); }
    finally { $('#collect').disabled = false; }
  }
  async function loadFlows() { try { const data = await request('/api/flows'); state.flows = data.doc.flows || []; $('#flows').innerHTML = state.flows.map((f) => `<article class="mini-card"><strong>${esc(f.name)}</strong><p>${esc(f.description)}</p><div class="mini-meta"><span>${esc(f.kind)}</span><button class="link-button" data-flow="${esc(f.id)}">Dry run</button></div></article>`).join('') || '<div class="empty">No flows configured.</div>'; document.querySelectorAll('[data-flow]').forEach((b) => b.addEventListener('click', () => dryRunFlow(b.dataset.flow))); } catch (e) { $('#flows').innerHTML = `<div class="warn">${esc(e.message)}</div>`; } }
  async function dryRunFlow(flowId) { if (!state.result) return toast('Run a query first.'); try { const data = await post('/api/flows/run', { flowId, mode: 'dryrun', incidentIds: state.result.incidentIds, parameters: {} }); if (!data.ok) throw new Error(data.error || data.stderr || 'Dry run failed'); toast('Flow dry run completed'); } catch (e) { toast(e.message); } }
  async function loadJobs() { try { const data = await request('/api/jobs'); $('#jobs').innerHTML = data.jobs.map((j) => `<article class="mini-card"><strong>${esc(j.name)}</strong><p>${esc(j.note || j.context?.filterSummary || '')}</p><div class="mini-meta"><span>${esc(j.status)} · ${j.incidentIds.length} incidents</span><button class="link-button" data-delete-job="${esc(j.id)}">Delete</button></div></article>`).join('') || '<div class="empty">No saved jobs.</div>'; document.querySelectorAll('[data-delete-job]').forEach((b) => b.addEventListener('click', () => deleteJob(b.dataset.deleteJob))); } catch (e) { $('#jobs').innerHTML = `<div class="warn">${esc(e.message)}</div>`; } }
  async function saveJob() { if (!state.result) return; const name = prompt('Job name', `DLP response ${new Date().toISOString().slice(0, 10)}`); if (!name) return; const data = await post('/api/jobs', { name, incidentIds: state.result.incidentIds, context: { matchedCount: state.result.matchedCount, filterSummary: JSON.stringify(filters()) }, queue: [] }); if (data.ok) { toast('Job saved'); loadJobs(); } }
  async function deleteJob(id) { if (!confirm('Delete this saved job?')) return; await post('/api/jobs/delete', { id }); loadJobs(); }
  function clear() { ['date-from','date-to'].forEach((id) => { $(`#${id}`).value = ''; }); $('#confidence').value = 0; $('#confidence-value').value = 0; Object.values(state.selected).forEach((selected) => selected.clear()); renderFacets(state.result?.facets || {}); }

  $('#query').addEventListener('click', runQuery); $('#filter-query').addEventListener('click', runQuery); $('#collect').addEventListener('click', collect); $('#enrich-departments').addEventListener('click', enrichDepartments); $('#plan').addEventListener('click', buildPlan); $('#clear').addEventListener('click', clear); $('#close-drawer').addEventListener('click', closeDrawer); $('#overlay').addEventListener('click', closeDrawer); $('#save-job').addEventListener('click', saveJob); $('#refresh-jobs').addEventListener('click', loadJobs); $('#confidence').addEventListener('input', () => { $('#confidence-value').value = $('#confidence').value; });
  Promise.all([health(), loadFlows(), loadJobs()]).then(runQuery).catch((e) => showNotice(e.message));
})();
