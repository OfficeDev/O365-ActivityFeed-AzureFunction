(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  const esc = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
  const facetDefinitions = [
    ['workloads', 'Workloads'], ['sits', 'Sensitive information types'], ['policies', 'DLP policies'],
    ['departments', 'Departments'], ['users', 'Users'], ['senders', 'Senders'],
  ];
  const state = {
    live: false, result: null, flows: [], queue: [], jobs: [],
    selected: Object.fromEntries(facetDefinitions.map(([name]) => [name, new Set()])),
  };
  let toastTimer;

  function toast(message) {
    const element = $('#toast'); element.textContent = message; element.classList.add('show');
    clearTimeout(toastTimer); toastTimer = setTimeout(() => element.classList.remove('show'), 3000);
  }
  async function request(url, options = {}) {
    const response = await fetch(url, options); const data = await response.json();
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`); return data;
  }
  const post = (url, body) => request(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  function filterBody() {
    return {
      dateFrom: $('#date-from').value || undefined,
      dateTo: $('#date-to').value ? `${$('#date-to').value}T23:59:59.999Z` : undefined,
      minConfidence: Number($('#confidence').value),
      ...Object.fromEntries(facetDefinitions.map(([name]) => [name, [...state.selected[name]]])),
    };
  }
  function setNotice(message, ok = false) { const element = $('#notice'); element.textContent = message; element.classList.toggle('ok', ok); }

  async function loadHealth() {
    const data = await request('/api/health'); state.live = data.liveApplyEnabled === true;
    $('#mode').textContent = state.live ? 'Graph writes enabled' : 'Graph writes locked'; $('#mode').title = state.live ? 'Microsoft Graph writes are enabled and still require explicit confirmation.' : 'Queries, local queue changes, saves, and dry runs remain available. Microsoft Graph writes are locked.'; $('#mode').className = `badge ${state.live ? 'live' : 'safe'}`;
    updateButtons();
  }
  async function runQuery() {
    const button = $('#run-query'); button.disabled = true; setNotice('Querying the redacted JSONL evidence store…');
    try {
      const data = await post('/api/dlp/query', filterBody());
      if (!data.ok) throw new Error(data.error || 'Query failed.');
      state.result = data; renderResults(); renderFacets(data.facets || {}); updateButtons();
      setNotice(`${data.matchedCount.toLocaleString()} detections matched the current bulk-response scope.`, true);
    } catch (error) {
      state.result = null; clearResults(); setNotice(error.message); updateButtons();
    } finally { button.disabled = false; }
  }
  function clearResults() {
    ['#stat-detections', '#stat-users', '#stat-incidents', '#stat-events'].forEach((id) => { $(id).textContent = '—'; });
    $('#stat-total').textContent = 'No query'; $('#result-meta').textContent = '';
    $('#detection-rows').innerHTML = '<tr><td colspan="7" class="empty">No DLP event data available.</td></tr>';
    $('#user-rows').innerHTML = '<tr><td colspan="5" class="empty">No affected users.</td></tr>';
    $('#enrich-departments').disabled = true; $('#enrich-departments').textContent = 'Enrich departments';
  }
  function renderResults() {
    const result = state.result;
    $('#stat-detections').textContent = result.matchedCount.toLocaleString(); $('#stat-total').textContent = `of ${result.totalDetections.toLocaleString()}`;
    $('#stat-users').textContent = result.affectedUsers.length.toLocaleString(); $('#stat-incidents').textContent = result.incidentIds.length.toLocaleString();
    $('#stat-events').textContent = result.scannedEvents.toLocaleString(); $('#result-meta').textContent = result.truncated ? 'Scan cap reached' : `${result.rows.length.toLocaleString()} rows shown`;
    $('#detection-rows').innerHTML = result.rows.length ? result.rows.map((row) => `<tr><td>${esc((row.observedUtc || '').slice(0, 10))}</td><td>${esc(row.user || '—')}</td><td>${esc(row.sensitiveTypeName || '—')}</td><td>${esc(row.confidence ?? '—')}</td><td>${esc(row.workload || '—')}</td><td title="${esc(row.policy)}">${esc(row.policy || '—')}</td><td>${row.incidentId ? `<a href="${esc(row.incidentUrl)}" target="_blank" rel="noopener">${esc(row.incidentId)}</a>` : '—'}</td></tr>`).join('') : '<tr><td colspan="7" class="empty">No detections match this scope.</td></tr>';
    $('#user-rows').innerHTML = result.affectedUsers.length ? result.affectedUsers.map((user) => `<tr><td>${esc(user.userId)}</td><td>${esc(user.department || '—')}</td><td>${user.detectionCount.toLocaleString()}</td><td>${user.incidentCount.toLocaleString()}</td><td title="${esc(user.sensitiveTypes.join(', '))}">${esc(user.sensitiveTypes.join(', ') || '—')}</td></tr>`).join('') : '<tr><td colspan="5" class="empty">No affected users.</td></tr>';
    const enrich = $('#enrich-departments'); enrich.disabled = !result.affectedUsers.length; enrich.textContent = `Enrich departments (${result.affectedUsers.length})`;
  }

  function renderFacets(facets) {
    $('#facets').innerHTML = facetDefinitions.map(([name, label], index) => {
      const values = facets[name] || []; const selected = state.selected[name];
      return `<details class="facet" ${index < 2 ? 'open' : ''} data-facet="${name}"><summary><span>${esc(label)}</span><small>${selected.size ? `${selected.size} selected` : values.length}</small></summary><div class="facet-options">${values.length > 8 ? `<input class="facet-search" data-search="${name}" placeholder="Search ${esc(label.toLowerCase())}">` : ''}<div data-options="${name}">${facetOptions(name, values, '')}</div></div></details>`;
    }).join('');
    document.querySelectorAll('[data-facet-value]').forEach((input) => input.addEventListener('change', () => {
      const set = state.selected[input.dataset.facetValue]; input.checked ? set.add(input.value) : set.delete(input.value); renderFacets(state.result?.facets || {});
    }));
    document.querySelectorAll('[data-search]').forEach((input) => input.addEventListener('input', () => {
      const name = input.dataset.search; const holder = document.querySelector(`[data-options="${name}"]`);
      holder.innerHTML = facetOptions(name, state.result?.facets?.[name] || [], input.value);
      holder.querySelectorAll('[data-facet-value]').forEach((option) => option.addEventListener('change', () => { const set = state.selected[name]; option.checked ? set.add(option.value) : set.delete(option.value); }));
    }));
  }
  function facetOptions(name, values, search) {
    const needle = search.toLowerCase(); const selected = state.selected[name];
    return values.filter((item) => !needle || String(item.value).toLowerCase().includes(needle)).map((item) => `<label class="facet-option"><input type="checkbox" data-facet-value="${name}" value="${esc(item.value)}" ${selected.has(item.value) ? 'checked' : ''}><span title="${esc(item.value)}">${esc(item.value)}</span><small>${item.count.toLocaleString()}</small></label>`).join('') || '<div class="empty">No values</div>';
  }
  function clearFilters() {
    $('#date-from').value = ''; $('#date-to').value = ''; $('#confidence').value = 0; $('#confidence-value').value = 0;
    Object.values(state.selected).forEach((set) => set.clear()); renderFacets(state.result?.facets || {});
  }

  async function enrichDepartments() {
    const users = state.result?.affectedUsers || [];
    if (!users.length) return toast('Run a query with affected users first.');
    const button = $('#enrich-departments'); button.disabled = true; button.textContent = 'Resolving through Graph…';
    setNotice(`Resolving departments for ${users.length.toLocaleString()} matched user(s) through Microsoft Graph…`);
    try {
      const data = await post('/api/dlp/enrich-departments', { upns: users.map((user) => user.userId) });
      if (!data.ok) throw new Error(data.error || 'Department enrichment failed.');
      toast(`Resolved ${data.resolved} department${data.resolved === 1 ? '' : 's'}; ${data.unresolved} unresolved.`);
      await runQuery();
    } catch (error) {
      setNotice(error.message); toast(error.message);
    } finally {
      button.disabled = !(state.result?.affectedUsers?.length); button.textContent = state.result?.affectedUsers?.length ? `Enrich departments (${state.result.affectedUsers.length})` : 'Enrich departments';
    }
  }

  async function loadFlows() {
    const data = await request('/api/flows'); state.flows = (data.doc?.flows || []).filter((flow) => flow.enabled !== false);
    $('#flow-library').innerHTML = state.flows.map((flow) => `<article class="flow-card"><div class="flow-head"><div><strong>${esc(flow.name)}</strong><span class="kind">${esc(flow.kind)}</span></div><button class="button" data-add-flow="${esc(flow.id)}">Add</button></div><p>${esc(flow.description)}</p><small class="muted">${esc((flow.requiredScopes || []).join(', ') || 'No live scopes')}</small></article>`).join('') || '<div class="empty">No response flows configured.</div>';
    document.querySelectorAll('[data-add-flow]').forEach((button) => button.addEventListener('click', () => addFlow(button.dataset.addFlow)));
  }
  function addFlow(flowId) {
    const flow = state.flows.find((item) => item.id === flowId); if (!flow) return;
    state.queue.push({ id: `${Date.now()}-${Math.random().toString(16).slice(2)}`, flowId, parameters: Object.fromEntries((flow.parameters || []).map((parameter) => [parameter.name, parameter.default || ''])), status: '', detail: '' });
    renderQueue();
  }
  function renderQueue() {
    $('#queue').innerHTML = state.queue.length ? state.queue.map((entry, index) => {
      const flow = state.flows.find((item) => item.id === entry.flowId); if (!flow) return '';
      const fields = (flow.parameters || []).map((parameter) => {
        const attributes = `data-queue-param="${esc(entry.id)}" data-param="${esc(parameter.name)}" ${parameter.required ? 'required' : ''}`;
        const control = parameter.type === 'text' ? `<textarea ${attributes} rows="3">${esc(entry.parameters[parameter.name] || '')}</textarea>` : `<input ${attributes} value="${esc(entry.parameters[parameter.name] || '')}">`;
        return `<label>${esc(parameter.label || parameter.name)}${control}${parameter.help ? `<small class="muted">${esc(parameter.help)}</small>` : ''}</label>`;
      }).join('');
      return `<article class="queue-item"><div class="queue-head"><div><strong>${index + 1}. ${esc(flow.name)}</strong><span class="kind">${esc(flow.kind)}</span></div><button class="remove" data-remove-flow="${esc(entry.id)}" aria-label="Remove">×</button></div>${fields}${entry.detail ? `<div class="result ${entry.status}">${esc(entry.detail)}</div>` : ''}</article>`;
    }).join('') : '<div class="empty">Add response flows from the library.</div>';
    document.querySelectorAll('[data-remove-flow]').forEach((button) => button.addEventListener('click', () => { state.queue = state.queue.filter((entry) => entry.id !== button.dataset.removeFlow); renderQueue(); }));
    document.querySelectorAll('[data-queue-param]').forEach((input) => input.addEventListener('input', () => { const entry = state.queue.find((item) => item.id === input.dataset.queueParam); if (entry) entry.parameters[input.dataset.param] = input.value; }));
    updateButtons();
  }
  function updateButtons() {
    const ready = Boolean(state.result?.matchedCount && state.queue.length);
    $('#dry-run').disabled = !ready; $('#save-job').disabled = !ready; $('#apply-live').disabled = !ready || !state.live;
  }
  async function executeQueue(mode) {
    if (!state.result || !state.queue.length) return;
    const confirmation = $('#confirmation').value;
    if (mode === 'apply') {
      if (!state.live) return toast('Live apply is disabled.');
      if (confirmation !== 'APPLY DLP REMEDIATION') return toast('Enter the exact live confirmation phrase.');
      if (!confirm(`Release ${state.queue.length} response flow(s) against ${state.result.incidentIds.length} incidents and ${state.result.affectedUsers.length} users?`)) return;
    }
    $('#dry-run').disabled = true; $('#apply-live').disabled = true;
    let succeeded = 0;
    for (const entry of state.queue) {
      const parameters = { ...entry.parameters, impactedUsers: state.result.affectedUsers.map((user) => user.userId).join(',') };
      entry.status = ''; entry.detail = `${mode === 'apply' ? 'Applying' : 'Dry-running'}…`; renderQueue();
      try {
        const data = await post('/api/flows/run', { flowId: entry.flowId, mode, confirmation, incidentIds: state.result.incidentIds, parameters });
        if (!data.ok) throw new Error(data.error || data.stderr || 'Flow failed.');
        const actions = data.result?.actions || []; entry.status = 'ok'; entry.detail = `${mode === 'apply' ? 'Applied' : 'Dry run complete'} · ${actions.length} action(s)`; succeeded++;
      } catch (error) { entry.status = 'bad'; entry.detail = error.message; }
      renderQueue();
    }
    toast(`${mode === 'apply' ? 'Release' : 'Dry run'} finished: ${succeeded}/${state.queue.length} flows succeeded`); updateButtons();
  }

  async function saveJob() {
    const name = prompt('Saved job name', `Bulk DLP response ${new Date().toISOString().slice(0, 10)}`); if (!name) return;
    const data = await post('/api/jobs', { name, incidentIds: state.result.incidentIds, queue: state.queue.map(({ flowId, parameters }) => ({ flowId, parameters })), context: { source: 'bulk-response-studio', matchedCount: state.result.matchedCount, filters: filterBody() } });
    if (!data.ok) return toast(data.error || 'Unable to save job.'); toast('Bulk response job saved'); await loadJobs();
  }
  async function loadJobs() {
    const data = await request('/api/jobs'); state.jobs = data.jobs || [];
    $('#jobs').innerHTML = state.jobs.length ? state.jobs.map((job) => `<article class="job-card"><div class="job-head"><div><strong>${esc(job.name)}</strong><span class="status">${esc(job.status)}</span></div><small class="muted">${esc((job.createdUtc || '').slice(0, 16).replace('T', ' '))}</small></div><p>${job.incidentIds.length} incidents · ${(job.queue || []).length} queued flows</p><div class="job-actions"><button class="button" data-load-job="${esc(job.id)}">Load queue</button><button class="button danger" data-delete-job="${esc(job.id)}">Delete</button></div></article>`).join('') : '<div class="empty">No saved jobs.</div>';
    document.querySelectorAll('[data-load-job]').forEach((button) => button.addEventListener('click', () => loadJob(button.dataset.loadJob)));
    document.querySelectorAll('[data-delete-job]').forEach((button) => button.addEventListener('click', () => deleteJob(button.dataset.deleteJob)));
  }
  function loadJob(id) {
    const job = state.jobs.find((item) => item.id === id); if (!job) return;
    state.queue = (job.queue || []).filter((saved) => state.flows.some((flow) => flow.id === saved.flowId)).map((saved) => ({ id: `${Date.now()}-${Math.random().toString(16).slice(2)}`, flowId: saved.flowId, parameters: { ...(saved.parameters || {}) }, status: '', detail: '' }));
    renderQueue(); toast(`Loaded ${state.queue.length} queued flow(s)`);
  }
  async function deleteJob(id) { if (!confirm('Delete this saved bulk-response job?')) return; await post('/api/jobs/delete', { id }); await loadJobs(); }

  $('#run-query').addEventListener('click', runQuery); $('#apply-filters').addEventListener('click', runQuery); $('#clear').addEventListener('click', clearFilters);
  $('#enrich-departments').addEventListener('click', enrichDepartments);
  $('#confidence').addEventListener('input', () => { $('#confidence-value').value = $('#confidence').value; });
  $('#clear-queue').addEventListener('click', () => { state.queue = []; renderQueue(); }); $('#dry-run').addEventListener('click', () => executeQueue('dryrun'));
  $('#apply-live').addEventListener('click', () => executeQueue('apply')); $('#save-job').addEventListener('click', saveJob); $('#refresh-jobs').addEventListener('click', loadJobs);
  Promise.all([loadHealth(), loadFlows(), loadJobs()]).then(runQuery).catch((error) => setNotice(error.message));
})();
