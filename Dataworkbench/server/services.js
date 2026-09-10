'use strict';

const crypto = require('node:crypto');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { appendJsonl, exists, loadUserDirectory, queryDlpEvents, readJson, writeJsonAtomic } = require('./dlp-store');
const { enrichDlpQueryWithSitTriage, getSitTriageForIncidents } = require('./sit-triage');

function safeId(value, max = 100) {
  const id = String(value || '').trim();
  if (!id || id.length > max || !/^[a-zA-Z0-9._-]+$/.test(id)) throw Object.assign(new Error('Invalid identifier.'), { statusCode: 400 });
  return id;
}

function runProcess(command, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd, windowsHide: true,
      env: { ...process.env, NO_COLOR: '1', TERM: 'dumb' },
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; }); child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', reject); child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

async function record(config, event) {
  await appendJsonl(path.join(config.dataDir, 'ledger', 'execution-ledger.jsonl'), {
    utc: new Date().toISOString(), ...event,
  });
}

async function queryDlpEventsWithTriage(config, body = {}) {
  return enrichDlpQueryWithSitTriage(config, await queryDlpEvents(config, body));
}

async function createPlan(config, body) {
  if (!Array.isArray(body?.sits) || !body.sits.length) return { ok: false, error: 'Select at least one sensitive information type.' };
  const query = await queryDlpEventsWithTriage(config, { ...body, sits: body.sits });
  if (!query.ok) return query;
  const planId = `${new Date().toISOString().replace(/[:.]/g, '-')}-${crypto.randomBytes(3).toString('hex')}`;
  const planDir = path.join(config.dataDir, 'plans');
  const detectionsFile = path.join(planDir, `${planId}-detections.json`);
  const plan = {
    ok: true, planId, generatedUtc: new Date().toISOString(),
    scope: { label: String(body.scopeLabel || 'Manual selection').slice(0, 160), kind: String(body.scopeKind || 'manual').slice(0, 40), sits: body.sits },
    totals: { eventsScanned: query.scannedEvents, detections: query.matchedCount, incidents: query.incidentIds.length, users: query.affectedUsers.length },
    incidentIds: query.incidentIds, users: query.affectedUsers.slice(0, 500), warnings: [],
  };
  if (!query.matchedCount) plan.warnings.push('No detections matched the selected scope.');
  if (query.truncated) plan.warnings.push('The event scan reached its configured cap. Narrow the query before applying.');
  if (query.incidentIds.length > config.maxIncidentsPerApply) plan.warnings.push(`Apply is capped to ${config.maxIncidentsPerApply} incidents.`);
  await writeJsonAtomic(detectionsFile, query.planDetections);
  await writeJsonAtomic(path.join(planDir, `${planId}-plan.json`), plan);
  await record(config, { type: 'plan-created', planId, scope: plan.scope, totals: plan.totals });
  return plan;
}

async function applyPlan(config, body) {
  const planId = safeId(body?.planId);
  if (!config.liveApplyEnabled) return { ok: false, error: 'Live apply is disabled. Set liveApplyEnabled only after validating dry runs.' };
  if (body?.confirmation !== config.liveConfirmationPhrase) return { ok: false, error: 'The live confirmation phrase does not match.' };
  const detections = path.join(config.dataDir, 'plans', `${planId}-detections.json`);
  const planFile = path.join(config.dataDir, 'plans', `${planId}-plan.json`);
  if (!(await exists(detections)) || !(await exists(planFile))) return { ok: false, error: 'Plan not found.' };
  const output = path.join(config.dataDir, 'results', `${planId}-apply.json`);
  const args = ['-NoProfile', '-File', path.join(config.rootDir, 'workers', 'Apply-BulkRemediation.ps1'),
    '-DetectionDataPath', detections, '-OutputPath', output,
    '-MaxIncidents', String(config.maxIncidentsPerApply), '-MaxUsers', String(config.maxUsersPerApply)];
  if (body?.actions?.emailUsers === true) args.push('-SendEmail');
  if (body?.actions?.teamsUsers === true) {
    const teamsMessage = String(body.actions.teamsMessage || '').trim();
    if (!teamsMessage || teamsMessage.length > 4000) return { ok: false, error: 'The Teams message must contain 1 to 4,000 characters.' };
    args.push('-SendTeams', '-TeamsMessage', teamsMessage);
  }
  if (body?.actions?.updateIncidents !== false) args.push('-UpdateIncidents');
  if (body?.actions?.resolveLowRisk === true) args.push('-ResolveLowRisk');
  await record(config, { type: 'apply-started', planId, actions: body.actions || {} });
  const run = await runProcess(config.powershellExecutable, args, config.rootDir);
  const result = await readJson(output, null);
  await record(config, { type: 'apply-finished', planId, exitCode: run.code, ok: run.code === 0 });
  return { ok: run.code === 0, planId, exitCode: run.code, result, stderr: run.code ? run.stderr.slice(-2000) : undefined };
}

async function collect(config, body = {}) {
  const captureSensitiveContent = body.captureSensitiveContent === true;
  if (captureSensitiveContent && !config.sitOptimize?.sensitiveContent?.enabled) return { ok: false, error: 'Protected sensitive-content capture is disabled in configuration.' };
  if (captureSensitiveContent && body.confirmation !== config.sitOptimize.sensitiveContent.captureConfirmationPhrase) return { ok: false, error: 'The protected-content capture confirmation phrase does not match.' };
  const args = ['-NoProfile', '-File', path.join(config.rootDir, 'workers', 'Collect-DlpAlerts.ps1'),
    '-MaxEvents', String(Math.min(150000, Math.max(1, Number(body.maxEvents) || 50000))),
    '-LookbackDays', String(Math.min(365, Math.max(1, Number(config.collectorLookbackDays) || 90)))];
  if (body.fullPull === true) args.push('-FullPull');
  if (captureSensitiveContent) args.push('-CaptureSensitiveEvents', '-SensitiveRetentionDays', String(config.sitOptimize.sensitiveContent.retentionDays));
  await record(config, { type: 'collection-started', fullPull: body.fullPull === true, protectedSensitiveCapture: captureSensitiveContent, sensitiveRetentionDays: captureSensitiveContent ? config.sitOptimize.sensitiveContent.retentionDays : undefined });
  const run = await runProcess(config.powershellExecutable, args, config.rootDir);
  const summary = await readJson(path.join(config.dataDir, 'dlp-sync-state.json'), null);
  await record(config, { type: 'collection-finished', exitCode: run.code, ok: run.code === 0, protectedSensitiveCapture: captureSensitiveContent, summary });
  return { ok: run.code === 0, exitCode: run.code, summary, output: run.stdout.split(/\r?\n/).filter(Boolean).slice(-30), error: run.code ? run.stderr.slice(-2000) : undefined };
}

async function enrichDepartments(config, body = {}) {
  const upns = Array.isArray(body.upns)
    ? [...new Set(body.upns.map((value) => String(value).trim().toLowerCase()).filter((value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)))].slice(0, Math.min(1000, Math.max(1, Number(config.maxDepartmentEnrichmentUsers) || 500)))
    : [];
  if (!upns.length) return { ok: false, error: 'No valid user principal names were supplied.' };
  const input = path.join(config.dataDir, 'results', `department-enrichment-${Date.now()}-${crypto.randomBytes(2).toString('hex')}.json`);
  const output = path.join(config.dataDir, 'user-directory.json');
  await writeJsonAtomic(input, upns);
  await record(config, { type: 'department-enrichment-started', requested: upns.length });
  let run;
  try {
    run = await runProcess(config.powershellExecutable, ['-NoProfile', '-File', path.join(config.rootDir, 'workers', 'Resolve-UserDepartments.ps1'), '-UpnsPath', input, '-OutputPath', output], config.rootDir);
  } finally {
    await fsp.unlink(input).catch(() => {});
  }
  const directory = await loadUserDirectory(config);
  const resolved = upns.filter((upn) => directory[upn]?.department).length;
  await record(config, { type: 'department-enrichment-finished', requested: upns.length, resolved, exitCode: run.code, ok: run.code === 0 });
  return {
    ok: run.code === 0,
    requested: upns.length,
    resolved,
    unresolved: upns.length - resolved,
    cacheEntries: Object.keys(directory).length,
    output: run.stdout.split(/\r?\n/).filter(Boolean).slice(-20),
    error: run.code ? run.stderr.slice(-2000) || 'Department enrichment failed.' : undefined,
  };
}

async function loadFlows(config) {
  const configured = path.join(config.rootDir, 'config', 'response-flows.json');
  const source = (await exists(configured)) ? configured : path.join(config.rootDir, 'config', 'response-flows.default.json');
  return readJson(source, { $schemaVersion: 1, flows: [] });
}

async function runFlow(config, body) {
  const flowId = safeId(body?.flowId, 64);
  const mode = body?.mode === 'apply' ? 'apply' : 'dryrun';
  if (mode === 'apply' && (!config.liveApplyEnabled || body?.confirmation !== config.liveConfirmationPhrase)) {
    return { ok: false, error: 'Live flow execution is disabled or not confirmed.' };
  }
  const incidentIds = Array.isArray(body?.incidentIds) ? body.incidentIds.map(String).filter((x) => /^[0-9a-zA-Z-]+$/.test(x)).slice(0, config.maxIncidentsPerApply) : [];
  const sitTriage = await getSitTriageForIncidents(config, incidentIds);
  const input = path.join(config.dataDir, 'results', `flow-${Date.now()}-${crypto.randomBytes(2).toString('hex')}-input.json`);
  const output = input.replace('-input.json', '-result.json');
  await writeJsonAtomic(input, { flowId, mode, incidentIds, parameters: body?.parameters || {}, sitTriage });
  const args = ['-NoProfile', '-File', path.join(config.rootDir, 'workers', 'Invoke-ResponseFlow.ps1'), '-InputPath', input, '-OutputPath', output];
  const run = await runProcess(config.powershellExecutable, args, config.rootDir);
  const result = await readJson(output, null);
  await record(config, { type: 'flow-run', flowId, mode, incidentCount: incidentIds.length, exitCode: run.code });
  return { ok: run.code === 0, exitCode: run.code, result, stderr: run.code ? run.stderr.slice(-2000) : undefined };
}

async function listJobs(config) {
  const dir = path.join(config.dataDir, 'jobs'); await fsp.mkdir(dir, { recursive: true });
  const files = (await fsp.readdir(dir)).filter((f) => f.endsWith('.json'));
  const jobs = (await Promise.all(files.map((f) => readJson(path.join(dir, f), null)))).filter(Boolean).sort((a, b) => String(b.createdUtc).localeCompare(String(a.createdUtc)));
  return { ok: true, jobs };
}

async function saveJob(config, body) {
  const id = `${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
  const job = { id, createdUtc: new Date().toISOString(), status: 'queued', name: String(body?.name || 'DLP response job').slice(0, 120), note: String(body?.note || '').slice(0, 500), incidentIds: Array.isArray(body?.incidentIds) ? body.incidentIds.slice(0, 500) : [], queue: Array.isArray(body?.queue) ? body.queue.slice(0, 50) : [], context: body?.context || {} };
  await writeJsonAtomic(path.join(config.dataDir, 'jobs', `${id}.json`), job); await record(config, { type: 'job-saved', jobId: id });
  return { ok: true, job };
}

async function deleteJob(config, body) {
  const id = safeId(body?.id, 80); const file = path.join(config.dataDir, 'jobs', `${id}.json`);
  try { await fsp.unlink(file); } catch { return { ok: false, error: 'Job not found.' }; }
  await record(config, { type: 'job-deleted', jobId: id }); return { ok: true };
}

function normalizeFlowDocument(input) {
  const source = input && Array.isArray(input.flows) ? input : { flows: [] };
  if (source.flows.length > 100) throw Object.assign(new Error('A maximum of 100 response flows is supported.'), { statusCode: 400 });
  const ids = new Set();
  const flows = source.flows.map((flow) => {
    const id = safeId(flow?.id, 64).toLowerCase();
    if (!/^[a-z0-9][a-z0-9-]*$/.test(id)) throw Object.assign(new Error(`Flow id "${id}" must use lowercase letters, numbers, and hyphens.`), { statusCode: 400 });
    if (ids.has(id)) throw Object.assign(new Error(`Duplicate flow id: ${id}`), { statusCode: 400 }); ids.add(id);
    const kind = ['notification', 'remediation', 'closure', 'investigation'].includes(flow?.kind) ? flow.kind : 'notification';
    const parameters = (Array.isArray(flow?.parameters) ? flow.parameters : []).slice(0, 30).map((parameter) => {
      const name = String(parameter?.name || '').trim();
      if (!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(name)) throw Object.assign(new Error(`Invalid parameter name in flow ${id}.`), { statusCode: 400 });
      return { name, label: String(parameter.label || name).slice(0, 100), type: ['string', 'text', 'number', 'boolean'].includes(parameter.type) ? parameter.type : 'string', required: parameter.required === true, default: String(parameter.default ?? '').slice(0, 4000), help: String(parameter.help || '').slice(0, 500) };
    });
    const actions = (Array.isArray(flow?.actions) ? flow.actions : []).slice(0, 20).map((action) => {
      if (action?.type === 'incidentPatch') return { type: 'incidentPatch', addTags: (Array.isArray(action.addTags) ? action.addTags : []).map(String).map((tag) => tag.slice(0, 100)).slice(0, 20), status: ['active', 'inProgress', 'resolved'].includes(action.status) ? action.status : '', includeSitTriageComment: action.includeSitTriageComment === true };
      if (action?.type === 'emailAffectedUsers') return { type: 'emailAffectedUsers' };
      if (action?.type === 'teamsNotifyAffectedUsers') return { type: 'teamsNotifyAffectedUsers' };
      throw Object.assign(new Error(`Unsupported declarative action type in flow ${id}.`), { statusCode: 400 });
    });
    const requiredScopes = [...new Set(actions.flatMap((action) => {
      if (action.type === 'incidentPatch') return ['SecurityIncident.ReadWrite.All'];
      if (action.type === 'emailAffectedUsers') return ['Mail.Send'];
      if (action.type === 'teamsNotifyAffectedUsers') return ['Chat.Create', 'ChatMessage.Send', 'User.ReadBasic.All'];
      return [];
    }))];
    return { id, name: String(flow?.name || id).slice(0, 120), description: String(flow?.description || '').slice(0, 1000), kind, enabled: flow?.enabled !== false, requiredScopes, parameters, actions };
  });
  return { $schemaVersion: 1, _doc: 'Declarative DLP response flows. Arbitrary scripts are intentionally unsupported.', flows };
}

async function captureFlowVersion(config, doc, source) {
  const dir = path.join(config.dataDir, 'flow-versions'); await fsp.mkdir(dir, { recursive: true });
  const id = `${new Date().toISOString().replace(/[:.]/g, '-')}-${crypto.randomBytes(3).toString('hex')}`;
  await writeJsonAtomic(path.join(dir, `${id}.json`), { id, capturedAtUtc: new Date().toISOString(), source: String(source || 'editor').slice(0, 60), flowCount: doc.flows.length, doc });
  return id;
}

async function saveFlows(config, body) {
  const doc = normalizeFlowDocument(body?.doc);
  const configured = path.join(config.rootDir, 'config', 'response-flows.json');
  const current = await loadFlows(config); await captureFlowVersion(config, current, body?.source || 'before-save');
  await writeJsonAtomic(configured, doc); await record(config, { type: 'flows-saved', flowCount: doc.flows.length });
  return { ok: true, doc };
}

async function importFlows(config, body) {
  const incoming = normalizeFlowDocument(body?.doc);
  const mode = body?.mode === 'replace' ? 'replace' : 'merge';
  let doc = incoming; let added = incoming.flows.length; let updated = 0;
  if (mode === 'merge') {
    const current = normalizeFlowDocument(await loadFlows(config)); const byId = new Map(current.flows.map((flow) => [flow.id, flow])); added = 0;
    for (const flow of incoming.flows) { if (byId.has(flow.id)) updated++; else added++; byId.set(flow.id, flow); }
    doc = normalizeFlowDocument({ flows: [...byId.values()] });
  }
  const saved = await saveFlows(config, { doc, source: `import-${mode}` });
  return { ...saved, imported: { mode, ids: incoming.flows.map((flow) => flow.id), added, updated } };
}

async function listFlowVersions(config) {
  const dir = path.join(config.dataDir, 'flow-versions'); await fsp.mkdir(dir, { recursive: true });
  const files = (await fsp.readdir(dir)).filter((file) => file.endsWith('.json')).sort().reverse().slice(0, 50);
  const versions = (await Promise.all(files.map((file) => readJson(path.join(dir, file), null)))).filter(Boolean).map(({ id, capturedAtUtc, source, flowCount }) => ({ id, capturedAtUtc, source, flowCount, kind: 'saved' }));
  return { ok: true, versions };
}

async function restoreFlowVersion(config, versionId) {
  const id = safeId(versionId, 100); const file = path.join(config.dataDir, 'flow-versions', `${id}.json`);
  const version = await readJson(file, null); if (!version?.doc) return { ok: false, error: 'Flow version not found.' };
  return saveFlows(config, { doc: version.doc, source: `restore-${id}` });
}

async function listFlowIncidents(config) {
  const query = await queryDlpEventsWithTriage(config, {}); if (!query.ok) return { ok: false, error: query.error, incidents: [] };
  const map = new Map();
  for (const row of query.rows) {
    if (!row.incidentId) continue;
    const id = String(row.incidentId);
    if (!map.has(id)) map.set(id, { id, displayName: row.policy || `DLP incident ${id}`, severity: row.severity || 'informational', status: row.status || 'unknown', affectedUsers: [], sitTriage: row.sitTriage || null });
    const incident = map.get(id);
    if (!incident.sitTriage && row.sitTriage) incident.sitTriage = row.sitTriage;
    if (row.user && !incident.affectedUsers.includes(row.user) && incident.affectedUsers.length < config.maxUsersPerApply) incident.affectedUsers.push(row.user);
  }
  return { ok: true, incidents: [...map.values()].slice(0, config.maxIncidentsPerApply) };
}

module.exports = { applyPlan, collect, createPlan, deleteJob, enrichDepartments, importFlows, listFlowIncidents, listFlowVersions, listJobs, loadFlows, normalizeFlowDocument, queryDlpEventsWithTriage, record, restoreFlowVersion, runFlow, saveFlows, saveJob };
