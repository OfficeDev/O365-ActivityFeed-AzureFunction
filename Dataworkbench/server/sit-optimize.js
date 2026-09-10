'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const readline = require('node:readline');
const { spawn } = require('node:child_process');
const { exists, loadAlertIndex, loadUserDirectory, readJson, resolveAlertOwner, writeJsonAtomic } = require('./dlp-store');
const { extractJson, extractResponseText } = require('./ai-helper');

function badRequest(message) {
  throw Object.assign(new Error(message), { statusCode: 400 });
}

function safeName(value, label = 'identifier') {
  const name = String(value || '').trim();
  if (!name || name.length > 100 || !/^[A-Za-z0-9_-]+$/.test(name)) badRequest(`Invalid ${label}.`);
  return name;
}

function sitRoot(config) {
  const configured = config.sitOptimize?.root || './sit-optimize';
  return path.resolve(config.rootDir, configured);
}

function valueFromPsd1(text, key) {
  const match = String(text).match(new RegExp(`^\\s*${key}\\s*=\\s*'((?:''|[^'])*)'`, 'mi'));
  return match ? match[1].replace(/''/g, "'") : '';
}

function hereStringFromPsd1(text, key) {
  const match = String(text).match(new RegExp(`^\\s*${key}\\s*=\\s*@'\\r?\\n([\\s\\S]*?)^\\s*'@\\s*$`, 'mi'));
  return match ? match[1].trim() : '';
}

function arrayFromPsd1(text, key) {
  const match = String(text).match(new RegExp(`^\\s*${key}\\s*=\\s*@\\(([\\s\\S]*?)\\)`, 'mi'));
  if (!match) return [];
  return [...match[1].matchAll(/'((?:''|[^'])*)'/g)]
    .map((item) => item[1].replace(/''/g, "'").trim())
    .filter(Boolean);
}

function sitScopeFromPsd1(text) {
  return {
    ids: arrayFromPsd1(text, 'SensitiveInformationTypeIds'),
    names: arrayFromPsd1(text, 'SensitiveInformationTypeNames'),
  };
}

function hasSitScope(scope) {
  return scope.ids.length > 0 || scope.names.length > 0;
}

function sensitiveIdentity(sensitive) {
  return {
    id: String(sensitive?.SensitiveType || sensitive?.SensitiveInformationTypeId || '').trim(),
    name: String(sensitive?.SensitiveInformationTypeName || '').trim(),
  };
}

function sensitiveMatchesScope(sensitive, scope) {
  const identity = sensitiveIdentity(sensitive);
  const ids = new Set(scope.ids.map((value) => value.toLowerCase()));
  const names = new Set(scope.names.map((value) => value.toLowerCase()));
  return (identity.id && ids.has(identity.id.toLowerCase())) || (identity.name && names.has(identity.name.toLowerCase()));
}

function psd1Escape(value) {
  return String(value || '').replace(/'/g, "''");
}

function psd1Array(values) {
  const unique = [...new Set(values.map((value) => String(value || '').trim()).filter(Boolean))];
  return `@(${unique.map((value) => `'${psd1Escape(value)}'`).join(', ')})`;
}

function replacePsd1Scalar(text, key, value) {
  const pattern = new RegExp(`^(\\s*${key}\\s*=\\s*)'((?:''|[^'])*)'`, 'mi');
  if (!pattern.test(text)) badRequest(`Profile is missing required field ${key}.`);
  return text.replace(pattern, (match, prefix) => `${prefix}'${psd1Escape(value)}'`);
}

function replacePsd1SitScope(text, ids, names) {
  const block = [
    '    # Exact SIT scope. Analysis fails closed when both allow-lists are empty.',
    `    SensitiveInformationTypeIds   = ${psd1Array(ids)}`,
    `    SensitiveInformationTypeNames = ${psd1Array(names)}`,
  ].join('\n');
  const existing = /(?:^\s*# Exact SIT scope\.[^\r\n]*\r?\n)?^\s*SensitiveInformationTypeIds\s*=\s*@\([^\r\n]*\)\r?\n^\s*SensitiveInformationTypeNames\s*=\s*@\([^\r\n]*\)/mi;
  if (existing.test(text)) return text.replace(existing, () => block);
  const findingNoun = /^(\s*FindingNoun\s*=\s*'((?:''|[^'])*)'\s*)$/mi;
  if (!findingNoun.test(text)) badRequest('Profile is missing required field FindingNoun.');
  return text.replace(findingNoun, (match) => `${match}\n\n${block}`);
}

function replacePsd1HereString(text, key, value) {
  const instruction = String(value || '').trim();
  if (!instruction || instruction.length > 100000) badRequest(`Invalid ${key}.`);
  if (/^\s*'@\s*$/m.test(instruction)) badRequest(`${key} contains an unsafe PSD1 here-string terminator.`);
  const pattern = new RegExp(`(^\\s*${key}\\s*=\\s*@'\\r?\\n)[\\s\\S]*?(^\\s*'@\\s*$)`, 'mi');
  if (!pattern.test(text)) badRequest(`Profile is missing required field ${key}.`);
  return text.replace(pattern, (match, prefix) => `${prefix}${instruction}${prefix.includes('\r\n') ? '\r\n' : '\n'}'@`);
}

function replacePsd1AnalysisFocus(text, value) {
  const focus = String(value || '').trim();
  if (focus.length > 12000 || /^\s*'@\s*$/m.test(focus)) badRequest('Analysis focus is invalid or contains an unsafe PSD1 here-string terminator.');
  const pattern = /(^\s*AnalysisFocus\s*=\s*@'\r?\n)[\s\S]*?(^\s*'@\s*$)/mi;
  if (pattern.test(text)) return text.replace(pattern, (match, prefix) => `${prefix}${focus}${prefix.includes('\r\n') ? '\r\n' : '\n'}'@`);
  const findingNoun = /^(\s*FindingNoun\s*=\s*'((?:''|[^'])*)'\s*)$/mi;
  if (!findingNoun.test(text)) badRequest('Profile is missing required field FindingNoun.');
  return text.replace(findingNoun, (match) => `${match}\n\n    # Operator-reviewed priorities supplied to every analysis run.\n    AnalysisFocus = @'\n${focus}\n'@`);
}

function profileFromPsd1(text, fallback, file) {
  const scope = sitScopeFromPsd1(text);
  return {
    id: fallback,
    name: valueFromPsd1(text, 'Name') || fallback,
    description: valueFromPsd1(text, 'Description'),
    dlpPolicy: valueFromPsd1(text, 'DlpPolicy') || '*',
    findingNoun: valueFromPsd1(text, 'FindingNoun') || 'finding',
    analysisFocus: hereStringFromPsd1(text, 'AnalysisFocus'),
    sitIds: scope.ids,
    sitNames: scope.names,
    hasSitScope: hasSitScope(scope),
    file,
  };
}

async function loadProfiles(config) {
  const root = sitRoot(config);
  const profileDir = path.join(root, 'profiles');
  if (!(await exists(profileDir))) return { ok: false, rootAvailable: false, error: `Detection Assurance profiles were not found under ${profileDir}.`, profiles: [] };
  const files = (await fsp.readdir(profileDir)).filter((file) => /^[A-Za-z0-9_-]+\.psd1$/i.test(file)).sort();
  const profiles = [];
  for (const file of files) {
    const text = await fsp.readFile(path.join(profileDir, file), 'utf8');
    const fallback = path.basename(file, '.psd1');
    profiles.push(profileFromPsd1(text, fallback, file));
  }
  return { ok: true, rootAvailable: true, profiles };
}

async function loadProfile(config, profileId) {
  const id = safeName(profileId, 'profile');
  const file = path.join(sitRoot(config), 'profiles', `${id}.psd1`);
  if (!(await exists(file))) badRequest('Detection Assurance profile not found.');
  const text = await fsp.readFile(file, 'utf8');
  return { ok: true, profile: profileFromPsd1(text, id, path.basename(file)) };
}

async function saveProfile(config, input = {}) {
  const id = safeName(input.id, 'profile');
  const sourceId = safeName(input.sourceId || id, 'source profile');
  const profileDir = path.join(sitRoot(config), 'profiles');
  const source = path.join(profileDir, `${sourceId}.psd1`);
  if (!(await exists(source))) badRequest('Source Detection Assurance profile not found.');
  const requestedIds = Array.isArray(input.sitIds) ? input.sitIds.map(String) : [];
  const requestedNames = Array.isArray(input.sitNames) ? input.sitNames.map(String) : [];
  if (!requestedIds.length && !requestedNames.length) badRequest('Select at least one Sensitive Information Type.');

  const catalog = await buildSitCatalog(config);
  const selected = catalog.sensitiveInformationTypes.filter((item) =>
    requestedIds.some((value) => value.toLowerCase() === item.id.toLowerCase())
    || requestedNames.some((value) => value.toLowerCase() === item.name.toLowerCase()));
  if (!selected.length) badRequest('None of the selected Sensitive Information Types exist in the synchronized catalog.');
  const recognized = new Set(selected.flatMap((item) => [item.id.toLowerCase(), item.name.toLowerCase()]));
  const unknown = [...requestedIds, ...requestedNames].filter((value) => !recognized.has(value.toLowerCase()));
  if (unknown.length) badRequest(`Unknown Sensitive Information Type selection: ${unknown.join(', ')}`);

  let text = await fsp.readFile(source, 'utf8');
  text = replacePsd1Scalar(text, 'Name', id);
  text = replacePsd1Scalar(text, 'Description', String(input.description || '').trim());
  text = replacePsd1Scalar(text, 'DlpPolicy', String(input.dlpPolicy || '').trim());
  text = replacePsd1Scalar(text, 'FindingNoun', String(input.findingNoun || '').trim());
  text = replacePsd1AnalysisFocus(text, input.analysisFocus);
  text = replacePsd1SitScope(text, selected.map((item) => item.id), selected.map((item) => item.name));
  if (input.instructions && typeof input.instructions === 'object') {
    text = replacePsd1HereString(text, 'ExtractionInstruction', input.instructions.extractionInstruction);
    text = replacePsd1HereString(text, 'ConsolidationInstruction', input.instructions.consolidationInstruction);
    text = replacePsd1HereString(text, 'ReportMergeInstruction', input.instructions.reportMergeInstruction);
  }

  const target = path.join(profileDir, `${id}.psd1`);
  const temporary = `${target}.${process.pid}.${crypto.randomBytes(3).toString('hex')}.tmp`;
  await fsp.writeFile(temporary, text, { encoding: 'utf8', flag: 'wx' });
  try {
    await fsp.copyFile(temporary, target);
  } finally {
    await fsp.rm(temporary, { force: true });
  }
  return loadProfile(config, id);
}

function forEachSensitiveInformation(audit, visit) {
  for (const policy of (Array.isArray(audit?.PolicyDetails) ? audit.PolicyDetails : [])) {
    for (const rule of (Array.isArray(policy?.Rules) ? policy.Rules : [])) {
      for (const sensitive of (Array.isArray(rule?.ConditionsMatched?.SensitiveInformation) ? rule.ConditionsMatched.SensitiveInformation : [])) {
        visit(sensitive, { policy, rule });
      }
    }
  }
}

function countDetections(audit, sitScope = null) {
  let detections = 0; let redactedValues = 0; let rawValues = 0;
  forEachSensitiveInformation(audit, (sensitive) => {
    if (sitScope && !sensitiveMatchesScope(sensitive, sitScope)) return;
    if (!sensitive?.SensitiveInformationDetections) return;
    detections++;
    const detected = sensitive.SensitiveInformationDetections.DetectedValues;
    for (const item of (Array.isArray(detected) ? detected : detected == null ? [] : [detected])) {
      const value = typeof item === 'object' && item !== null ? item.value : item;
      if (value === '[REDACTED]') redactedValues++;
      else if (value != null && String(value).trim()) rawValues++;
    }
  });
  return { detections, redactedValues, rawValues };
}

async function buildSitCatalog(config) {
  const eventFile = path.join(config.dataDir, 'dlp-events-store.jsonl');
  const catalog = new Map();
  if (await exists(eventFile)) {
    const lines = readline.createInterface({ input: fs.createReadStream(eventFile, 'utf8'), crlfDelay: Infinity });
    for await (const line of lines) {
      let event; try { event = JSON.parse(line); } catch { continue; }
      let audit = event?.auditRecord;
      if (typeof audit === 'string') { try { audit = JSON.parse(audit); } catch { audit = null; } }
      forEachSensitiveInformation(audit, (sensitive, context) => {
        const identity = sensitiveIdentity(sensitive);
        if (!identity.id && !identity.name) return;
        const key = (identity.id || identity.name).toLowerCase();
        const item = catalog.get(key) || { ...identity, detections: 0, policies: new Set(), workloads: new Set() };
        item.detections++;
        const policyName = String(context.policy?.PolicyName || '').trim();
        const workload = String(audit?.Workload || '').trim();
        if (policyName) item.policies.add(policyName);
        if (workload) item.workloads.add(workload);
        catalog.set(key, item);
      });
    }
  }
  const sensitiveInformationTypes = [...catalog.values()]
    .map((item) => ({ id: item.id, name: item.name, detections: item.detections, policies: [...item.policies].sort(), workloads: [...item.workloads].sort() }))
    .sort((a, b) => b.detections - a.detections || a.name.localeCompare(b.name));
  return { ok: true, source: 'DLP Response Studio shared redacted JSONL', sensitiveInformationTypes };
}

async function summarizeSharedStore(config) {
  const eventFile = path.join(config.dataDir, 'dlp-events-store.jsonl');
  const alertFile = path.join(config.dataDir, 'dlp-alerts-store.jsonl');
  const sync = await readJson(path.join(config.dataDir, 'dlp-sync-state.json'), null);
  let events = 0; let alerts = 0; let detections = 0; let redactedValues = 0; let rawValues = 0;
  const protectedFile = path.join(config.dataDir, 'protected', 'sit-sensitive-events.jsonl');
  const userDirectory = await loadUserDirectory(config);
  const resolvedProfiles = Object.values(userDirectory).filter((profile) => profile.department);
  const departments = [...new Set(resolvedProfiles.map((profile) => profile.department))].sort();
  let protectedEvents = 0; let protectedUpdatedUtc = null;
  if (await exists(protectedFile)) {
    const protectedLines = readline.createInterface({ input: fs.createReadStream(protectedFile, 'utf8'), crlfDelay: Infinity });
    for await (const line of protectedLines) { if (line.trim()) protectedEvents++; }
    protectedUpdatedUtc = (await fsp.stat(protectedFile)).mtime.toISOString();
  }
  if (await exists(alertFile)) {
    const lines = readline.createInterface({ input: fs.createReadStream(alertFile, 'utf8'), crlfDelay: Infinity });
    for await (const line of lines) { if (line.trim()) alerts++; }
  }
  if (await exists(eventFile)) {
    const lines = readline.createInterface({ input: fs.createReadStream(eventFile, 'utf8'), crlfDelay: Infinity });
    for await (const line of lines) {
      if (!line.trim()) continue;
      let event; try { event = JSON.parse(line); } catch { continue; }
      events++;
      let audit = event?.auditRecord;
      if (typeof audit === 'string') { try { audit = JSON.parse(audit); } catch { audit = null; } }
      const counts = countDetections(audit); detections += counts.detections; redactedValues += counts.redactedValues; rawValues += counts.rawValues;
    }
  }
  return {
    ok: Boolean(events), alerts, events, detections, redactedValues, rawValues,
    privacyMode: rawValues > 0 ? 'sensitive-values-present' : 'context-only',
    source: 'DLP Response Studio shared JSONL',
    lastSyncUtc: sync?.updatedUtc || sync?.lastAlertWatermark || null,
    message: events ? (protectedEvents ? 'The general store is redacted. A separate DPAPI-protected evidence store is available for explicitly confirmed sensitive-content assessment.' : 'Detected values are redacted and no protected Detection Assurance evidence has been captured yet.') : 'Run Sync DLP alerts before starting a Detection Assurance assessment.',
    protectedEvidence: {
      enabled: config.sitOptimize?.sensitiveContent?.enabled === true,
      ready: protectedEvents > 0,
      eventCount: protectedEvents,
      protection: 'DPAPI-CurrentUser',
      retentionDays: Number(config.sitOptimize?.sensitiveContent?.retentionDays) || 30,
      updatedUtc: protectedUpdatedUtc,
      captureConfirmationPhrase: config.sitOptimize?.sensitiveContent?.captureConfirmationPhrase || 'CAPTURE SENSITIVE DLP CONTENT',
      analysisConfirmationPhrase: config.sitOptimize?.sensitiveContent?.analysisConfirmationPhrase || 'ANALYZE SENSITIVE DLP CONTENT',
    },
    directoryEnrichment: { cacheEntries: Object.keys(userDirectory).length, resolvedUsers: resolvedProfiles.length, departmentCount: departments.length, departments },
  };
}

function wildcardRegex(pattern) {
  const escaped = String(pattern || '*').replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i');
}

function analysisPeriod(startValue, endValue) {
  const startDate = String(startValue || '').trim(); const endDate = String(endValue || '').trim();
  if (!startDate && !endDate) return { startDate: '', endDate: '', startUtc: null, endExclusiveUtc: null, durationDays: null, label: 'All synchronized evidence' };
  if (!startDate || !endDate) badRequest('Select both a start date and an end date, or leave both blank.');
  const parse = (value, label) => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) badRequest(`Invalid ${label}. Use YYYY-MM-DD.`);
    const date = new Date(`${value}T00:00:00.000Z`);
    if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 10) !== value) badRequest(`Invalid ${label}.`);
    return date;
  };
  const start = parse(startDate, 'analysis start date'); const end = parse(endDate, 'analysis end date');
  if (end < start) badRequest('The analysis end date must be on or after the start date.');
  const endExclusive = new Date(end.getTime() + 86400000);
  return { startDate, endDate, startUtc: start.toISOString(), endExclusiveUtc: endExclusive.toISOString(), durationDays: Math.round((end.getTime() - start.getTime()) / 86400000) + 1, label: `${startDate} through ${endDate}` };
}

function eventInPeriod(event, period) {
  if (!period.startUtc) return true;
  const observed = new Date(String(event?.createdDateTime || event?.startDateTime || ''));
  return Number.isFinite(observed.getTime()) && observed >= new Date(period.startUtc) && observed < new Date(period.endExclusiveUtc);
}

async function scopeProfile(config, profileId, startDate = '', endDate = '') {
  const id = safeName(profileId, 'profile'); const available = await loadProfiles(config); const profile = available.profiles.find((item) => item.id.toLowerCase() === id.toLowerCase());
  if (!profile) badRequest('Detection Assurance profile not found.');
  if (!profile.hasSitScope) badRequest(`Profile ${profile.id} has no explicit SensitiveInformationTypeIds or SensitiveInformationTypeNames allow-list.`);
  const sitScope = { ids: profile.sitIds, names: profile.sitNames }; const period = analysisPeriod(startDate, endDate);
  const matchingAlertIds = new Set(); let alerts = 0; let events = 0; let detections = 0; let detectionsWithDepartment = 0; const policy = wildcardRegex(profile.dlpPolicy);
  const userDirectory = await loadUserDirectory(config); const resolvedUsers = new Set(); const departments = new Set();
  const alertFile = path.join(config.dataDir, 'dlp-alerts-store.jsonl'); const eventFile = path.join(config.dataDir, 'dlp-events-store.jsonl');
  const alertIndex = await loadAlertIndex(alertFile);
  if (await exists(alertFile)) {
    const lines = readline.createInterface({ input: fs.createReadStream(alertFile, 'utf8'), crlfDelay: Infinity });
    for await (const line of lines) { let alert; try { alert = JSON.parse(line); } catch { continue; } const title = alert?.additionalData?.AlertPolicyTitle || alert?.additionalData?.alertPolicytitle || ''; if (!policy.test(String(title))) continue; alerts++; if (alert?.id) matchingAlertIds.add(String(alert.id)); }
  }
  const observedAlertIds = new Set();
  if (matchingAlertIds.size && await exists(eventFile)) {
    const lines = readline.createInterface({ input: fs.createReadStream(eventFile, 'utf8'), crlfDelay: Infinity });
    for await (const line of lines) {
      let event; try { event = JSON.parse(line); } catch { continue; }
      const owner = resolveAlertOwner(event, alertIndex);
      if (!owner?.alertId || !matchingAlertIds.has(String(owner.alertId))) continue;
      if (!eventInPeriod(event, period)) continue;
      let audit = event?.auditRecord;
      if (typeof audit === 'string') { try { audit = JSON.parse(audit); } catch { audit = null; } }
      const scoped = countDetections(audit, sitScope);
      if (!scoped.detections) continue;
      const userKey = String(audit?.UserId || '').trim().toLowerCase(); const department = userKey ? userDirectory[userKey]?.department : null;
      if (department) { resolvedUsers.add(userKey); departments.add(department); detectionsWithDepartment += scoped.detections; }
      observedAlertIds.add(String(owner.alertId));
      events++;
      detections += scoped.detections;
    }
  }
  if (period.startDate) alerts = observedAlertIds.size;
  return { ok: true, profileId: profile.id, dlpPolicy: profile.dlpPolicy, sitIds: profile.sitIds, sitNames: profile.sitNames, alerts, events, detections, canAnalyze: events > 0, departmentContext: { resolvedUsers: resolvedUsers.size, departmentCount: departments.size, departments: [...departments].sort(), detectionsWithDepartment, unresolvedDetections: Math.max(0, detections - detectionsWithDepartment) }, analysisPeriod: { startDate: period.startDate, endDate: period.endDate, durationDays: period.durationDays, label: period.label } };
}

function profileOutputDir(config, profileId) {
  return path.join(config.dataDir, 'sit-optimize', safeName(profileId, 'profile'));
}

function safeRunFile(file) {
  const runFile = String(file || '');
  if (!/^run-[0-9_]+\.json$/.test(runFile)) badRequest('Invalid run file.');
  return runFile;
}

async function loadRunDocument(config, profileId, file) {
  const profile = safeName(profileId, 'profile');
  const runFile = safeRunFile(file);
  const doc = await readJson(path.join(profileOutputDir(config, profile), 'runs', runFile), null);
  if (!doc) badRequest('Detection Assurance run not found.');
  return { profile, runFile, doc };
}

async function listRuns(config, profileId) {
  const profiles = profileId ? [safeName(profileId, 'profile')] : (await loadProfiles(config)).profiles.map((profile) => profile.id);
  const runs = [];
  for (const profile of profiles) {
    const dir = path.join(profileOutputDir(config, profile), 'runs');
    if (!(await exists(dir))) continue;
    const files = (await fsp.readdir(dir)).filter((file) => /^run-[0-9_]+\.json$/.test(file)).sort().reverse().slice(0, 50);
    for (const file of files) {
      const doc = await readJson(path.join(dir, file), null); if (!doc) continue;
      runs.push({ profileId: profile, file, label: doc.label || '', generatedAt: doc.generatedAt || '', profile: doc.profile || profile, dlpPolicy: doc.dlpPolicy || '', analysisModel: doc.analysisModel || '', reportModel: doc.reportModel || '', privacyMode: doc.privacyMode || 'context-only', rawDetectionCount: Number(doc.rawDetectionCount) || 0, eventStoreCount: Number(doc.eventStoreCount) || 0, alertStoreCount: Number(doc.alertStoreCount) || 0, chunkCount: Number(doc.chunkCount) || 0, hasReport: Boolean(doc.finalReport), departmentContext: doc.departmentContext || null, analysisStartDate: doc.analysisStartDate || '', analysisEndDate: doc.analysisEndDate || '', analysisDurationDays: Number(doc.analysisDurationDays) || null });
    }
  }
  runs.sort((a, b) => String(b.generatedAt).localeCompare(String(a.generatedAt)));
  return { ok: true, runs: runs.slice(0, 100) };
}

async function loadReport(config, profileId, file) {
  const { profile, doc } = await loadRunDocument(config, profileId, file);
  return { ok: true, profile: doc.profile || profile, label: doc.label || '', generatedAt: doc.generatedAt || '', dlpPolicy: doc.dlpPolicy || '', analysisModel: doc.analysisModel || '', reportModel: doc.reportModel || '', rawDetectionCount: Number(doc.rawDetectionCount) || 0, chunkCount: Number(doc.chunkCount) || 0, departmentContext: doc.departmentContext || null, analysisStartDate: doc.analysisStartDate || '', analysisEndDate: doc.analysisEndDate || '', analysisDurationDays: Number(doc.analysisDurationDays) || null, markdown: String(doc.finalReport || '') };
}

function analysisObject(chunk) {
  let value = chunk?.analysis_result ?? chunk;
  if (typeof value === 'string') { try { value = JSON.parse(value); } catch { return null; } }
  return value && typeof value === 'object' ? value : null;
}

function increment(map, key, amount) {
  const safeKey = String(key || 'Unspecified').slice(0, 200);
  map.set(safeKey, (map.get(safeKey) || 0) + (Number(amount) || 0));
}

function aggregateRun(doc) {
  const byRule = new Map(); const byWorkload = new Map(); const byRisk = new Map(); const byPattern = new Map(); const byFinding = new Map(); const uniqueNoise = new Set();
  let noiseOccurrences = 0; let validatedInstances = 0; let credentialPairs = 0; let weightedReduction = 0; let weightedCount = 0;
  for (const chunk of (Array.isArray(doc?.chunkAnalyses) ? doc.chunkAnalyses : [])) {
    const analysis = analysisObject(chunk); if (!analysis) continue;
    for (const item of (Array.isArray(analysis.noise_patterns) ? analysis.noise_patterns : [])) {
      const count = Math.max(0, Number(item?.occurrence_count) || 0); noiseOccurrences += count;
      const fingerprint = crypto.createHash('sha256').update(String(item?.pattern || '')).digest('hex'); uniqueNoise.add(fingerprint); increment(byPattern, `Noise pattern ${fingerprint.slice(0, 10)}`, count);
      increment(byRule, item?.triggering_sit_rule, count); increment(byWorkload, item?.source_workload, count);
      const reduction = Number(item?.estimated_fp_reduction); if (Number.isFinite(reduction) && count > 0) { weightedReduction += reduction * count; weightedCount += count; }
    }
    for (const item of (Array.isArray(analysis.validated_credentials) ? analysis.validated_credentials : [])) {
      const count = Math.max(0, Number(item?.count) || 0); const risk = String(item?.risk_level || 'Unspecified').toUpperCase(); validatedInstances += count; increment(byRisk, risk, count); increment(byFinding, `${String(item?.type || 'Finding').slice(0, 80)} · ${String(item?.triggering_sit_rule || 'Unspecified').slice(0, 80)} · ${risk}`, count);
    }
    credentialPairs += (Array.isArray(analysis.credential_pairs) ? analysis.credential_pairs : []).reduce((sum, item) => sum + Math.max(0, Number(item?.count) || 1), 0);
  }
  return {
    metrics: { noiseOccurrences, uniqueNoisePatterns: uniqueNoise.size, validatedInstances, credentialPairs, weightedFpReduction: weightedCount ? Math.round((weightedReduction / weightedCount) * 10) / 10 : 0 },
    byRule: Object.fromEntries([...byRule].sort((a, b) => b[1] - a[1])),
    byWorkload: Object.fromEntries([...byWorkload].sort((a, b) => b[1] - a[1])),
    byRisk: Object.fromEntries([...byRisk].sort()),
    byPattern: Object.fromEntries([...byPattern].sort((a, b) => b[1] - a[1])),
    byFinding: Object.fromEntries([...byFinding].sort((a, b) => b[1] - a[1])),
  };
}

function deltaRows(baseline, current) {
  return [...new Set([...Object.keys(baseline), ...Object.keys(current)])].map((name) => {
    const before = Number(baseline[name]) || 0; const after = Number(current[name]) || 0; const delta = after - before;
    return { name, baseline: before, current: after, delta, status: before === 0 && after > 0 ? 'new' : delta < 0 ? 'reduced' : delta > 0 ? 'increased' : 'unchanged' };
  }).sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta) || a.name.localeCompare(b.name));
}

async function compareRuns(config, profileId, baselineFile, currentFile) {
  if (baselineFile === currentFile) badRequest('Choose two different runs to compare.');
  const baselineRun = await loadRunDocument(config, profileId, baselineFile); const currentRun = await loadRunDocument(config, profileId, currentFile);
  const baseline = aggregateRun(baselineRun.doc); const current = aggregateRun(currentRun.doc);
  const metricDelta = Object.fromEntries(Object.keys(baseline.metrics).map((key) => [key, (Number(current.metrics[key]) || 0) - (Number(baseline.metrics[key]) || 0)]));
  const metadata = (run, file) => ({ file, label: run.label || '', generatedAt: run.generatedAt || '', profile: run.profile || profileId, dlpPolicy: run.dlpPolicy || '', rawDetectionCount: Number(run.rawDetectionCount) || 0, analysisStartDate: run.analysisStartDate || '', analysisEndDate: run.analysisEndDate || '', analysisDurationDays: Number(run.analysisDurationDays) || null });
  const baselineMeta = metadata(baselineRun.doc, baselineRun.runFile); const currentMeta = metadata(currentRun.doc, currentRun.runFile);
  const hasPeriods = Boolean(baselineMeta.analysisStartDate && baselineMeta.analysisEndDate && currentMeta.analysisStartDate && currentMeta.analysisEndDate);
  const overlaps = hasPeriods && baselineMeta.analysisStartDate <= currentMeta.analysisEndDate && currentMeta.analysisStartDate <= baselineMeta.analysisEndDate;
  const sameDuration = hasPeriods && baselineMeta.analysisDurationDays === currentMeta.analysisDurationDays;
  const warning = !hasPeriods ? 'One or both runs use all synchronized evidence or predate period metadata.' : overlaps ? 'The selected assessment periods overlap; deltas are not independent.' : !sameDuration ? 'The selected periods have different durations; compare absolute counts with care.' : '';
  return { ok: true, profileId: safeName(profileId, 'profile'), baseline: { ...baselineMeta, ...baseline }, current: { ...currentMeta, ...current }, comparability: { hasPeriods, overlaps, sameDuration, warning }, delta: { metrics: metricDelta, byRule: deltaRows(baseline.byRule, current.byRule), byWorkload: deltaRows(baseline.byWorkload, current.byWorkload), byRisk: deltaRows(baseline.byRisk, current.byRisk), byPattern: deltaRows(baseline.byPattern, current.byPattern), byFinding: deltaRows(baseline.byFinding, current.byFinding) }, privacy: 'Pattern values are represented by deterministic SHA-256 pseudonyms; chunk text and detected values are not returned.' };
}

async function invokeTextModel(config, systemPrompt, userPrompt, maxOutputTokens = 16000) {
  if (!config.ai?.enabled || !config.ai?.apiKey || !config.ai?.endpoint) throw Object.assign(new Error('Purview implementation guides require the configured Azure OpenAI endpoint and API key.'), { statusCode: 503 });
  const body = { model: config.ai.model, max_output_tokens: maxOutputTokens, input: [{ role: 'system', content: [{ type: 'input_text', text: systemPrompt }] }, { role: 'user', content: [{ type: 'input_text', text: userPrompt }] }] };
  let lastError;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const response = await fetch(config.ai.endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'api-key': config.ai.apiKey, 'User-Agent': 'DlpResponseStudio/0.1' }, body: JSON.stringify(body), signal: AbortSignal.timeout(180000) });
      if (!response.ok) { const detail = (await response.text().catch(() => '')).slice(0, 1000); const error = new Error(`Azure OpenAI request failed (${response.status}): ${detail}`); error.retryable = response.status === 429 || response.status >= 500; throw error; }
      const text = extractResponseText(await response.json()).trim(); if (!text) throw new Error('Azure OpenAI returned an empty implementation guide.'); return text;
    } catch (error) {
      lastError = error; if (!error.retryable || attempt === 3) break;
      await new Promise((resolve) => setTimeout(resolve, Math.min(20000, 1500 * (2 ** (attempt - 1)))));
    }
  }
  throw lastError;
}

function implementationEvidence(doc, includeSensitiveDetails = false) {
  const noisePatterns = []; const regexRefinements = []; const exclusionRules = [];
  for (const chunk of (Array.isArray(doc?.chunkAnalyses) ? doc.chunkAnalyses : [])) {
    const analysis = analysisObject(chunk); if (!analysis) continue;
    for (const item of (Array.isArray(analysis.noise_patterns) ? analysis.noise_patterns : [])) noisePatterns.push({
      ...(includeSensitiveDetails ? { exactFalsePositiveArtifact: String(item?.pattern || '').slice(0, 4000) } : {}),
      triggeringSitRule: String(item?.triggering_sit_rule || '').slice(0, 160),
      reasonFalsePositive: String(item?.reason_false_positive || '').slice(0, 1000),
      occurrenceCount: Math.max(0, Number(item?.occurrence_count) || 0),
      sourceWorkload: String(item?.source_workload || '').slice(0, 100),
      supportingIndicators: (Array.isArray(item?.noise_signal_keywords) ? item.noise_signal_keywords : []).map((value) => String(value).slice(0, 100)).slice(0, 12),
      suppressionStrategy: String(item?.suppression_strategy || '').slice(0, 1500),
      estimatedFpReduction: Math.max(0, Number(item?.estimated_fp_reduction) || 0),
    });
    for (const item of (Array.isArray(analysis.regex_refinements) ? analysis.regex_refinements : [])) regexRefinements.push({ triggeringSitRule: String(item?.triggering_sit_rule || '').slice(0, 160), ...(includeSensitiveDetails ? { observedCurrentPattern: String(item?.current_regex || '').slice(0, 4000) } : {}), improvedLogic: String(item?.improved_regex || '').slice(0, 2000), falsePositiveReduction: String(item?.false_positive_reduction || '').slice(0, 500), falseNegativeRisk: String(item?.false_negative_risk || '').slice(0, 1000) });
    for (const item of (Array.isArray(analysis.exclusion_rules) ? analysis.exclusion_rules : [])) exclusionRules.push({ rule: String(item?.rule || '').slice(0, 2000), scope: String(item?.scope || '').slice(0, 500), reason: String(item?.reason || '').slice(0, 1000) });
  }
  return { noisePatterns: noisePatterns.slice(0, 100), regexRefinements: regexRefinements.slice(0, 100), exclusionRules: exclusionRules.slice(0, 100) };
}

async function getImplementationGuide(config, input = {}) {
  const { profile, runFile, doc } = await loadRunDocument(config, input.profileId, input.file);
  const report = String(doc.finalReport || '').trim(); if (!report) badRequest('This run has no completed report.');
  const includeSensitiveDetails = doc.privacyMode === 'protected-sensitive-content';
  const cacheDir = path.join(profileOutputDir(config, profile), 'implementation'); const cacheFile = path.join(cacheDir, runFile.replace(/\.json$/, '.md'));
  if (!includeSensitiveDetails && input.refresh !== true && await exists(cacheFile)) {
    return { ok: true, cached: true, sensitiveDetailsIncluded: includeSensitiveDetails, profile: doc.profile || profile, dlpPolicy: doc.dlpPolicy || '', generatedAt: doc.generatedAt || '', analysisStartDate: doc.analysisStartDate || '', analysisEndDate: doc.analysisEndDate || '', analysisDurationDays: Number(doc.analysisDurationDays) || null, markdown: await fsp.readFile(cacheFile, 'utf8') };
  }
  const systemPrompt = await fsp.readFile(path.join(__dirname, 'prompts', includeSensitiveDetails ? 'purview-implementation-protected.md' : 'purview-implementation.md'), 'utf8');
  const period = doc.analysisStartDate && doc.analysisEndDate ? `${doc.analysisStartDate} through ${doc.analysisEndDate} (${Number(doc.analysisDurationDays) || 'unknown'} days)` : 'All synchronized evidence';
  const evidence = implementationEvidence(doc, includeSensitiveDetails);
  const detailInstruction = includeSensitiveDetails ? 'Step 2 already performed the explicitly confirmed protected-content analysis. Use exact artifacts that Step 2 classified as false positives when needed to configure or validate the Purview change. Do not request or infer raw event data. Never reproduce validated or possible credentials, personal data, message content, or unrelated sensitive values.' : 'Do not reproduce detected sensitive values.';
  const userPrompt = `DLP policy: ${String(doc.dlpPolicy || '')}\nSIT profile: ${String(doc.profile || profile)}\nAssessment period: ${period}\nRun generated: ${String(doc.generatedAt || '')}\nEvidence mode: ${includeSensitiveDetails ? 'protected sensitive-detail planning' : 'privacy-safe planning'}\n\nConvert this completed SIT noise-reduction report and its structured remediation evidence into the required implementation plan. Keep all evidence claims bounded to the stated assessment period. ${detailInstruction} Every proposed Purview change must cite the triggering SIT, workload or location when available, false-positive rationale, structural indicators, suppression mechanism, expected reduction, false-negative risk, and validation guardrail. Do not replace actionable evidence with generic language.\n\n----- BEGIN STRUCTURED REMEDIATION EVIDENCE -----\n${JSON.stringify(evidence, null, 2)}\n----- END STRUCTURED REMEDIATION EVIDENCE -----\n\n----- BEGIN ANALYSIS REPORT -----\n${report}\n----- END ANALYSIS REPORT -----`;
  const markdown = await invokeTextModel(config, systemPrompt, userPrompt);
  if (!includeSensitiveDetails) { await fsp.mkdir(cacheDir, { recursive: true }); const temporary = `${cacheFile}.${process.pid}.tmp`; await fsp.writeFile(temporary, markdown, 'utf8'); await fsp.copyFile(temporary, cacheFile); await fsp.rm(temporary, { force: true }); }
  return { ok: true, cached: false, sensitiveDetailsIncluded: includeSensitiveDetails, profile: doc.profile || profile, dlpPolicy: doc.dlpPolicy || '', generatedAt: doc.generatedAt || '', analysisStartDate: doc.analysisStartDate || '', analysisEndDate: doc.analysisEndDate || '', analysisDurationDays: Number(doc.analysisDurationDays) || null, markdown };
}

async function draftProfile(config, input = {}) {
  const requestedIds = Array.isArray(input.sitIds) ? input.sitIds.map(String) : [];
  if (!requestedIds.length) badRequest('Select at least one Sensitive Information Type before using AI authoring.');
  const catalog = await buildSitCatalog(config); const selected = catalog.sensitiveInformationTypes.filter((item) => requestedIds.some((id) => id.toLowerCase() === item.id.toLowerCase()));
  if (selected.length !== new Set(requestedIds.map((id) => id.toLowerCase())).size) badRequest('The AI authoring scope contains an unknown Sensitive Information Type.');
  const operatorFocus = String(input.analysisFocus || '').trim();
  if (!operatorFocus) badRequest('Describe what is key for this SIT before using AI authoring.');
  if (operatorFocus.length > 12000) badRequest('Analysis focus exceeds 12,000 characters.');
  const systemPrompt = await fsp.readFile(path.join(__dirname, 'prompts', 'sit-profile-authoring.md'), 'utf8');
  const userPrompt = `Draft a profile for this exact, immutable SIT scope:\n${selected.map((item) => `- ${item.name} (${item.id})`).join('\n')}\n\nCurrent profile ID: ${String(input.id || '')}\nCurrent description: ${String(input.description || '')}\nCurrent DLP policy wildcard: ${String(input.dlpPolicy || '*')}\nCurrent finding noun: ${String(input.findingNoun || '')}\n\nAUTHORITATIVE OPERATOR ANALYSIS FOCUS:\n${operatorFocus}\n\nRefine the analysis focus and author all three instructions. Do not add another SIT or request synchronized evidence.`;
  const raw = await invokeTextModel(config, systemPrompt, userPrompt, 16000); let parsed;
  try { parsed = JSON.parse(extractJson(raw)); } catch (error) { throw new Error(`AI profile authoring returned invalid JSON: ${error.message}`); }
  const instructions = { extractionInstruction: String(parsed.extractionInstruction || '').trim(), consolidationInstruction: String(parsed.consolidationInstruction || '').trim(), reportMergeInstruction: String(parsed.reportMergeInstruction || '').trim() };
  for (const [key, value] of Object.entries(instructions)) { if (!value || value.length > 100000) throw new Error(`AI profile authoring returned an invalid ${key}.`); }
  const requiredKeys = ['credential_summary', 'noise_patterns', 'validated_credentials', 'credential_pairs', 'low_frequency_patterns', 'regex_refinements', 'multi_encoded_artifacts', 'workload_context', 'exclusion_rules', 'recommendations'];
  const missing = requiredKeys.filter((key) => !instructions.extractionInstruction.includes(key)); if (missing.length) throw new Error(`AI extraction instruction omitted required schema keys: ${missing.join(', ')}.`);
  const proposedName = String(parsed.name || input.id || '').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 100) || safeName(input.id, 'profile');
  return { ok: true, draft: { id: proposedName, description: String(parsed.description || input.description || '').trim().slice(0, 500), analysisFocus: String(parsed.analysisFocus || operatorFocus).trim().slice(0, 12000), dlpPolicy: String(parsed.dlpPolicy || input.dlpPolicy || '*').trim().slice(0, 200), findingNoun: String(parsed.findingNoun || input.findingNoun || 'finding').trim().slice(0, 100), instructions, sitIds: selected.map((item) => item.id), sitNames: selected.map((item) => item.name) }, model: config.ai.model, privacy: 'Only operator-entered profile fields and selected SIT metadata were sent; synchronized DLP events and detected values were excluded.' };
}

function processIsAlive(pid) {
  const processId = Number(pid);
  if (!Number.isInteger(processId) || processId <= 0) return false;
  try { process.kill(processId, 0); return true; } catch { return false; }
}

async function readLogTail(file, maxBytes = 512 * 1024) {
  try {
    const stat = await fsp.stat(file); const length = Math.min(stat.size, maxBytes); const handle = await fsp.open(file, 'r'); const buffer = Buffer.alloc(length);
    try { await handle.read(buffer, 0, length, Math.max(0, stat.size - length)); } finally { await handle.close(); }
    return { text: buffer.toString('utf8'), lastWriteUtc: stat.mtime.toISOString() };
  } catch { return { text: '', lastWriteUtc: '' }; }
}

function parseJobProgress(logText, status = 'running') {
  const text = String(logText || ''); let totalChunks = 0; let completedChunks = 0;
  for (const match of text.matchAll(/(?:Created\s+(\d+)\s+chunk|(?:Queueing|Analyzing|Completed) chunk\s+\d+\/(\d+))/gi)) totalChunks = Math.max(totalChunks, Number(match[1] || match[2]) || 0);
  for (const match of text.matchAll(/Completed chunk\s+(\d+)\/(\d+)/gi)) { completedChunks = Math.max(completedChunks, Number(match[1]) || 0); totalChunks = Math.max(totalChunks, Number(match[2]) || 0); }
  for (const match of text.matchAll(/Analyzing chunk\s+(\d+)\/(\d+)/gi)) { completedChunks = Math.max(completedChunks, (Number(match[1]) || 1) - 1); totalChunks = Math.max(totalChunks, Number(match[2]) || 0); }
  let stage = text ? 'Preparing governed evidence' : 'Waiting for worker output'; let percent = totalChunks ? Math.min(85, Math.round((completedChunks / totalChunks) * 85)) : null;
  if (/Queueing chunk|Analyzing chunk|Completed chunk/i.test(text)) stage = totalChunks ? `Analyzing chunks (${completedChunks}/${totalChunks} complete)` : 'Analyzing evidence chunks';
  if (/--- Consolidating\s+\d+\s+analyses|Consolidation pass/i.test(text)) { stage = 'Consolidating final report'; percent = 90; completedChunks = totalChunks || completedChunks; }
  if (/Final Consolidated Report|Report cached at/i.test(text)) { stage = 'Saving report and run evidence'; percent = 97; }
  if (/Run snapshot saved to/i.test(text) || status === 'completed') { stage = 'Completed'; percent = 100; completedChunks = totalChunks || completedChunks; }
  if (status === 'failed') { stage = 'Worker stopped before completion'; percent = null; }
  return { stage, percent, completedChunks, totalChunks };
}

async function listJobs(config) {
  const dir = path.join(config.dataDir, 'sit-optimize', 'jobs'); await fsp.mkdir(dir, { recursive: true });
  const files = (await fsp.readdir(dir)).filter((file) => /^[A-Za-z0-9_-]+\.json$/.test(file)).sort().reverse().slice(0, 50);
  const jobs = [];
  for (const file of files) {
    const jobFile = path.join(dir, file); let job = await readJson(jobFile, null); if (!job) continue;
    const logName = /^[A-Za-z0-9_.-]+\.log$/.test(String(job.logFile || '')) ? job.logFile : file.replace(/\.json$/, '.log');
    const log = await readLogTail(path.join(dir, logName));
    if (['starting', 'running'].includes(job.status) && !processIsAlive(job.pid)) {
      job = { ...job, status: 'failed', completedUtc: new Date().toISOString(), error: 'The analysis worker is no longer running. It may have been interrupted by a server restart or process termination.' };
      await writeJsonAtomic(jobFile, job);
    }
    jobs.push({ ...job, workerAlive: ['starting', 'running'].includes(job.status) ? true : false, lastActivityUtc: log.lastWriteUtc, progress: parseJobProgress(log.text, job.status) });
  }
  return { ok: true, jobs };
}

async function startAnalysis(config, body = {}) {
  if (!config.sitOptimize?.enabled) throw Object.assign(new Error('Detection Assurance is disabled in configuration.'), { statusCode: 503 });
  if (!config.ai?.apiKey || !config.ai?.endpoint) throw Object.assign(new Error('Detection Assurance requires the configured Azure OpenAI endpoint and API key.'), { statusCode: 503 });
  const profileId = safeName(body.profileId, 'profile');
  const available = await loadProfiles(config);
  const profile = available.profiles.find((item) => item.id.toLowerCase() === profileId.toLowerCase());
  if (!profile) badRequest('Detection Assurance profile not found.');
  if (!profile.hasSitScope) badRequest(`Profile ${profile.id} has no explicit SensitiveInformationTypeIds or SensitiveInformationTypeNames allow-list.`);
  const period = analysisPeriod(body.analysisStartDate, body.analysisEndDate);
  const scoped = await scopeProfile(config, profile.id, period.startDate, period.endDate);
  if (!scoped.canAnalyze) badRequest(`No synchronized detections match profile ${profile.id} during ${period.label}.`);
  const summary = await summarizeSharedStore(config);
  if (!summary.ok) badRequest(summary.message);
  const sensitiveContent = body.sensitiveContent === true;
  if (sensitiveContent && !config.sitOptimize?.sensitiveContent?.enabled) badRequest('Protected sensitive-content analysis is disabled in configuration.');
  if (sensitiveContent && body.confirmation !== config.sitOptimize.sensitiveContent.analysisConfirmationPhrase) badRequest('The sensitive-content analysis confirmation phrase does not match.');
  if (sensitiveContent && !summary.protectedEvidence?.ready) badRequest('No DPAPI-protected SIT evidence is available. Rebuild protected evidence first.');
  const root = sitRoot(config); const script = path.join(root, 'credpattern.ps1');
  if (!(await exists(script))) throw Object.assign(new Error('Detection Assurance analysis worker was not found.'), { statusCode: 503 });

  const jobId = `${new Date().toISOString().replace(/[:.]/g, '-')}-${crypto.randomBytes(3).toString('hex')}`;
  const jobDir = path.join(config.dataDir, 'sit-optimize', 'jobs');
  const outputDir = profileOutputDir(config, profile.id); const runDir = path.join(outputDir, 'runs'); const reportDir = path.join(outputDir, 'reports'); const triageDir = path.join(config.dataDir, 'sit-optimize', 'triage');
  await Promise.all([fsp.mkdir(jobDir, { recursive: true }), fsp.mkdir(runDir, { recursive: true }), fsp.mkdir(reportDir, { recursive: true }), fsp.mkdir(triageDir, { recursive: true })]);
  const jobFile = path.join(jobDir, `${jobId}.json`); const logFile = path.join(jobDir, `${jobId}.log`);
  const label = String(body.label || `${profile.name} · ${period.label}`).slice(0, 120);
  const privacyMode = sensitiveContent ? 'protected-sensitive-content' : 'context-only';
  const source = sensitiveContent ? 'DPAPI-protected SIT evidence' : summary.source;
  const job = { id: jobId, profileId: profile.id, profile: profile.name, dlpPolicy: profile.dlpPolicy, label, status: 'starting', createdUtc: new Date().toISOString(), privacyMode, source, analysisModel: config.sitOptimize.analysisModel || config.ai.model, reportModel: config.ai.model, departmentContext: scoped.departmentContext, analysisStartDate: period.startDate, analysisEndDate: period.endDate, analysisDurationDays: period.durationDays, analysisPeriodLabel: period.label, logFile: path.basename(logFile) };
  await writeJsonAtomic(jobFile, job);

  const args = ['-NoProfile', '-File', script, '-ProfilePath', path.join(root, 'profiles', `${profile.id}.psd1`), '-SkipCollection', '-EventStorePath', path.join(config.dataDir, 'dlp-events-store.jsonl'), '-AlertStorePath', path.join(config.dataDir, 'dlp-alerts-store.jsonl'), '-SyncStatePath', path.join(config.dataDir, 'dlp-sync-state.json'), '-UserDirectoryPath', path.join(config.dataDir, 'user-directory.json'), '-RunSnapshotDir', runDir, '-ReportCacheDir', reportDir, '-TriageOutputDir', triageDir, '-AnalysisResultsReferencePath', path.join(outputDir, `${jobId}-chunks.json`), '-OpenAIEndpoint', config.ai.endpoint, '-AnalysisModel', config.sitOptimize.analysisModel || config.ai.model, '-Model', config.ai.model, '-RunLabel', label];
  if (period.startDate) args.push('-AnalysisStartDate', period.startDate, '-AnalysisEndDate', period.endDate);
  if (sensitiveContent) args.push('-UseProtectedSensitiveEvents', '-IncludeSensitiveValues', '-ProtectedEventStorePath', path.join(config.dataDir, 'protected', 'sit-sensitive-events.jsonl'));
  if (body.disableMultiThreading === true) args.push('-DisableMultiThreading');
  const output = fs.openSync(logFile, 'a');
  const child = spawn(config.powershellExecutable, args, { cwd: outputDir, windowsHide: true, stdio: ['ignore', output, output], env: { ...process.env, AZURE_OPENAI_API_KEY2: config.ai.apiKey, NO_COLOR: '1', TERM: 'dumb' } });
  fs.closeSync(output);
  job.status = 'running'; job.pid = child.pid; job.startedUtc = new Date().toISOString(); await writeJsonAtomic(jobFile, job);
  child.on('error', async (error) => { await writeJsonAtomic(jobFile, { ...job, status: 'failed', completedUtc: new Date().toISOString(), error: String(error.message || error).slice(0, 1000) }).catch(() => {}); });
  child.on('close', async (code) => { await writeJsonAtomic(jobFile, { ...job, status: code === 0 ? 'completed' : 'failed', exitCode: code, completedUtc: new Date().toISOString() }).catch(() => {}); });
  return { ok: true, job: { ...job, pid: undefined }, message: `${sensitiveContent ? 'Sensitive-content Detection Assurance assessment started from the DPAPI-protected store' : 'Context-only Detection Assurance assessment started against the redacted DLP stores'} for ${period.label}. No Graph synchronization was launched.` };
}

module.exports = { buildSitCatalog, compareRuns, draftProfile, getImplementationGuide, listJobs, listRuns, loadProfile, loadProfiles, loadReport, parseJobProgress, saveProfile, scopeProfile, startAnalysis, summarizeSharedStore };
