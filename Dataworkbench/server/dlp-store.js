'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const readline = require('node:readline');

async function exists(file) {
  try { await fsp.access(file); return true; } catch { return false; }
}

async function readJson(file, fallback = null) {
  try { return JSON.parse(await fsp.readFile(file, 'utf8')); } catch { return fallback; }
}

async function writeJsonAtomic(file, value) {
  await fsp.mkdir(path.dirname(file), { recursive: true });
  const temp = `${file}.${process.pid}.tmp`;
  await fsp.writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  await fsp.rename(temp, file);
}

async function appendJsonl(file, value) {
  await fsp.mkdir(path.dirname(file), { recursive: true });
  await fsp.appendFile(file, `${JSON.stringify(value)}\n`, 'utf8');
}

function alertOwner(alert) {
  const extra = alert.additionalData || {};
  return {
    alertId: alert.id || null,
    incidentId: alert.incidentId || null,
    detectorId: alert.detectorId || null,
    policyId: alert.alertPolicyId || null,
    policy: extra.AlertPolicyTitle || extra.alertPolicytitle || alert.title || null,
    severity: alert.severity || null,
    status: alert.status || null,
    firstActivityMs: Date.parse(alert.firstActivityDateTime || ''),
    lastActivityMs: Date.parse(alert.lastActivityDateTime || ''),
  };
}

async function loadAlertIndex(alertStorePath) {
  const index = { byId: new Map(), byDetector: new Map() };
  if (!(await exists(alertStorePath))) return index;
  const input = fs.createReadStream(alertStorePath, 'utf8');
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  for await (const line of lines) {
    if (!line.trim()) continue;
    let alert;
    try { alert = JSON.parse(line); } catch { continue; }
    const detectorId = alert?.detectorId;
    if (!detectorId) continue;
    const owner = alertOwner(alert); const detectorKey = String(detectorId).toLowerCase();
    if (owner.alertId) index.byId.set(String(owner.alertId), owner);
    if (!index.byDetector.has(detectorKey)) index.byDetector.set(detectorKey, []);
    index.byDetector.get(detectorKey).push(owner);
  }
  return index;
}

function resolveAlertOwner(event, alertIndex) {
  const lineage = event?._dlpResponseStudio;
  if (lineage?.alertId) {
    const explicit = alertIndex.byId.get(String(lineage.alertId));
    if (explicit) return explicit;
  }
  const detectorKey = String(event?.alertCorrelationId || '').toLowerCase();
  const candidates = alertIndex.byDetector.get(detectorKey) || [];
  if (!candidates.length) return null;
  const eventStart = Date.parse(event?.startDateTime || event?.createdDateTime || '');
  const eventEnd = Date.parse(event?.endDateTime || event?.startDateTime || event?.createdDateTime || '');
  if (!Number.isFinite(eventStart) || !Number.isFinite(eventEnd)) return null;
  const matches = candidates.filter((owner) => Number.isFinite(owner.firstActivityMs) && Number.isFinite(owner.lastActivityMs)
    && eventStart >= owner.firstActivityMs && eventEnd <= owner.lastActivityMs);
  return matches.length === 1 ? matches[0] : null;
}

function normalizeFilters(body = {}) {
  const list = (name) => new Set((Array.isArray(body[name]) ? body[name] : []).map((v) => String(v).trim().toLowerCase()).filter(Boolean));
  return {
    workloads: list('workloads'), sits: list('sits'), policies: list('policies'),
    users: list('users'), senders: list('senders'), departments: list('departments'),
    minConfidence: Math.max(0, Math.min(100, Number(body.minConfidence) || 0)),
    dateFrom: body.dateFrom ? Date.parse(body.dateFrom) : null,
    dateTo: body.dateTo ? Date.parse(body.dateTo) : null,
  };
}

function matchesSet(value, set) {
  return !set.size || set.has(String(value || '').toLowerCase());
}

function addFacet(map, value) {
  if (value == null || value === '') return;
  const key = String(value);
  map.set(key, (map.get(key) || 0) + 1);
}

function facetRows(map) {
  return [...map].map(([value, count]) => ({ value, count })).sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
}

async function loadUserDirectory(config) {
  const source = await readJson(path.join(config.dataDir, 'user-directory.json'), {});
  if (!source || typeof source !== 'object' || Array.isArray(source)) return {};
  return Object.fromEntries(Object.entries(source).map(([upn, profile]) => [String(upn).trim().toLowerCase(), {
    department: profile?.department ? String(profile.department).trim() : null,
    displayName: profile?.displayName ? String(profile.displayName).trim() : null,
    mail: profile?.mail ? String(profile.mail).trim().toLowerCase() : null,
    resolvedUtc: profile?.resolvedUtc ? String(profile.resolvedUtc) : null,
  }]));
}

function redactedDetection(event, audit, sensitive, owner, handling) {
  const detectedValues = sensitive.SensitiveInformationDetections?.DetectedValues;
  const values = handling === 'retain' ? detectedValues : detectedValues ? '[REDACTED]' : null;
  return {
    eventId: event.id || null,
    alertId: owner?.alertId || event.id || null,
    detectorId: event.alertCorrelationId || null,
    incidentId: owner?.incidentId || null,
    incidentUrl: owner?.incidentId ? `https://security.microsoft.com/incidents/${encodeURIComponent(owner.incidentId)}` : null,
    observedUtc: event.createdDateTime || event.startDateTime || null,
    user: audit.UserId ? String(audit.UserId).toLowerCase() : null,
    sender: audit.EnrichedEmailInfo?.Sender ? String(audit.EnrichedEmailInfo.Sender).toLowerCase() : null,
    workload: audit.Workload || audit.EnrichedFields?.EnrichedWorkload || null,
    sensitiveTypeId: sensitive.SensitiveType || null,
    sensitiveTypeName: sensitive.SensitiveInformationTypeName || null,
    confidence: Number(sensitive.Confidence) || null,
    location: sensitive.Location || null,
    policyId: owner?.policyId || event.alertPolicyId || null,
    policy: owner?.policy || null,
    severity: owner?.severity || null,
    status: owner?.status || null,
    contentName: audit.ContentInfo?.FullName || audit.FileFullPath || null,
    recipients: Array.isArray(audit.FullRecipients) ? audit.FullRecipients : audit.FullRecipients || null,
    detectedValues: values,
  };
}

async function queryDlpEvents(config, body = {}) {
  const eventStorePath = path.join(config.dataDir, 'dlp-events-store.jsonl');
  const alertStorePath = path.join(config.dataDir, 'dlp-alerts-store.jsonl');
  if (!(await exists(eventStorePath))) return { ok: false, error: 'No DLP event store found. Run the collector first.' };
  const filters = normalizeFilters(body);
  const alertIndex = await loadAlertIndex(alertStorePath);
  const userDirectory = await loadUserDirectory(config);
  const facets = Object.fromEntries(['workloads', 'sits', 'policies', 'departments', 'users', 'senders'].map((k) => [k, new Map()]));
  const rows = [];
  const allMatched = [];
  const affected = new Map();
  const incidentIds = new Set();
  const documentUrls = new Set();
  let scannedEvents = 0;
  let totalDetections = 0;
  let truncated = false;

  const input = fs.createReadStream(eventStorePath, 'utf8');
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  for await (const line of lines) {
    if (!line.trim()) continue;
    scannedEvents++;
    if (scannedEvents > config.maxScanEvents) { truncated = true; break; }
    let event;
    try { event = JSON.parse(line); } catch { continue; }
    let audit = event.auditRecord;
    if (typeof audit === 'string') { try { audit = JSON.parse(audit); } catch { audit = null; } }
    if (!audit || !Array.isArray(audit.PolicyDetails)) continue;
    const owner = resolveAlertOwner(event, alertIndex);
    if (!owner) continue;
    for (const policy of audit.PolicyDetails) {
      for (const rule of (policy.Rules || [])) {
        for (const sensitive of (rule.ConditionsMatched?.SensitiveInformation || [])) {
          if (!sensitive?.SensitiveInformationDetections) continue;
          totalDetections++;
          const row = redactedDetection(event, audit, sensitive, owner, config.detectedValueHandling);
          row.department = row.user ? userDirectory[row.user]?.department || null : null;
          addFacet(facets.workloads, row.workload); addFacet(facets.sits, row.sensitiveTypeName);
          addFacet(facets.policies, row.policy); addFacet(facets.departments, row.department);
          addFacet(facets.users, row.user); addFacet(facets.senders, row.sender);
          const when = row.observedUtc ? Date.parse(row.observedUtc) : null;
          if (!matchesSet(row.workload, filters.workloads) || !matchesSet(row.sensitiveTypeName, filters.sits)
            || !matchesSet(row.policy, filters.policies) || !matchesSet(row.user, filters.users)
            || !matchesSet(row.sender, filters.senders) || !matchesSet(row.department, filters.departments)
            || (row.confidence || 0) < filters.minConfidence
            || (filters.dateFrom && (!when || when < filters.dateFrom)) || (filters.dateTo && (!when || when > filters.dateTo))) continue;
          if (allMatched.length < config.maxPlanDetections) allMatched.push(row);
          if (rows.length < config.maxResultRows) rows.push(row);
          if (row.incidentId) incidentIds.add(String(row.incidentId));
          if (/^https:\/\//i.test(String(row.contentName || ''))) documentUrls.add(row.contentName);
          if (row.user) {
            if (!affected.has(row.user)) affected.set(row.user, { userId: row.user, department: row.department, detectionCount: 0, incidentIds: new Set(), sensitiveTypes: new Set() });
            const user = affected.get(row.user); user.detectionCount++;
            if (row.incidentId) user.incidentIds.add(String(row.incidentId));
            if (row.sensitiveTypeName) user.sensitiveTypes.add(row.sensitiveTypeName);
          }
        }
      }
    }
  }

  const affectedUsers = [...affected.values()].map((u) => ({
    userId: u.userId, department: u.department, detectionCount: u.detectionCount, incidentIds: [...u.incidentIds],
    incidentCount: u.incidentIds.size, sensitiveTypes: [...u.sensitiveTypes],
  })).sort((a, b) => b.detectionCount - a.detectionCount);
  return {
    ok: true, generatedUtc: new Date().toISOString(), scannedEvents, truncated, totalDetections,
    matchedCount: allMatched.length, rows, planDetections: allMatched, affectedUsers,
    incidentIds: [...incidentIds], documentUrls: [...documentUrls],
    departmentsCached: Object.values(userDirectory).filter((profile) => profile.department).length,
    facets: Object.fromEntries(Object.entries(facets).map(([k, v]) => [k, facetRows(v)])),
  };
}

module.exports = { appendJsonl, exists, loadAlertIndex, loadUserDirectory, queryDlpEvents, readJson, resolveAlertOwner, writeJsonAtomic };
