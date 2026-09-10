'use strict';

const fsp = require('node:fs/promises');
const path = require('node:path');
const { exists, readJson } = require('./dlp-store');

const PRIORITIES = new Set(['HIGH', 'MEDIUM', 'LOW']);
const DISPOSITIONS = new Set(['LIVE_CREDENTIAL', 'LIKELY_CREDENTIAL', 'NOISE', 'INDETERMINATE']);
const VALIDITY = new Set(['ACTIVE', 'EXPIRED', 'TRUNCATED', 'REVOKED', 'INDETERMINATE']);
const CORRELATION_VERSION = 'detector-and-alert-activity-window-v2';

function cleanText(value, max) {
  return String(value || '').replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

function cleanSecurityComment(value) {
  return cleanText(value, 3000)
    .replace(/\bhttps?:\/\/\S+/gi, '[URL redacted]')
    .replace(/\b[^\s@]+@[^\s@]+\.[^\s@]+\b/gi, '[identity redacted]')
    .replace(/(^|\s)(?:[A-Za-z0-9+/_=]{20,}|(?=[A-Za-z0-9+/_=-]{20,}(?=\s|$|[.,;:!?]))(?=[A-Za-z0-9+/_=-]*[0-9+/_=])[A-Za-z0-9+/_=-]{20,})(?=\s|$|[.,;:!?])/g, '$1[sensitive artifact redacted]')
    .slice(0, 1500);
}

function normalizeFalsePositivePattern(pattern) {
  const patternFamily = cleanSecurityComment(pattern?.patternFamily || pattern?.pattern_family);
  const reasonFalsePositive = cleanSecurityComment(pattern?.reasonFalsePositive || pattern?.reason_false_positive);
  const suppressionStrategy = cleanSecurityComment(pattern?.suppressionStrategy || pattern?.suppression_strategy);
  const falseNegativeGuardrail = cleanSecurityComment(pattern?.falseNegativeGuardrail || pattern?.false_negative_guardrail);
  if (!patternFamily || !reasonFalsePositive || !suppressionStrategy || !falseNegativeGuardrail) return null;
  const confidence = cleanText(pattern?.confidence, 12).toUpperCase();
  return {
    patternFamily,
    triggeringSitRule: cleanText(pattern?.triggeringSitRule || pattern?.triggering_sit_rule, 160),
    reasonFalsePositive,
    supportingIndicators: (Array.isArray(pattern?.supportingIndicators || pattern?.supporting_indicators) ? (pattern.supportingIndicators || pattern.supporting_indicators) : []).map((value) => cleanSecurityComment(value)).filter(Boolean).slice(0, 8),
    suppressionStrategy,
    falseNegativeGuardrail,
    workload: cleanText(pattern?.workload, 100),
    location: cleanText(pattern?.location, 160),
    occurrenceCount: Math.max(0, Number(pattern?.occurrenceCount ?? pattern?.occurrence_count) || 0),
    confidence: PRIORITIES.has(confidence) ? confidence : 'MEDIUM',
    bindingBasis: ['evidence-reference', 'analysis-batch-fallback', 'prior-same-scope-fallback'].includes(cleanText(pattern?.bindingBasis || pattern?.binding_basis, 40)) ? cleanText(pattern?.bindingBasis || pattern?.binding_basis, 40) : '',
  };
}

function normalizeEntry(entry, source = {}) {
  const incidentId = cleanText(entry?.incidentId || entry?.incident_id, 100);
  if (!incidentId || !/^[A-Za-z0-9-]+$/.test(incidentId)) return null;
  const priority = cleanText(entry?.priority, 12).toUpperCase();
  const disposition = cleanText(entry?.disposition, 32).toUpperCase();
  const validityStatus = cleanText(entry?.validityStatus || entry?.validity_status, 20).toUpperCase();
  const securityComment = cleanSecurityComment(entry?.securityComment || entry?.security_comment);
  if (!securityComment) return null;
  return {
    incidentId,
    priority: PRIORITIES.has(priority) ? priority : 'MEDIUM',
    disposition: DISPOSITIONS.has(disposition) ? disposition : 'INDETERMINATE',
    validityStatus: VALIDITY.has(validityStatus) ? validityStatus : 'INDETERMINATE',
    securityComment,
    profileId: cleanText(entry?.profileId || source.profileId || source.profile, 100),
    assessmentLabel: cleanText(entry?.assessmentLabel || source.label, 120),
    analysisStartDate: cleanText(entry?.analysisStartDate || source.analysisStartDate, 10),
    analysisEndDate: cleanText(entry?.analysisEndDate || source.analysisEndDate, 10),
    generatedAt: cleanText(entry?.generatedAt || source.generatedAt, 40),
    model: cleanText(entry?.model || source.model, 100),
    evidenceCount: Math.max(0, Number(entry?.evidenceCount) || 0),
    falsePositivePatterns: (Array.isArray(entry?.falsePositivePatterns || entry?.false_positive_patterns) ? (entry.falsePositivePatterns || entry.false_positive_patterns) : []).map(normalizeFalsePositivePattern).filter(Boolean).slice(0, 20),
    isAiGenerated: true,
    requiresHumanReview: true,
  };
}

async function loadLatestSitTriage(config) {
  const dir = path.join(config.dataDir, 'sit-optimize', 'triage');
  if (!(await exists(dir))) return new Map();
  const files = (await fsp.readdir(dir)).filter((file) => /^triage-[A-Za-z0-9_-]+-[0-9_]+\.json$/.test(file)).sort().reverse().slice(0, 100);
  const byIncident = new Map();
  for (const file of files) {
    const doc = await readJson(path.join(dir, file), null); if (!doc) continue;
    if (doc.correlationVersion !== CORRELATION_VERSION) continue;
    for (const raw of (Array.isArray(doc.entries) ? doc.entries : [])) {
      const entry = normalizeEntry(raw, doc); if (!entry) continue;
      const current = byIncident.get(entry.incidentId);
      if (!current || String(entry.generatedAt).localeCompare(String(current.generatedAt)) > 0) byIncident.set(entry.incidentId, entry);
    }
  }
  return byIncident;
}

async function getSitTriageForIncidents(config, incidentIds = []) {
  const index = await loadLatestSitTriage(config); const result = {};
  for (const value of incidentIds) { const id = String(value); if (index.has(id)) result[id] = index.get(id); }
  return result;
}

async function enrichDlpQueryWithSitTriage(config, query) {
  if (!query?.ok) return query;
  const index = await loadLatestSitTriage(config);
  const rows = (query.rows || []).map((row) => ({ ...row, sitTriage: row.incidentId ? index.get(String(row.incidentId)) || null : null }));
  const planDetections = (query.planDetections || []).map((row) => ({ ...row, sitTriage: row.incidentId ? index.get(String(row.incidentId)) || null : null }));
  return { ...query, rows, planDetections, sitTriageSummary: { incidentCount: new Set(rows.filter((row) => row.sitTriage).map((row) => String(row.incidentId))).size } };
}

module.exports = { CORRELATION_VERSION, enrichDlpQueryWithSitTriage, getSitTriageForIncidents, loadLatestSitTriage, normalizeEntry, normalizeFalsePositivePattern };
