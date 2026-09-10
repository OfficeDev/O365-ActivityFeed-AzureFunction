'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { extractJson, extractResponseText } = require('./ai-helper');
const { queryDlpEvents } = require('./dlp-store');
const { normalizeEndpoint, saveFoundryConfiguration } = require('./foundry-configuration');
const { generateIntegration, normalizeSpec } = require('./integration-generator');
const sitOptimize = require('./sit-optimize');
const { collect, normalizeFlowDocument, queryDlpEventsWithTriage } = require('./services');

async function fixture() {
  const dataDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'dlp-studio-'));
  const alert = { id: 'a1', detectorId: 'corr1', incidentId: '100', alertPolicyId: 'p1', firstActivityDateTime: '2026-08-01T12:00:00Z', lastActivityDateTime: '2026-08-01T12:15:00Z', title: 'DLP alert', additionalData: { AlertPolicyTitle: 'Protect credentials' } };
  const event = { id: 'e1', alertCorrelationId: 'corr1', startDateTime: '2026-08-01T12:00:00Z', auditRecord: { UserId: 'User@Example.com', Workload: 'SharePoint', PolicyDetails: [{ Rules: [{ ConditionsMatched: { SensitiveInformation: [{ SensitiveType: 'sit1', SensitiveInformationTypeName: 'Source Code', Confidence: 91, Location: 'body', SensitiveInformationDetections: { DetectedValues: [{ value: 'secret' }] } }] } }] }] } };
  await fsp.writeFile(path.join(dataDir, 'dlp-alerts-store.jsonl'), `${JSON.stringify(alert)}\n`);
  await fsp.writeFile(path.join(dataDir, 'dlp-events-store.jsonl'), `${JSON.stringify(event)}\n`);
  return dataDir;
}

test('queries and redacts DLP detections', async () => {
  const dataDir = await fixture();
  const result = await queryDlpEvents({ dataDir, maxScanEvents: 100, maxResultRows: 10, maxPlanDetections: 10, detectedValueHandling: 'redact' }, { sits: ['source code'] });
  assert.equal(result.ok, true); assert.equal(result.matchedCount, 1); assert.equal(result.rows[0].user, 'user@example.com');
  assert.equal(result.rows[0].incidentId, '100'); assert.equal(result.rows[0].detectedValues, '[REDACTED]');
});

test('filters by confidence', async () => {
  const dataDir = await fixture();
  const result = await queryDlpEvents({ dataDir, maxScanEvents: 100, maxResultRows: 10, maxPlanDetections: 10, detectedValueHandling: 'redact' }, { minConfidence: 95 });
  assert.equal(result.matchedCount, 0); assert.equal(result.totalDetections, 1);
});

test('enriches and filters DLP results by cached Graph department', async () => {
  const dataDir = await fixture();
  await fsp.writeFile(path.join(dataDir, 'user-directory.json'), JSON.stringify({ 'USER@example.com': { department: 'Finance', displayName: 'Example User', mail: 'user@example.com', resolvedUtc: '2026-08-11T00:00:00Z' } }));
  const enriched = await queryDlpEvents({ dataDir, maxScanEvents: 100, maxResultRows: 10, maxPlanDetections: 10, detectedValueHandling: 'redact' }, { departments: ['finance'] });
  assert.equal(enriched.matchedCount, 1); assert.equal(enriched.rows[0].department, 'Finance'); assert.equal(enriched.affectedUsers[0].department, 'Finance'); assert.deepEqual(enriched.facets.departments, [{ value: 'Finance', count: 1 }]); assert.equal(enriched.departmentsCached, 1);
  const excluded = await queryDlpEvents({ dataDir, maxScanEvents: 100, maxResultRows: 10, maxPlanDetections: 10, detectedValueHandling: 'redact' }, { departments: ['engineering'] });
  assert.equal(excluded.matchedCount, 0);
});

test('correlates shared-detector events by alert activity window', async () => {
  const dataDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'dlp-temporal-lineage-'));
  const alerts = [
    { id: 'old-alert', detectorId: 'shared-detector', incidentId: '111', firstActivityDateTime: '2026-05-05T05:45:00Z', lastActivityDateTime: '2026-05-05T06:00:00Z', additionalData: { AlertPolicyTitle: 'Credentials' } },
    { id: 'new-alert', detectorId: 'shared-detector', incidentId: '3219', firstActivityDateTime: '2026-08-04T08:00:00Z', lastActivityDateTime: '2026-08-04T08:15:00Z', additionalData: { AlertPolicyTitle: 'Credentials' } },
  ];
  const event = (id, startDateTime) => ({ id, alertCorrelationId: 'shared-detector', startDateTime, endDateTime: new Date(Date.parse(startDateTime) + 15 * 60000).toISOString(), auditRecord: { UserId: 'user@example.com', Workload: 'Exchange', PolicyDetails: [{ Rules: [{ ConditionsMatched: { SensitiveInformation: [{ SensitiveType: 'sit1', SensitiveInformationTypeName: 'All Credential Types', Confidence: 85, SensitiveInformationDetections: { DetectedValues: [{ value: '[REDACTED]' }] } }] } }] }] } });
  await fsp.writeFile(path.join(dataDir, 'dlp-alerts-store.jsonl'), `${alerts.map(JSON.stringify).join('\n')}\n`);
  const explicitEvent = event('explicit-event', '2026-08-04T07:00:00Z'); explicitEvent._dlpResponseStudio = { alertId: 'new-alert' };
  await fsp.writeFile(path.join(dataDir, 'dlp-events-store.jsonl'), `${[event('old-event', '2026-05-05T05:45:00Z'), event('new-event', '2026-08-04T08:00:00Z'), event('unmatched-event', '2026-08-04T07:00:00Z'), explicitEvent].map(JSON.stringify).join('\n')}\n`);
  const result = await queryDlpEvents({ dataDir, maxScanEvents: 100, maxResultRows: 10, maxPlanDetections: 10, detectedValueHandling: 'redact' }, {});
  assert.equal(result.rows.length, 3); assert.deepEqual(result.rows.map((row) => [row.eventId, row.alertId, row.incidentId]), [['old-event', 'old-alert', '111'], ['new-event', 'new-alert', '3219'], ['explicit-event', 'new-alert', '3219']]);
});

test('normalizes declarative response flows and derives scopes', () => {
  const doc = normalizeFlowDocument({ flows: [{ id: 'tag-review', name: 'Tag review', kind: 'remediation', script: 'throw "unsafe"', actions: [{ type: 'incidentPatch', addTags: ['Reviewed'], status: 'inProgress', includeSitTriageComment: true }, { type: 'teamsNotifyAffectedUsers' }] }] });
  assert.equal(doc.flows.length, 1); assert.equal(doc.flows[0].script, undefined);
  assert.equal(doc.flows[0].actions[0].includeSitTriageComment, true);
  assert.deepEqual(doc.flows[0].requiredScopes, ['SecurityIncident.ReadWrite.All', 'Chat.Create', 'ChatMessage.Send', 'User.ReadBasic.All']);
});

test('Detection Assurance triage enriches DLP Response without exposing sensitive artifacts', async () => {
  const dataDir = await fixture(); const triageDir = path.join(dataDir, 'sit-optimize', 'triage'); await fsp.mkdir(triageDir, { recursive: true });
  await fsp.writeFile(path.join(triageDir, 'triage-Cards-20260801_010101.json'), JSON.stringify({ schemaVersion: 2, correlationVersion: 'detector-and-alert-activity-window-v2', generatedAt: '2026-08-01T01:01:01Z', profileId: 'Cards', label: 'Baseline', model: 'test-model', entries: [{ incidentId: '100', priority: 'HIGH', disposition: 'LIVE_CREDENTIAL', validityStatus: 'ACTIVE', evidenceCount: 1, securityComment: 'A credible live credential was identified. Investigate https://secret.example/path and owner@example.com token ABCDEFGHIJKLMNOPQRSTUVWXYZ immediately.', falsePositivePatterns: [{ patternFamily: 'Redirect telemetry https://secret.example/path', triggeringSitRule: 'Auth_Tokens', reasonFalsePositive: 'Correlation value, not owner@example.com.', supportingIndicators: ['Bearer context absent', 'ABCDEFGHIJKLMNOPQRSTUVWX'], suppressionStrategy: 'Exclude approved redirect path.', falseNegativeGuardrail: 'Retain recognized token schemas.', workload: 'Exchange', location: 'Message Body', occurrenceCount: 4, confidence: 'HIGH', bindingBasis: 'analysis-batch-fallback' }] }] }));
  const result = await queryDlpEventsWithTriage({ dataDir, maxScanEvents: 100, maxResultRows: 10, maxPlanDetections: 10, detectedValueHandling: 'redact' }, {}); const triage = result.rows[0].sitTriage; const serialized = JSON.stringify(triage);
  assert.equal(triage.priority, 'HIGH'); assert.equal(triage.disposition, 'LIVE_CREDENTIAL'); assert.equal(triage.requiresHumanReview, true); assert.equal(result.sitTriageSummary.incidentCount, 1);
  assert.match(triage.securityComment, /credible live credential/); assert.match(triage.securityComment, /\[URL redacted\]|\[identity redacted\]|\[sensitive artifact redacted\]/); assert.equal(triage.falsePositivePatterns[0].occurrenceCount, 4); assert.equal(triage.falsePositivePatterns[0].bindingBasis, 'analysis-batch-fallback'); assert.match(triage.falsePositivePatterns[0].suppressionStrategy, /approved redirect path/); assert.doesNotMatch(serialized, /secret\.example|owner@example\.com|ABCDEFGHIJKLMNOPQRSTUVWXYZ|detectedValues/i);
});

test('incident update dry run includes Detection Assurance priority and security comment', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sit-comment-flow-')); const flowsPath = path.join(dir, 'flows.json'); const inputPath = path.join(dir, 'input.json'); const outputPath = path.join(dir, 'output.json');
  await fsp.writeFile(flowsPath, JSON.stringify(normalizeFlowDocument({ flows: [{ id: 'triage-comment', name: 'Triage comment', actions: [{ type: 'incidentPatch', addTags: ['Reviewed'], status: 'inProgress', includeSitTriageComment: true }] }] })));
  await fsp.writeFile(inputPath, JSON.stringify({ flowId: 'triage-comment', mode: 'dryrun', incidentIds: ['100'], parameters: {}, sitTriage: { 100: { priority: 'HIGH', disposition: 'LIVE_CREDENTIAL', validityStatus: 'ACTIVE', securityComment: 'A credible live credential is exposed and requires immediate rotation.', falsePositivePatterns: [{ patternFamily: 'Redirect telemetry', triggeringSitRule: 'Auth_Tokens', reasonFalsePositive: 'Correlation telemetry has no authentication semantics.', suppressionStrategy: 'Use a host-and-path-aware exclusion.', falseNegativeGuardrail: 'Retain bearer and OAuth context.', workload: 'Exchange', location: 'Message Body', occurrenceCount: 4 }], profileId: 'Credentials', assessmentLabel: 'Protected baseline', generatedAt: '2026-08-01T01:01:01Z' } } }));
  const worker = path.resolve(__dirname, '../workers/Invoke-ResponseFlow.ps1'); const result = spawnSync('pwsh', ['-NoProfile', '-File', worker, '-InputPath', inputPath, '-OutputPath', outputPath, '-FlowsPath', flowsPath], { encoding: 'utf8' }); const output = JSON.parse(await fsp.readFile(outputPath, 'utf8'));
  assert.equal(result.status, 0, result.stderr); assert.deepEqual(output.actions.map((action) => action.type), ['incidentPatch', 'incidentComment']); assert.match(output.actions[0].detail, /SIT-AI-Triaged.*SIT-Risk-High/); assert.match(output.actions[1].detail, /Priority: HIGH/); assert.match(output.actions[1].detail, /credible live credential/); assert.match(output.actions[1].detail, /False-positive patterns supporting Purview remediation/); assert.match(output.actions[1].detail, /host-and-path-aware exclusion/); assert.match(output.actions[1].detail, /human review required/);
  await fsp.writeFile(inputPath, JSON.stringify({ flowId: 'triage-comment', mode: 'dryrun', incidentIds: ['101'], parameters: {}, sitTriage: {} }));
  const withoutTriage = spawnSync('pwsh', ['-NoProfile', '-File', worker, '-InputPath', inputPath, '-OutputPath', outputPath, '-FlowsPath', flowsPath], { encoding: 'utf8' }); const withoutTriageOutput = JSON.parse(await fsp.readFile(outputPath, 'utf8'));
  assert.equal(withoutTriage.status, 0, withoutTriage.stderr); assert.deepEqual(withoutTriageOutput.actions.map(({ type, status }) => ({ type, status })), [{ type: 'incidentPatch', status: 'planned' }, { type: 'incidentComment', status: 'skipped' }]);
});

test('Teams notification worker dry-runs without Graph and bounds recipients', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'teams-flow-')); const flowsPath = path.join(dir, 'flows.json'); const inputPath = path.join(dir, 'input.json'); const outputPath = path.join(dir, 'output.json');
  const doc = normalizeFlowDocument({ flows: [{ id: 'notify-teams', name: 'Notify in Teams', actions: [{ type: 'teamsNotifyAffectedUsers' }] }] });
  await fsp.writeFile(flowsPath, JSON.stringify(doc)); await fsp.writeFile(inputPath, JSON.stringify({ flowId: 'notify-teams', mode: 'dryrun', incidentIds: [], parameters: { impactedUsers: 'first@example.com;second@example.com', teamsMessage: 'Review the DLP activity. <No values>' } }));
  const worker = path.resolve(__dirname, '../workers/Invoke-ResponseFlow.ps1'); const result = spawnSync('pwsh', ['-NoProfile', '-File', worker, '-InputPath', inputPath, '-OutputPath', outputPath, '-FlowsPath', flowsPath], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr); const output = JSON.parse(await fsp.readFile(outputPath, 'utf8')); assert.equal(output.mode, 'dryrun'); assert.deepEqual(output.actions.map(({ type, target, status }) => ({ type, target, status })), [{ type: 'teamsNotification', target: 'first@example.com', status: 'planned' }, { type: 'teamsNotification', target: 'second@example.com', status: 'planned' }]);
  await fsp.writeFile(inputPath, JSON.stringify({ flowId: 'notify-teams', mode: 'dryrun', incidentIds: [], parameters: { teamsRecipients: 'only@example.com', teamsMessage: 'Reviewed notification.' } }));
  const single = spawnSync('pwsh', ['-NoProfile', '-File', worker, '-InputPath', inputPath, '-OutputPath', outputPath, '-FlowsPath', flowsPath], { encoding: 'utf8' }); const singleOutput = JSON.parse(await fsp.readFile(outputPath, 'utf8'));
  assert.equal(single.status, 0, single.stderr); assert.equal(singleOutput.actions.length, 1); assert.equal(singleOutput.actions[0].target, 'only@example.com');
  await fsp.writeFile(inputPath, JSON.stringify({ flowId: 'notify-teams', mode: 'dryrun', incidentIds: [], parameters: { teamsRecipients: 'not-a-user-principal-name', teamsMessage: 'Reviewed notification.' } }));
  const invalid = spawnSync('pwsh', ['-NoProfile', '-File', worker, '-InputPath', inputPath, '-OutputPath', outputPath, '-FlowsPath', flowsPath], { encoding: 'utf8' }); const invalidOutput = JSON.parse(await fsp.readFile(outputPath, 'utf8'));
  assert.equal(invalid.status, 2, invalid.stderr); assert.equal(invalidOutput.actions[0].status, 'error'); assert.match(invalidOutput.actions[0].detail, /user principal name/);
});

test('rejects unsupported response actions', () => {
  assert.throws(() => normalizeFlowDocument({ flows: [{ id: 'unsafe-flow', actions: [{ type: 'runScript' }] }] }), /Unsupported declarative action/);
});

test('extracts AI Helper text and JSON from Azure Responses shape', () => {
  const text = extractResponseText({ output: [{ content: [{ type: 'output_text', text: '{"flow":{"id":"safe-flow"}}' }] }] });
  assert.equal(JSON.parse(extractJson(text)).flow.id, 'safe-flow');
});

test('saves Foundry paths and model routing without accepting secrets', async () => {
  const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'foundry-config-'));
  await fsp.mkdir(path.join(rootDir, 'config'));
  await fsp.writeFile(path.join(rootDir, 'config', 'settings.json'), JSON.stringify({ sitOptimize: { enabled: true }, ai: { enabled: true } }));
  const config = { rootDir, ai: { endpoint: '', model: '', apiKey: 'runtime-only' }, sitOptimize: { analysisModel: '' } };
  assert.equal(normalizeEndpoint('https://example.services.ai.azure.com'), 'https://example.services.ai.azure.com/openai/v1/responses');
  const result = await saveFoundryConfiguration(config, { endpoint: 'https://example.services.ai.azure.com/openai/v1', reportModel: 'gpt-report', analysisModel: 'gpt-5.6-luna' });
  const persisted = JSON.parse(await fsp.readFile(path.join(rootDir, 'config', 'settings.json'), 'utf8'));
  assert.equal(result.restartRequired, true); assert.equal(result.secret.configured, true); assert.equal(result.secret.persistedByStudio, false);
  assert.equal(persisted.ai.endpoint, 'https://example.services.ai.azure.com/openai/v1/responses'); assert.equal(persisted.ai.model, 'gpt-report'); assert.equal(persisted.sitOptimize.analysisModel, 'gpt-5.6-luna'); assert.equal(persisted.ai.apiKey, undefined);
  await assert.rejects(saveFoundryConfiguration(config, { endpoint: 'https://example.services.ai.azure.com', reportModel: 'gpt-report', analysisModel: 'gpt-5.6-luna', apiKey: 'must-not-save' }), /Secrets are never accepted/);
  assert.throws(() => normalizeEndpoint('https://attacker.example/openai/v1/responses'), /Microsoft Foundry/);
});

test('generates guarded PowerShell integration scripts', () => {
  const cases = [
    ['slack', 'DLP_SLACK_WEBHOOK_URL'],
    ['servicenow', 'DLP_SERVICENOW_TOKEN'],
    ['webhook', 'DLP_WEBHOOK_URL'],
  ];
  for (const [provider, environmentName] of cases) {
    const result = generateIntegration({ provider, name: `${provider} DLP sync`, studioUrl: 'http://127.0.0.1:3100', lookbackHours: 48 });
    assert.equal(result.ok, true); assert.match(result.fileName, /\.ps1$/); assert.match(result.code, /Set-StrictMode -Version Latest/);
    assert.match(result.code, new RegExp(environmentName)); assert.match(result.code, /\$DryRun/); assert.match(result.code, /lastSuccessfulSyncUtc/);
    assert.doesNotMatch(result.code, /DetectedValues|detectedValues/); assert.doesNotMatch(result.code, /\.user\b|\.sender\b|\.recipients\b|\.contentName\b/);
    assert.match(result.sha256, /^[a-f0-9]{64}$/);
  }
});

test('integration generator rejects non-loopback Studio URLs and embedded credentials', () => {
  assert.throws(() => normalizeSpec({ provider: 'slack', studioUrl: 'https://studio.example.com' }), /loopback/);
  assert.throws(() => normalizeSpec({ provider: 'slack', studioUrl: 'http://user:secret@127.0.0.1:3100' }), /only scheme/);
});

test('Detection Assurance discovers data-only profiles and summarizes the shared DLP store', async () => {
  const dataDir = await fixture(); const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sit-root-')); const profileDir = path.join(rootDir, 'profiles'); await fsp.mkdir(profileDir);
  await fsp.writeFile(path.join(dataDir, 'user-directory.json'), JSON.stringify({ 'user@example.com': { department: 'Finance', displayName: 'Example User', mail: 'user@example.com' } }));
  const eventFile = path.join(dataDir, 'dlp-events-store.jsonl'); const mixedEvent = JSON.parse((await fsp.readFile(eventFile, 'utf8')).trim());
  mixedEvent.auditRecord.PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation.push({ SensitiveType: 'sit2', SensitiveInformationTypeName: 'Unrelated Identity', SensitiveInformationDetections: { DetectedValues: [{ value: 'other' }] } });
  await fsp.writeFile(eventFile, `${JSON.stringify(mixedEvent)}\n`);
  await fsp.writeFile(path.join(profileDir, 'Cards.psd1'), "@{\nName = 'Cards'\nDescription = 'Payment card tuning.'\nDlpPolicy = '*Protect*'\nFindingNoun = 'card number'\nAnalysisFocus = @'\nOriginal focus\n  '@\nSensitiveInformationTypeIds = @('sit1')\nSensitiveInformationTypeNames = @('Source Code')\nExtractionInstruction = @'\nPRESERVE THIS PROMPT\n  '@\nConsolidationInstruction = @'\nPRESERVE CONSOLIDATION\n  '@\nReportMergeInstruction = @'\nPRESERVE MERGE\n  '@\n}\n");
  const config = { dataDir, rootDir, sitOptimize: { root: '.', enabled: true } };
  const profiles = await sitOptimize.loadProfiles(config); const summary = await sitOptimize.summarizeSharedStore(config); const scope = await sitOptimize.scopeProfile(config, 'Cards'); const catalog = await sitOptimize.buildSitCatalog(config);
  assert.equal(profiles.ok, true); assert.equal(profiles.profiles[0].dlpPolicy, '*Protect*'); assert.equal(profiles.profiles[0].findingNoun, 'card number'); assert.equal(profiles.profiles[0].analysisFocus, 'Original focus');
  assert.equal(summary.ok, true); assert.equal(summary.alerts, 1); assert.equal(summary.events, 1); assert.equal(summary.detections, 2); assert.equal(summary.rawValues, 2); assert.deepEqual(summary.directoryEnrichment, { cacheEntries: 1, resolvedUsers: 1, departmentCount: 1, departments: ['Finance'] });
  assert.deepEqual({ alerts: scope.alerts, events: scope.events, detections: scope.detections, canAnalyze: scope.canAnalyze }, { alerts: 1, events: 1, detections: 1, canAnalyze: true }); assert.deepEqual(scope.departmentContext, { resolvedUsers: 1, departmentCount: 1, departments: ['Finance'], detectionsWithDepartment: 1, unresolvedDetections: 0 });
  const firstDay = await sitOptimize.scopeProfile(config, 'Cards', '2026-08-01', '2026-08-01'); const nextDay = await sitOptimize.scopeProfile(config, 'Cards', '2026-08-02', '2026-08-02');
  assert.deepEqual({ events: firstDay.events, detections: firstDay.detections, period: firstDay.analysisPeriod }, { events: 1, detections: 1, period: { startDate: '2026-08-01', endDate: '2026-08-01', durationDays: 1, label: '2026-08-01 through 2026-08-01' } }); assert.equal(nextDay.events, 0);
  await assert.rejects(() => sitOptimize.scopeProfile(config, 'Cards', '2026-08-01', ''), /both a start date and an end date/);
  assert.deepEqual(catalog.sensitiveInformationTypes.map((item) => item.id).sort(), ['sit1', 'sit2']);
  const reviewedInstructions = { extractionInstruction: 'credential_summary noise_patterns validated_credentials credential_pairs low_frequency_patterns regex_refinements multi_encoded_artifacts workload_context exclusion_rules recommendations $&', consolidationInstruction: 'Reviewed consolidation', reportMergeInstruction: 'Reviewed merge' };
  const saved = await sitOptimize.saveProfile(config, { id: 'CardsClone', sourceId: 'Cards', description: 'Cloned.', analysisFocus: 'Operator focus $&', dlpPolicy: '*', findingNoun: 'card', sitIds: ['sit1'], instructions: reviewedInstructions });
  const savedText = await fsp.readFile(path.join(profileDir, 'CardsClone.psd1'), 'utf8'); assert.equal(saved.profile.id, 'CardsClone'); assert.match(savedText, /Operator focus \$&/); assert.match(savedText, /recommendations \$&/); assert.match(savedText, /SensitiveInformationTypeIds\s*=\s*@\('sit1'\)/); assert.doesNotMatch(savedText, /sit2/);
  const imported = spawnSync('pwsh', ['-NoProfile', '-Command', `$p=Import-PowerShellDataFile '${path.join(profileDir, 'CardsClone.psd1').replace(/'/g, "''")}'; [ordered]@{focus=$p.AnalysisFocus; extraction=$p.ContainsKey('ExtractionInstruction'); consolidation=$p.ContainsKey('ConsolidationInstruction'); merge=$p.ContainsKey('ReportMergeInstruction')} | ConvertTo-Json -Compress`], { encoding: 'utf8' });
  assert.equal(imported.status, 0, imported.stderr); assert.deepEqual(JSON.parse(imported.stdout.trim()), { focus: 'Operator focus $&', extraction: true, consolidation: true, merge: true });
  const worker = path.resolve(__dirname, '../sit-optimize/credpattern.ps1'); const workerText = await fsp.readFile(worker, 'utf8'); assert.match(workerText, /MANDATORY INCIDENT TRIAGE OUTPUT/); assert.match(workerText, /MANDATORY CORRELATION ENVELOPE/); assert.match(workerText, /DEPARTMENT TUNING CONTEXT/); assert.match(workerText, /Department\s+=\s+\$resolvedDepartment/); assert.match(workerText, /EvidenceRef\s+=\s+\('DLPREF-/); assert.match(workerText, /evidence_bindings/); assert.match(workerText, /ChunkIncidentIds/); assert.match(workerText, /analysis-batch-fallback/); assert.match(workerText, /priority.*HIGH\|MEDIUM\|LOW/); assert.match(workerText, /security_comment/); assert.match(workerText, /cannot be removed, renamed, or weakened by later instructions/); assert.match(workerText, /expectedIncidents\.ContainsKey\(\$incidentId\)/); assert.match(workerText, /model omitted incident-specific triage/i);
  const workerResult = spawnSync('pwsh', ['-NoProfile', '-File', worker, '-ProfilePath', path.join(profileDir, 'CardsClone.psd1'), '-SkipCollection', '-EventStorePath', path.join(dataDir, 'dlp-events-store.jsonl'), '-AlertStorePath', path.join(dataDir, 'dlp-alerts-store.jsonl'), '-UserDirectoryPath', path.join(dataDir, 'user-directory.json'), '-AnalysisStartDate', '2026-08-02', '-AnalysisEndDate', '2026-08-02', '-OpenAIEndpoint', 'https://example.invalid', '-AnalysisModel', 'gpt-5.6-luna', '-Model', 'test-terra'], { encoding: 'utf8', env: { ...process.env, AZURE_OPENAI_API_KEY2: 'dry-run-no-network' } });
  assert.equal(workerResult.status, 0, workerResult.stderr); assert.match(workerResult.stdout, /chunk analysis and incident triage=gpt-5\.6-luna; report consolidation=test-terra/); assert.match(workerResult.stdout, /Assessment period: 2026-08-02 through 2026-08-02/); assert.match(workerResult.stdout, /Loaded 1 Graph-resolved user department mapping/); assert.match(workerResult.stdout, /No matches found/);
  assert.equal(Object.hasOwn(summary, 'values'), false);
});

test('AI profile authoring receives operator focus and SIT metadata but no synchronized event values', async () => {
  const dataDir = await fixture(); let requestBody = ''; const originalFetch = global.fetch;
  const required = 'credential_summary noise_patterns validated_credentials credential_pairs low_frequency_patterns regex_refinements multi_encoded_artifacts workload_context exclusion_rules recommendations';
  global.fetch = async (url, options) => { requestBody = options.body; return { ok: true, json: async () => ({ output: [{ content: [{ text: JSON.stringify({ name: 'SourceCodeReview', description: 'Review source code noise.', analysisFocus: 'Prioritize test fixtures and preserve validated findings.', dlpPolicy: '*Protect*', findingNoun: 'finding', extractionInstruction: required, consolidationInstruction: 'Create a Markdown noise-reduction report.', reportMergeInstruction: 'Merge reports without duplication.' }) }] }] }) }; };
  try {
    const result = await sitOptimize.draftProfile({ dataDir, ai: { enabled: true, apiKey: 'not-returned', endpoint: 'https://example.invalid', model: 'test-model' } }, { id: 'Cards', description: 'Current.', analysisFocus: 'Known test fixtures are key; require validation context.', dlpPolicy: '*', findingNoun: 'finding', sitIds: ['sit1'] });
    assert.equal(result.draft.sitIds[0], 'sit1'); assert.match(result.draft.analysisFocus, /test fixtures/); assert.match(requestBody, /Known test fixtures are key/); assert.doesNotMatch(requestBody, /"secret"|User@Example\.com/); assert.doesNotMatch(JSON.stringify(result), /not-returned/);
  } finally { global.fetch = originalFetch; }
});

test('Detection Assurance fails closed when a profile has no explicit SIT allow-list', async () => {
  const dataDir = await fixture(); const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sit-closed-')); const profileDir = path.join(rootDir, 'profiles'); await fsp.mkdir(profileDir);
  await fsp.writeFile(path.join(profileDir, 'Unscoped.psd1'), "@{\nName='Unscoped'\nDlpPolicy='*Protect*'\nFindingNoun='finding'\n}\n");
  await assert.rejects(() => sitOptimize.scopeProfile({ dataDir, rootDir, sitOptimize: { root: '.' } }, 'Unscoped'), /no explicit SensitiveInformationTypeIds/);
});

test('SIT reporting compares aggregate categories without returning chunk patterns', async () => {
  const dataDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sit-reporting-')); const runDir = path.join(dataDir, 'sit-optimize', 'Cards', 'runs'); await fsp.mkdir(runDir, { recursive: true });
  const analysis = (noise, validated) => ({ noise_patterns: [{ pattern: '4111111111111111', triggering_sit_rule: 'Credit Card Number', source_workload: 'Exchange', occurrence_count: noise, estimated_fp_reduction: 50 }], validated_credentials: [{ pattern: 'secret-value-must-not-return', risk_level: 'HIGH', count: validated }], credential_pairs: [{ count: 1 }] });
  const baselineFile = 'run-20260801_010101.json'; const currentFile = 'run-20260802_010101.json';
  await fsp.writeFile(path.join(runDir, baselineFile), JSON.stringify({ profile: 'Cards', dlpPolicy: '*', label: 'Baseline', generatedAt: '2026-08-01T01:01:01Z', analysisStartDate: '2026-07-01', analysisEndDate: '2026-07-07', analysisDurationDays: 7, finalReport: '# Baseline', chunkAnalyses: [{ analysis_result: analysis(10, 2) }] }));
  await fsp.writeFile(path.join(runDir, currentFile), JSON.stringify({ profile: 'Cards', dlpPolicy: '*', label: 'Current', generatedAt: '2026-08-02T01:01:01Z', analysisStartDate: '2026-07-08', analysisEndDate: '2026-07-14', analysisDurationDays: 7, finalReport: '# Current', chunkAnalyses: [{ analysis_result: analysis(4, 2) }] }));
  const result = await sitOptimize.compareRuns({ dataDir }, 'Cards', baselineFile, currentFile); const serialized = JSON.stringify(result);
  assert.equal(result.delta.metrics.noiseOccurrences, -6); assert.equal(result.delta.byRule[0].name, 'Credit Card Number'); assert.equal(result.delta.byRule[0].status, 'reduced'); assert.match(result.delta.byPattern[0].name, /^Noise pattern [a-f0-9]{10}$/); assert.doesNotMatch(serialized, /4111111111111111|secret-value-must-not-return|chunkAnalyses/);
  assert.deepEqual(result.comparability, { hasPeriods: true, overlaps: false, sameDuration: true, warning: '' }); assert.equal(result.baseline.analysisStartDate, '2026-07-01'); assert.equal(result.current.analysisEndDate, '2026-07-14');
  const overlapFile = 'run-20260803_010101.json'; const unequalFile = 'run-20260804_010101.json'; const legacyFile = 'run-20260805_010101.json';
  await fsp.writeFile(path.join(runDir, overlapFile), JSON.stringify({ profile: 'Cards', analysisStartDate: '2026-07-05', analysisEndDate: '2026-07-11', analysisDurationDays: 7, chunkAnalyses: [] }));
  await fsp.writeFile(path.join(runDir, unequalFile), JSON.stringify({ profile: 'Cards', analysisStartDate: '2026-07-15', analysisEndDate: '2026-07-17', analysisDurationDays: 3, chunkAnalyses: [] }));
  await fsp.writeFile(path.join(runDir, legacyFile), JSON.stringify({ profile: 'Cards', chunkAnalyses: [] }));
  const overlap = await sitOptimize.compareRuns({ dataDir }, 'Cards', baselineFile, overlapFile); assert.equal(overlap.comparability.overlaps, true); assert.match(overlap.comparability.warning, /overlap/i);
  const unequal = await sitOptimize.compareRuns({ dataDir }, 'Cards', currentFile, unequalFile); assert.equal(unequal.comparability.sameDuration, false); assert.match(unequal.comparability.warning, /different durations/i);
  const legacy = await sitOptimize.compareRuns({ dataDir }, 'Cards', baselineFile, legacyFile); assert.equal(legacy.comparability.hasPeriods, false); assert.match(legacy.comparability.warning, /predate period metadata/i);

  const implementationDir = path.join(dataDir, 'sit-optimize', 'Cards', 'implementation'); await fsp.mkdir(implementationDir); await fsp.writeFile(path.join(implementationDir, 'run-20260802_010101.md'), '# Cached implementation plan');
  const guide = await sitOptimize.getImplementationGuide({ dataDir, ai: {} }, { profileId: 'Cards', file: currentFile }); assert.equal(guide.cached, true); assert.equal(guide.analysisStartDate, '2026-07-08'); assert.equal(guide.analysisDurationDays, 7); assert.match(guide.markdown, /Cached implementation plan/);
  const protectedFile = 'run-20260806_010101.json'; const exactFalsePositive = 'https://approved-redirect.example/path?destination=feedback';
  await fsp.writeFile(path.join(runDir, protectedFile), JSON.stringify({ profile: 'Cards', privacyMode: 'protected-sensitive-content', finalReport: `# Protected report\n\nProtected false-positive evidence: ${exactFalsePositive}`, chunkAnalyses: [{ analysis_result: { noise_patterns: [{ pattern: exactFalsePositive, triggering_sit_rule: 'Auth_Tokens', reason_false_positive: 'Approved redirect telemetry without authentication context.', occurrence_count: 8, source_workload: 'Exchange', noise_signal_keywords: ['redirect', 'feedback'], suppression_strategy: 'Require the approved host and path together.', estimated_fp_reduction: 80 }] } }] }));
  const protectedConfig = { dataDir, ai: { enabled: true, apiKey: 'test-key', endpoint: 'https://example.invalid/openai/v1/responses', model: 'test-report-model' }, sitOptimize: {} }; let protectedRequest = ''; const originalFetch = global.fetch;
  global.fetch = async (url, options) => { protectedRequest = options.body; return { ok: true, json: async () => ({ output: [{ content: [{ text: '# Protected Purview DLP Implementation Plan' }] }] }) }; };
  try { const protectedGuide = await sitOptimize.getImplementationGuide(protectedConfig, { profileId: 'Cards', file: protectedFile }); assert.equal(protectedGuide.sensitiveDetailsIncluded, true); assert.equal(protectedGuide.cached, false); assert.match(protectedRequest, /approved-redirect\.example/); assert.match(protectedRequest, /Step 2 already performed/); } finally { global.fetch = originalFetch; }
  assert.equal(await fsp.stat(path.join(implementationDir, 'run-20260806_010101.md')).then(() => true).catch(() => false), false);
});

test('PowerShell SIT scope helper excludes unrelated SITs in the same event', () => {
  const helper = path.resolve(__dirname, '../sit-optimize/SitScopeHelpers.ps1').replace(/'/g, "''");
  const command = `. '${helper}'; $scope = New-SitAnalysisScope -Ids @('sit-card') -Names @('Credit Card Number'); $items = @([pscustomobject]@{SensitiveType='sit-card';SensitiveInformationTypeName='Credit Card Number'},[pscustomobject]@{SensitiveType='sit-other';SensitiveInformationTypeName='Unrelated Identity'}); @($items | Where-Object { Test-SensitiveInformationInScope -SensitiveInformation $_ -Scope $scope }).SensitiveType | ConvertTo-Json -Compress`;
  const result = spawnSync('pwsh', ['-NoProfile', '-Command', command], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr); assert.equal(result.stdout.trim(), '"sit-card"');
});

test('Detection Assurance rejects unsafe report identifiers', async () => {
  await assert.rejects(() => sitOptimize.loadReport({ dataDir: os.tmpdir() }, '../profile', 'run-20260101_000000.json'), /Invalid profile/);
});

test('SIT activity reports real chunk progress and reconciles dead workers', async () => {
  const progress = sitOptimize.parseJobProgress('Created 8 chunk(s) for analysis.\nQueueing chunk 8/8\nCompleted chunk 1/8.\nCompleted chunk 3/8.', 'running');
  assert.equal(progress.totalChunks, 8); assert.equal(progress.completedChunks, 3); assert.equal(progress.percent, 32); assert.match(progress.stage, /3\/8 complete/);
  const dataDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sit-stale-job-')); const jobDir = path.join(dataDir, 'sit-optimize', 'jobs'); await fsp.mkdir(jobDir, { recursive: true });
  const job = { id: 'stale-job', profile: 'Credentials', status: 'running', pid: 2147483647, logFile: 'stale-job.log', startedUtc: '2026-08-07T08:00:00Z' };
  await fsp.writeFile(path.join(jobDir, 'stale-job.json'), JSON.stringify(job)); await fsp.writeFile(path.join(jobDir, 'stale-job.log'), 'Analysis profile: Credentials\n');
  const listed = await sitOptimize.listJobs({ dataDir }); const persisted = JSON.parse(await fsp.readFile(path.join(jobDir, 'stale-job.json'), 'utf8'));
  assert.equal(listed.jobs[0].status, 'failed'); assert.equal(listed.jobs[0].workerAlive, false); assert.match(listed.jobs[0].error, /no longer running/); assert.equal(persisted.status, 'failed');
});

test('protected SIT evidence requires exact capture and analysis confirmations', async () => {
  const dataDir = await fixture(); const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sit-protected-')); const profileDir = path.join(rootDir, 'profiles'); await fsp.mkdir(profileDir); await fsp.writeFile(path.join(profileDir, 'Cards.psd1'), "@{\nName='Cards'\nDlpPolicy='*Protect*'\nFindingNoun='card'\nSensitiveInformationTypeIds=@('sit1')\nSensitiveInformationTypeNames=@('Source Code')\n}\n");
  await fsp.mkdir(path.join(dataDir, 'protected')); await fsp.writeFile(path.join(dataDir, 'protected', 'sit-sensitive-events.jsonl'), '{"id":"encrypted-1","protection":"DPAPI-CurrentUser","ciphertext":"not-returned"}\n');
  const sensitiveContent = { enabled: true, retentionDays: 30, captureConfirmationPhrase: 'CAPTURE TEST CONTENT', analysisConfirmationPhrase: 'ANALYZE TEST CONTENT' };
  const config = { dataDir, rootDir, powershellExecutable: 'pwsh', collectorLookbackDays: 90, ai: { apiKey: 'test', endpoint: 'https://example.invalid', model: 'test' }, sitOptimize: { root: '.', enabled: true, sensitiveContent } };
  const summary = await sitOptimize.summarizeSharedStore(config); assert.equal(summary.protectedEvidence.ready, true); assert.equal(summary.protectedEvidence.eventCount, 1); assert.equal(Object.hasOwn(summary.protectedEvidence, 'ciphertext'), false);
  const capture = await collect(config, { captureSensitiveContent: true, confirmation: 'wrong' }); assert.equal(capture.ok, false); assert.match(capture.error, /confirmation phrase/);
  await assert.rejects(() => sitOptimize.startAnalysis(config, { profileId: 'Cards', sensitiveContent: true, confirmation: 'wrong' }), /confirmation phrase/);
});
