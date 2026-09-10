'use strict';

const http = require('node:http');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { loadConfig } = require('./config');
const aiHelper = require('./ai-helper');
const foundryConfiguration = require('./foundry-configuration');
const integrationGenerator = require('./integration-generator');
const sitOptimize = require('./sit-optimize');
const services = require('./services');

const config = loadConfig();
const publicDir = path.join(config.rootDir, 'public');
const MAX_BODY = 1024 * 1024;
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json; charset=utf-8' };

function sendJson(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, { 'Content-Type': MIME['.json'], 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store' }); res.end(body);
}

async function bodyJson(req) {
  const chunks = []; let total = 0;
  for await (const chunk of req) { total += chunk.length; if (total > MAX_BODY) throw Object.assign(new Error('Request body too large.'), { statusCode: 413 }); chunks.push(chunk); }
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw Object.assign(new Error('Invalid JSON body.'), { statusCode: 400 }); }
}

async function staticFile(reqPath, res) {
  const requested = reqPath === '/' ? '/start.html' : reqPath;
  const file = path.resolve(publicDir, `.${requested}`);
  if (file !== publicDir && !file.startsWith(`${publicDir}${path.sep}`)) return false;
  try {
    const content = await fsp.readFile(file); const ext = path.extname(file).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Content-Length': content.length, 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'" }); res.end(content); return true;
  } catch { return false; }
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (url.pathname === '/api/health' && req.method === 'GET') return sendJson(res, 200, { ok: true, service: 'DLP Response Studio', liveApplyEnabled: config.liveApplyEnabled, ai: { enabled: config.ai.enabled, configured: Boolean(config.ai.apiKey && config.ai.endpoint), model: config.ai.model }, sitOptimize: { enabled: config.sitOptimize.enabled, analysisModel: config.sitOptimize.analysisModel } });
    if (url.pathname === '/api/configuration/foundry' && req.method === 'GET') return sendJson(res, 200, await foundryConfiguration.getFoundryConfiguration(config));
    if (url.pathname === '/api/configuration/foundry' && req.method === 'PUT') return sendJson(res, 200, await foundryConfiguration.saveFoundryConfiguration(config, await bodyJson(req)));
    if (url.pathname === '/api/dlp/query' && req.method === 'POST') return sendJson(res, 200, await services.queryDlpEventsWithTriage(config, await bodyJson(req)));
    if (url.pathname === '/api/dlp/collect' && req.method === 'POST') return sendJson(res, 200, await services.collect(config, await bodyJson(req)));
    if (url.pathname === '/api/dlp/enrich-departments' && req.method === 'POST') return sendJson(res, 200, await services.enrichDepartments(config, await bodyJson(req)));
    if (url.pathname === '/api/remediation/plan' && req.method === 'POST') return sendJson(res, 200, await services.createPlan(config, await bodyJson(req)));
    if (url.pathname === '/api/remediation/apply' && req.method === 'POST') return sendJson(res, 200, await services.applyPlan(config, await bodyJson(req)));
    if (url.pathname === '/api/flows' && req.method === 'GET') return sendJson(res, 200, { ok: true, doc: await services.loadFlows(config) });
    if (url.pathname === '/api/flows/run' && req.method === 'POST') return sendJson(res, 200, await services.runFlow(config, await bodyJson(req)));
    if (url.pathname === '/api/response-flows' && req.method === 'GET') return sendJson(res, 200, { ok: true, doc: await services.loadFlows(config) });
    if (url.pathname === '/api/response-flows' && req.method === 'PUT') return sendJson(res, 200, await services.saveFlows(config, await bodyJson(req)));
    if (url.pathname === '/api/response-flows/import' && req.method === 'POST') return sendJson(res, 200, await services.importFlows(config, await bodyJson(req)));
    if (url.pathname === '/api/response-flows/versions' && req.method === 'GET') return sendJson(res, 200, await services.listFlowVersions(config));
    if (url.pathname === '/api/response-flows/incidents' && req.method === 'GET') return sendJson(res, 200, await services.listFlowIncidents(config));
    if (url.pathname === '/api/sit/summary' && req.method === 'GET') return sendJson(res, 200, await sitOptimize.summarizeSharedStore(config));
    if (url.pathname === '/api/sit/catalog' && req.method === 'GET') return sendJson(res, 200, await sitOptimize.buildSitCatalog(config));
    if (url.pathname === '/api/sit/profiles' && req.method === 'GET') return sendJson(res, 200, await sitOptimize.loadProfiles(config));
    if (url.pathname === '/api/sit/profile' && req.method === 'GET') return sendJson(res, 200, await sitOptimize.loadProfile(config, url.searchParams.get('profileId')));
    if (url.pathname === '/api/sit/profile' && req.method === 'PUT') return sendJson(res, 200, await sitOptimize.saveProfile(config, await bodyJson(req)));
    if (url.pathname === '/api/sit/profile/draft' && req.method === 'POST') {
      const result = await sitOptimize.draftProfile(config, await bodyJson(req));
      await services.record(config, { type: 'sit-profile-ai-draft', profileId: result.draft.id, sitCount: result.draft.sitIds.length, model: result.model });
      return sendJson(res, 200, result);
    }
    if (url.pathname === '/api/sit/scope' && req.method === 'GET') return sendJson(res, 200, await sitOptimize.scopeProfile(config, url.searchParams.get('profileId'), url.searchParams.get('analysisStartDate'), url.searchParams.get('analysisEndDate')));
    if (url.pathname === '/api/sit/runs' && req.method === 'GET') return sendJson(res, 200, await sitOptimize.listRuns(config, url.searchParams.get('profileId') || ''));
    if (url.pathname === '/api/sit/report' && req.method === 'GET') return sendJson(res, 200, await sitOptimize.loadReport(config, url.searchParams.get('profileId'), url.searchParams.get('file')));
    if (url.pathname === '/api/sit/compare' && req.method === 'POST') {
      const body = await bodyJson(req);
      return sendJson(res, 200, await sitOptimize.compareRuns(config, body.profileId, body.baselineFile, body.currentFile));
    }
    if (url.pathname === '/api/sit/implementation' && req.method === 'POST') {
      const body = await bodyJson(req); const result = await sitOptimize.getImplementationGuide(config, body);
      await services.record(config, { type: 'sit-implementation-guide', profileId: body.profileId, runFile: body.file, cached: result.cached });
      return sendJson(res, 200, result);
    }
    if (url.pathname === '/api/sit/jobs' && req.method === 'GET') return sendJson(res, 200, await sitOptimize.listJobs(config));
    if (url.pathname === '/api/sit/capture' && req.method === 'POST') {
      const body = await bodyJson(req);
      return sendJson(res, 200, await services.collect(config, { fullPull: true, maxEvents: body.maxEvents, captureSensitiveContent: true, confirmation: body.confirmation }));
    }
    if (url.pathname === '/api/sit/analyze' && req.method === 'POST') {
      const result = await sitOptimize.startAnalysis(config, await bodyJson(req));
      await services.record(config, { type: 'sit-analysis-started', jobId: result.job.id, profileId: result.job.profileId, privacyMode: result.job.privacyMode, source: result.job.source });
      return sendJson(res, 202, result);
    }
    if (url.pathname === '/api/response-flows/ai-helper' && req.method === 'POST') {
      const result = await aiHelper.generateFlow(config, await bodyJson(req), services.normalizeFlowDocument, await services.loadFlows(config));
      await services.record(config, { type: 'ai-helper-draft', flowId: result.flow.id, model: result.model });
      return sendJson(res, 200, result);
    }
    if (url.pathname === '/api/response-flows/integration-code' && req.method === 'POST') {
      const result = integrationGenerator.generateIntegration(await bodyJson(req));
      await services.record(config, { type: 'integration-code-generated', provider: result.spec.provider, fileName: result.fileName, sha256: result.sha256 });
      return sendJson(res, 200, result);
    }
    const restoreMatch = url.pathname.match(/^\/api\/response-flows\/versions\/([a-zA-Z0-9._-]+)\/restore$/);
    if (restoreMatch && req.method === 'POST') return sendJson(res, 200, await services.restoreFlowVersion(config, restoreMatch[1]));
    if (url.pathname === '/api/jobs' && req.method === 'GET') return sendJson(res, 200, await services.listJobs(config));
    if (url.pathname === '/api/jobs' && req.method === 'POST') return sendJson(res, 200, await services.saveJob(config, await bodyJson(req)));
    if (url.pathname === '/api/jobs/delete' && req.method === 'POST') return sendJson(res, 200, await services.deleteJob(config, await bodyJson(req)));
    if (req.method === 'GET' && await staticFile(url.pathname, res)) return;
    sendJson(res, 404, { ok: false, error: 'Not found.' });
  } catch (error) {
    console.error(error); sendJson(res, error.statusCode || 500, { ok: false, error: error.statusCode ? error.message : 'Internal server error.' });
  }
});

server.listen(config.port, config.host, () => console.log(`DLP Response Studio listening on http://${config.host}:${config.port}`));
