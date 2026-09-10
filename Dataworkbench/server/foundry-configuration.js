'use strict';

const fsp = require('node:fs/promises');
const path = require('node:path');

const SECRET_VARIABLE = 'AZURE_OPENAI_REPORTING_KEY';
const MODEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function badRequest(message) {
  return Object.assign(new Error(message), { statusCode: 400 });
}

function normalizeEndpoint(value) {
  const input = String(value || '').trim();
  if (!input || input.length > 2048) throw badRequest('Enter a Microsoft Foundry Responses endpoint.');
  let parsed;
  try { parsed = new URL(input); } catch { throw badRequest('The Foundry endpoint must be a valid HTTPS URL.'); }
  const host = parsed.hostname.toLowerCase();
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash) throw badRequest('The Foundry endpoint must use HTTPS and cannot contain credentials, query parameters, or fragments.');
  if (!(host.endsWith('.services.ai.azure.com') || host.endsWith('.openai.azure.com'))) throw badRequest('Use a Microsoft Foundry or Azure OpenAI endpoint hosted on services.ai.azure.com or openai.azure.com.');
  let pathname = parsed.pathname.replace(/\/+$/, '');
  if (!pathname) pathname = '/openai/v1/responses';
  else if (pathname === '/openai/v1') pathname += '/responses';
  if (pathname !== '/openai/v1/responses') throw badRequest('The endpoint path must end with /openai/v1/responses.');
  parsed.pathname = pathname;
  return parsed.toString().replace(/\/$/, '');
}

function normalizeModel(value, label) {
  const model = String(value || '').trim();
  if (!MODEL_PATTERN.test(model)) throw badRequest(`${label} must be 1-128 letters, numbers, periods, underscores, or hyphens.`);
  return model;
}

function envState() {
  return {
    endpoint: Boolean(process.env.AZURE_OPENAI_REPORTING_ENDPOINT),
    reportModel: Boolean(process.env.AZURE_OPENAI_REPORTING_MODEL),
    analysisModel: Boolean(process.env.SIT_ANALYSIS_MODEL),
  };
}

async function readOverrides(rootDir) {
  try { return JSON.parse(await fsp.readFile(path.join(rootDir, 'config', 'settings.json'), 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return {}; throw error; }
}

async function getFoundryConfiguration(config) {
  const overrides = await readOverrides(config.rootDir);
  const environmentOverrides = envState();
  const saved = {
    endpoint: overrides.ai?.endpoint || config.ai.endpoint || '',
    reportModel: overrides.ai?.model || config.ai.model || '',
    analysisModel: overrides.sitOptimize?.analysisModel || config.sitOptimize.analysisModel || '',
  };
  const effective = { endpoint: config.ai.endpoint || '', reportModel: config.ai.model || '', analysisModel: config.sitOptimize.analysisModel || '' };
  const restartRequired = (!environmentOverrides.endpoint && saved.endpoint !== effective.endpoint)
    || (!environmentOverrides.reportModel && saved.reportModel !== effective.reportModel)
    || (!environmentOverrides.analysisModel && saved.analysisModel !== effective.analysisModel);
  return {
    ok: true,
    saved,
    effective,
    environmentOverrides,
    restartRequired,
    secret: { configured: Boolean(config.ai.apiKey), variable: SECRET_VARIABLE, persistedByStudio: false },
  };
}

async function saveFoundryConfiguration(config, body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw badRequest('A configuration object is required.');
  const allowed = new Set(['endpoint', 'reportModel', 'analysisModel']);
  const unexpected = Object.keys(body).filter((key) => !allowed.has(key));
  if (unexpected.length) throw badRequest('Only endpoint and model deployment names can be saved. Secrets are never accepted by this API.');
  const endpoint = normalizeEndpoint(body.endpoint);
  const reportModel = normalizeModel(body.reportModel, 'Reporting model deployment');
  const analysisModel = normalizeModel(body.analysisModel, 'Analysis model deployment');
  const settingsPath = path.join(config.rootDir, 'config', 'settings.json');
  const current = await readOverrides(config.rootDir);
  const next = {
    ...current,
    ai: { ...(current.ai || {}), endpoint, model: reportModel },
    sitOptimize: { ...(current.sitOptimize || {}), analysisModel },
  };
  delete next.ai.apiKey;
  const temporaryPath = `${settingsPath}.${process.pid}.${Date.now()}.tmp`;
  await fsp.mkdir(path.dirname(settingsPath), { recursive: true });
  await fsp.writeFile(temporaryPath, `${JSON.stringify(next, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await fsp.rename(temporaryPath, settingsPath);
  const environmentOverrides = envState();
  const restartRequired = (!environmentOverrides.endpoint && endpoint !== config.ai.endpoint)
    || (!environmentOverrides.reportModel && reportModel !== config.ai.model)
    || (!environmentOverrides.analysisModel && analysisModel !== config.sitOptimize.analysisModel);
  return {
    ok: true,
    saved: { endpoint, reportModel, analysisModel },
    environmentOverrides,
    restartRequired,
    secret: { configured: Boolean(config.ai.apiKey), variable: SECRET_VARIABLE, persistedByStudio: false },
  };
}

module.exports = { getFoundryConfiguration, normalizeEndpoint, normalizeModel, saveFoundryConfiguration };
