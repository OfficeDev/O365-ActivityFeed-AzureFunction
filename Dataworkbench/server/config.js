'use strict';

const fs = require('node:fs');
const path = require('node:path');

const rootDir = path.resolve(__dirname, '..');

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function loadConfig() {
  const defaults = readJson(path.join(rootDir, 'config', 'settings.example.json'));
  const overridePath = path.join(rootDir, 'config', 'settings.json');
  const overrides = fs.existsSync(overridePath) ? readJson(overridePath) : {};
  const sitDefaults = defaults.sitOptimize || {}; const sitOverrides = overrides.sitOptimize || {};
  const config = { ...defaults, ...overrides, ai: { ...defaults.ai, ...(overrides.ai || {}) }, sitOptimize: { ...sitDefaults, ...sitOverrides, sensitiveContent: { ...(sitDefaults.sensitiveContent || {}), ...(sitOverrides.sensitiveContent || {}) } } };
  config.rootDir = rootDir;
  config.dataDir = path.resolve(rootDir, config.dataDir || './data');
  config.port = Number(process.env.PORT || config.port || 3100);
  config.host = process.env.HOST || config.host || '127.0.0.1';
  config.liveApplyEnabled = process.env.DLP_STUDIO_LIVE_APPLY === 'true' || config.liveApplyEnabled === true;
  config.ai.enabled = config.ai.enabled !== false;
  config.ai.endpoint = process.env.AZURE_OPENAI_REPORTING_ENDPOINT || config.ai.endpoint;
  config.ai.model = process.env.AZURE_OPENAI_REPORTING_MODEL || config.ai.model || 'gpt-5.6-terra';
  config.ai.apiKey = process.env.AZURE_OPENAI_REPORTING_KEY || process.env.AZURE_OPENAI_API_KEY2 || process.env.AZURE_OPENAI_API_KEY || '';
  config.sitOptimize.enabled = config.sitOptimize.enabled !== false;
  config.sitOptimize.root = process.env.SIT_OPTIMIZE_ROOT || config.sitOptimize.root || './sit-optimize';
  config.sitOptimize.analysisModel = process.env.SIT_ANALYSIS_MODEL || config.sitOptimize.analysisModel || config.ai.model;
  config.sitOptimize.sensitiveContent.enabled = process.env.SIT_SENSITIVE_CONTENT_ENABLED === 'true' || config.sitOptimize.sensitiveContent.enabled === true;
  config.sitOptimize.sensitiveContent.retentionDays = Math.min(365, Math.max(1, Number(config.sitOptimize.sensitiveContent.retentionDays) || 30));
  return Object.freeze(config);
}

module.exports = { loadConfig, rootDir };
