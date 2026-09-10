'use strict';

function extractResponseText(response) {
  if (typeof response?.output_text === 'string' && response.output_text.trim()) return response.output_text;
  for (const item of (Array.isArray(response?.output) ? response.output : [])) {
    for (const part of (Array.isArray(item?.content) ? item.content : [])) {
      if (typeof part?.text === 'string' && part.text.trim()) return part.text;
    }
  }
  return response?.choices?.[0]?.message?.content || '';
}

function extractJson(text) {
  const value = String(text || '').trim();
  if (value.startsWith('{') && value.endsWith('}')) return value;
  const fenced = value.match(/```(?:json)?\s*([\s\S]*?)```/i); if (fenced) return fenced[1].trim();
  const start = value.indexOf('{'); const end = value.lastIndexOf('}');
  if (start >= 0 && end > start) return value.slice(start, end + 1);
  throw new Error('AI Helper did not return a JSON object.');
}

async function generateFlow(config, body, normalizeFlowDocument, existingDoc) {
  if (!config.ai?.enabled) throw Object.assign(new Error('AI Helper is disabled in configuration.'), { statusCode: 503 });
  if (!config.ai.apiKey) throw Object.assign(new Error('AI Helper requires AZURE_OPENAI_REPORTING_KEY, AZURE_OPENAI_API_KEY2, or AZURE_OPENAI_API_KEY.'), { statusCode: 503 });
  if (!config.ai.endpoint) throw Object.assign(new Error('AI Helper endpoint is not configured.'), { statusCode: 503 });
  const prompt = String(body?.prompt || '').trim();
  if (!prompt) throw Object.assign(new Error('Describe the response flow to generate.'), { statusCode: 400 });
  if (prompt.length > 4000) throw Object.assign(new Error('AI Helper prompt exceeds 4,000 characters.'), { statusCode: 400 });
  const currentFlow = body?.currentFlow && typeof body.currentFlow === 'object' ? normalizeFlowDocument({ flows: [body.currentFlow] }).flows[0] : null;
  const existingIds = (existingDoc?.flows || []).map((flow) => flow.id).slice(0, 100);
  const system = `You are AI Helper inside a Microsoft Purview DLP Response Studio. Design exactly one safe declarative response flow from the operator request.
Return one JSON object only with this shape:
{"summary":"brief explanation","assumptions":["..."],"flow":{"id":"lowercase-hyphen-id","name":"...","description":"...","kind":"notification|remediation|closure|investigation","enabled":true,"parameters":[{"name":"PascalCaseName","label":"...","type":"string|text|number|boolean","required":false,"default":"","help":"..."}],"actions":[...]}}
Only these action shapes are allowed:
1. {"type":"incidentPatch","addTags":["tag"],"status":"active|inProgress|resolved|","includeSitTriageComment":false}
2. {"type":"emailAffectedUsers"}
3. {"type":"teamsNotifyAffectedUsers"}
Rules:
- Never emit PowerShell, scripts, commands, URLs containing secrets, arbitrary Graph requests, or unsupported action types.
- Never request or reproduce detected DLP values, credentials, document content, API keys, tokens, or personal message content.
- Add parameters only for operator-configurable non-secret values. For email flows, a subject parameter is appropriate; impactedUsers is supplied automatically at runtime and must not be requested.
- For Teams flows, use a teamsMessage text parameter. A teamsRecipients string parameter may be optional; when blank, selected incidents or the bulk-response scope supply affected users automatically.
- Prefer dry-run-safe, reversible incident tagging and inProgress status over resolution unless the operator explicitly requests closure.
- Set includeSitTriageComment to true when the operator wants the latest Detection Assurance priority and privacy-safe security rationale added as a Microsoft Graph incident comment. Never invent that triage in the flow draft; it is supplied only from a completed Detection Assurance assessment at runtime.
- The server derives Graph scopes and validates every field. If the request needs unsupported behavior, produce the closest supported draft and state the limitation in assumptions.
- Keep the flow narrowly scoped. The draft is never saved or executed automatically.`;
  const user = `${currentFlow ? `Revise this current declarative flow while retaining its id unless renaming is requested:\n${JSON.stringify(currentFlow)}\n\n` : ''}Existing ids: ${existingIds.join(', ') || '(none)'}\n\nOperator request:\n${prompt}`;
  const requestBody = { model: config.ai.model, max_output_tokens: Math.min(3000, Math.max(500, Number(config.ai.maxOutputTokens) || 1800)), input: [{ role: 'system', content: [{ type: 'input_text', text: `${system}\n\nFORMATTING: Return valid JSON only, without markdown.` }] }, { role: 'user', content: [{ type: 'input_text', text: user }] }] };
  const response = await fetch(config.ai.endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'api-key': config.ai.apiKey, 'User-Agent': 'DlpResponseStudio/0.1' }, body: JSON.stringify(requestBody), signal: AbortSignal.timeout(90000) });
  if (!response.ok) { const text = await response.text().catch(() => ''); throw new Error(`Azure OpenAI request failed (${response.status}): ${text.slice(0, 500)}`); }
  const raw = extractResponseText(await response.json());
  let parsed; try { parsed = JSON.parse(extractJson(raw)); } catch (error) { throw new Error(`AI Helper returned invalid JSON: ${error.message}`); }
  if (!parsed?.flow) throw new Error('AI Helper did not return a flow draft.');
  const flow = normalizeFlowDocument({ flows: [parsed.flow] }).flows[0];
  return { ok: true, summary: String(parsed.summary || '').slice(0, 1000), assumptions: (Array.isArray(parsed.assumptions) ? parsed.assumptions : []).map(String).map((item) => item.slice(0, 500)).slice(0, 10), flow, model: config.ai.model };
}

module.exports = { extractJson, extractResponseText, generateFlow };
