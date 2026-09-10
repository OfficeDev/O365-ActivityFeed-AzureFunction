# DLP Response Studio

Standalone bulk query, planning, and response studio for Microsoft Purview DLP alerts and DLP alert events.

New installation: follow the [Setup guide](SETUP.md) for prerequisites, a safe first run, Graph synchronization, and optional capabilities.

Read the standalone launch article: [Introducing DLP Response Studio](docs/introducing-dlp-response-studio.html).

The project is standalone and uses JSONL as its persistence format.

## Safety defaults

- Query and plan operations are read-only.
- Detected values are redacted by the collector and again by the Node projection.
- Live apply is disabled by default.
- Live actions require server enablement, an explicit confirmation phrase, and a second browser confirmation.
- Plans and executions are recorded in `data/ledger/execution-ledger.jsonl`.
- Incident and user caps are enforced server-side.
- Response flows are declarative; arbitrary PowerShell from configuration is not executed.

## Requirements

- Node.js 20 or later
- PowerShell 7
- Microsoft Graph PowerShell authentication module
- An operator account with the Graph permissions required by the selected operation

Install the Graph authentication module if it is not already available:

    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

### Microsoft Graph delegated permissions

The PowerShell workers authenticate interactively as the operator and request only the delegated permissions needed for the selected operation. Depending on tenant policy, an administrator may need to grant consent before an operator can use them.

| Operation | Delegated permissions | Access |
|---|---|---|
| Synchronize Purview DLP alerts and events | `SecurityAlert.Read.All`, `SecurityEvents.Read.All`, `CustomTags.Read.All` | Read |
| Resolve Microsoft Entra departments | `User.Read.All` | Read |
| Update incident status/tags and add Detection Assurance comments | `SecurityIncident.ReadWrite.All` | Read/write |
| Email affected users | `Mail.Send` | Send mail as the signed-in operator |
| Send one-to-one Teams notifications | `Chat.Create`, `ChatMessage.Send`, `User.ReadBasic.All` | Create chats, send messages, and resolve users |

No application permissions, client secrets, or stored Graph access tokens are required. Querying cached JSONL, creating plans, running dry-run response flows, and running Detection Assurance against the synchronized store do not authenticate to Graph. A live response worker derives its scopes from the explicitly selected actions.

## Quick start

1. Run `npm start` from the repository directory. No npm package installation is required.
2. Open `http://127.0.0.1:3100`.
3. Choose **DLP Response**, **Detection Assurance**, or **Response Studio** from the start page.
4. Select **Sync DLP alerts** in DLP Response, or run `workers/Collect-DlpAlerts.ps1` directly.

The public defaults are sufficient for a read-only first run. Copy `config/settings.example.json` to the ignored `config/settings.json` only when local overrides are needed. See the [Setup guide](SETUP.md) for configuration and optional feature setup.

The main page links to **Response Studio** at `http://127.0.0.1:3100/response-studio.html`. It provides the flow list/editor/test layout, parameter and action authoring, import/export, version history, incident selection, dry runs, and guarded live execution. Supported actions include incident updates, affected-user email, and administrator-reviewed one-to-one Microsoft Teams notifications. Flow definitions remain declarative; arbitrary PowerShell is intentionally not accepted.

The Teams notification action derives the delegated Graph scopes `Chat.Create`, `ChatMessage.Send`, and `User.ReadBasic.All`. Dry runs do not authenticate to Graph. Live delivery remains disabled by default and requires the same server enablement, exact confirmation phrase, and browser confirmation as every other live response. The reviewed message is HTML-encoded before delivery, and detected DLP values are never added automatically.

The separate bulk-query workspace remains available at `http://127.0.0.1:3100/bulk-response.html` for facet filtering, affected-user review, multi-flow queues, and saved queue jobs.

## Department enrichment

Bulk Response Studio can resolve the Microsoft Entra department for users in the current matched DLP scope:

1. Run a bulk-response query.
2. Select **Enrich departments** beside the affected-user table.
3. Complete delegated Microsoft Graph authentication if prompted.
4. The server reruns the same local DLP query and exposes Department in the affected-user table and filter facets.

The operation:

- Accepts up to `maxDepartmentEnrichmentUsers` unique, valid UPNs per request; the default is 500 and the hard maximum is 1,000.
- Requests delegated `User.Read.All` and performs only `GET /users/{upn}?$select=displayName,department,mail` calls.
- Merges normalized results into `data/user-directory.json`, keyed by lowercase UPN.
- Preserves previous cache entries so repeated enrichment is additive.
- Keeps users with missing departments or failed lookups visible as unresolved.
- Joins the cache during local query projection; it does not alter DLP JSONL, alert ownership, collection queries, or Detection Assurance evidence.
- Records start and completion metadata in the execution ledger without recording Graph tokens.

`POST /api/dlp/enrich-departments` accepts `{ "upns": ["user@example.com"] }` and returns requested, resolved, unresolved, cache-entry, and worker outcome counts. Department enrichment is read-only in Graph and does not depend on `liveApplyEnabled` or the live-remediation confirmation phrase.

## Detection Assurance

The start page links to **Detection Assurance** at `http://127.0.0.1:3100/sit-optimize.html`. It reuses `data/dlp-alerts-store.jsonl` and `data/dlp-events-store.jsonl`; starting an assessment does not authenticate to Microsoft Graph and does not launch another alert synchronization. The existing `sit-optimize` paths and `sitOptimize` configuration names remain stable technical identifiers.

Data-only analysis profiles and the assessment worker are included under `sit-optimize/`. Profiles are loaded from the configured `sitOptimize.root` (default `./sit-optimize`). Set `SIT_OPTIMIZE_ROOT` to override that location. Before a run, the UI previews how many shared alerts, events, and detections match the profile's `DlpPolicy` wildcard.

### Customize the Purview analysis language

The Purview language is intentionally stored as reviewable text rather than embedded in a hosted service. Tune the layer that matches the intended scope:

| Layer | Location | What to tune |
| --- | --- | --- |
| SIT-specific assessment profiles | `sit-optimize/profiles/*.psd1` | `DlpPolicy`, exact `SensitiveInformationTypeIds` and `SensitiveInformationTypeNames` allow-lists, `AnalysisFocus`, `ExtractionInstruction`, `ConsolidationInstruction`, and `ReportMergeInstruction`. The Detection Assurance profile editor saves reviewed changes back to this directory. |
| Context-only Purview implementation plans | `server/prompts/purview-implementation.md` | Administrative plan structure, supported Purview controls, validation requirements, and rollout guidance for redacted assessments. |
| Protected-evidence implementation plans | `server/prompts/purview-implementation-protected.md` | The access-controlled plan format and rules governing explicitly authorized false-positive artifacts. Preserve the prohibitions on credentials, personal data, identities, and unrelated detected values. |
| AI-assisted profile drafting | `server/prompts/sit-profile-authoring.md` | The profile schema and authoring guidance used when drafting a new exact-SIT profile for operator review. |
| Mandatory runtime contracts | `sit-optimize/credpattern.ps1` | Shared incident-triage, evidence-correlation, privacy, and department-context rules applied in addition to profile language. Treat these as security controls rather than normal profile customization. |

For routine tuning, create or edit a profile through Detection Assurance and review its exact SIT allow-list before running it. Direct edits to the Markdown prompts affect every implementation plan of that type. Direct edits to the mandatory worker contracts affect every assessment and should receive code review and regression testing. Keep built-in Microsoft SITs read-only, prefer copy-and-tune, preserve staged validation and rollback guidance, and never weaken redaction or protected-evidence handling to obtain a more detailed response.

Application settings do not contain these instructions. Public defaults are in `config/settings.example.json`; copy that file to the ignored `config/settings.json` for local endpoint, model, execution-limit, and protected-evidence settings. Declarative remediation and notification actions are customized separately through `config/response-flows.json`, copied from `config/response-flows.default.json`.

Integrated analysis remains context-only by default:

- Detected values, identities, recipients, content names, senders, and subjects are excluded from the AI payload.
- Policy, workload, SIT name, location, Graph-resolved department when available, confidence, frequency, and count context remain available for tuning.
- Department context is joined locally by UPN before identity redaction. The model receives the department name but not the UPN used to resolve it.
- Assessments use department concentration for ownership, pilot design, monitoring, and department-aware validation; department alone must never become a suppression condition.
- Exact-value classification and regex recommendations are marked as requiring a separate controlled validation sample.
- Reports, run snapshots, chunk results, logs, and job state are written under `data/sit-optimize/`.

For assurance assessments that require actual matched content, Detection Assurance can use a separate protected evidence path:

1. Enable `sitOptimize.sensitiveContent.enabled` in `config/settings.json` (or set `SIT_SENSITIVE_CONTENT_ENABLED=true`).
2. In Detection Assurance, type the configured capture phrase and select **Rebuild protected evidence**. This performs a full DLP pull using the existing collector.
3. The collector encrypts each raw event with Windows DPAPI `CurrentUser` before redacting the normal event object. Plaintext is never written to JSONL.
4. Select **Protected sensitive values**, type the separate analysis phrase, and start the profile-scoped analysis.

The protected store is `data/protected/sit-sensitive-events.jsonl`. Each line contains only an event ID, capture metadata, and DPAPI ciphertext. The directory and file ACLs are restricted to the current Windows identity and `SYSTEM`. Decryption therefore requires the same Windows account that performed capture. Retention defaults to 30 days and is applied whenever protected evidence is rebuilt or incrementally updated.

Sensitive analysis sends decrypted, profile-scoped DLP values and related event context to the configured Azure OpenAI endpoint. It requires both configuration enablement and an exact per-run confirmation. Protected content is never returned by a Node API or rendered in the browser; reports may nevertheless contain model-derived examples or recommendations and must be handled as sensitive output.

The shared-store mode was added to the existing analysis worker with `-SkipCollection`. It resolves event ownership from persisted parent-alert lineage when available, otherwise from detector ID plus the alert activity window, and then applies the selected profile's policy and exact SIT boundary. Ambiguous or unmatched events fail closed. `-FullPull` is rejected in this mode.

The Detection Assurance page presents an Observe–Explain–Improve–Prove workflow: create and save the exact-scope tuning profile, assess a baseline period, produce the deployable Purview change plan, then run a post-change period and compare observed outcomes. Start and end dates are inclusive UTC calendar days. Date filtering occurs only after the existing local evidence store is loaded; it does not alter the Microsoft Graph collection query or trigger another synchronization. Run snapshots, reports, exports, and implementation plans retain the selected period. Comparisons warn when periods overlap, have different durations, or predate period metadata.

Completed Detection Assurance assessments can also feed DLP Response with incident-level AI triage. The mandatory runtime prompt requests `HIGH`, `MEDIUM`, or `LOW` priority and a concise security comment for every correlated incident regardless of the end-user profile instructions. The interchange excludes detected values and is defensively sanitized. DLP Response displays the latest triage, and the built-in incident review flow demonstrates how to preview and, only after normal live confirmation, add that rationale as a Microsoft Graph incident comment. The comment is explicitly marked AI-generated and requiring human review.

High-volume SIT chunk extraction and incident triage use the configured `sitOptimize.analysisModel` (`gpt-5.6-luna` by default). Final consolidation, reports, and Purview change plans continue to use the stronger configured reporting model. Set `SIT_ANALYSIS_MODEL` to override only the economical analysis tier.

## Microsoft Foundry configuration

Open the workbench Configuration page to save the Microsoft Foundry Responses endpoint, reporting deployment, and analysis deployment. The page accepts only non-secret settings and requires a server restart before saved changes become active. Environment variables continue to take precedence and are identified in the page when present.

The browser never accepts, reads, or persists the API key. Set `AZURE_OPENAI_REPORTING_KEY` in the environment of the process that starts the workbench. For a local PowerShell session, use `Read-Host -MaskInput` to populate the variable and run `npm start` from the same terminal. For shared and hosted environments, use the platform secret store to inject that environment variable.

## AI Helper

Response Studio includes an optional **AI Helper**. It uses the Azure OpenAI Responses endpoint and defaults to `gpt-5.6-terra`. Configure one of these environment variables before starting the server:

- `AZURE_OPENAI_REPORTING_KEY`
- `AZURE_OPENAI_API_KEY2`
- `AZURE_OPENAI_API_KEY`

Optional endpoint and model overrides are `AZURE_OPENAI_REPORTING_ENDPOINT` and `AZURE_OPENAI_REPORTING_MODEL`. API keys are never returned to the browser or written to project configuration.

AI Helper receives only the operator's flow description, existing flow IDs, and an optional declarative flow being revised. It does not receive DLP events, detected values, document content, or remediation credentials. Generated drafts are normalized to allow-listed actions and must be reviewed and explicitly added before they can be saved.

## Integration code

Select **Integrations** in Response Studio to generate a standalone PowerShell synchronization script for:

- Slack incoming webhooks
- ServiceNow Table API incidents
- Generic HTTPS REST webhooks

The generator is deterministic and template-backed. It does not send DLP records to the AI model. Generated scripts query only the redacted loopback API, keep incremental delivery state, deduplicate deliveries, refuse to advance state after a partial/truncated query, and omit users, senders, recipients, document names, and detected values from destination payloads.

Response Studio returns the script for review and download but does not save it as a flow action or execute it. Run the downloaded script with `-DryRun` first. Destination credentials are read at runtime from the environment variables shown in the preview:

- Slack: `DLP_SLACK_WEBHOOK_URL`
- ServiceNow: `DLP_SERVICENOW_INSTANCE`, `DLP_SERVICENOW_TOKEN`, and optional `DLP_SERVICENOW_TABLE`
- Generic webhook: `DLP_WEBHOOK_URL` and optional `DLP_WEBHOOK_TOKEN`

After review, schedule the script using the operating system, automation platform, or coding agent appropriate to the deployment. Keep generated state files and destination secrets outside source control.

No npm packages are required in this version.

## License

This project is available under the MIT License. See `LICENSE`.

## Enable live apply

Live mutations are intentionally disabled. After validating collection, query, plans, and dry runs:

1. Set `liveApplyEnabled` to `true` in `config/settings.json`, or set `DLP_STUDIO_LIVE_APPLY=true` before starting the server.
2. Restart the service.
3. Review the generated plan.
4. Type the configured confirmation phrase exactly.
5. Confirm the browser warning.

Do not enable live apply for a shared or unauthenticated network listener. The default host is loopback-only.

## Data files

| File | Purpose |
|---|---|
| `data/dlp-alerts-store.jsonl` | Latest DLP alert objects, rewritten atomically after each incremental sync |
| `data/dlp-events-store.jsonl` | Append-only DLP alert-event store |
| `data/dlp-sync-state.json` | Incremental collection watermark |
| `data/plans/` | Redacted detection scopes and plan previews |
| `data/jobs/` | Saved response jobs |
| `data/results/` | Apply and flow execution results |
| `data/ledger/execution-ledger.jsonl` | Append-only operation ledger |
| `data/user-directory.json` | Graph-resolved UPN, display name, mail, and department cache |
| `data/sit-optimize/` | Profile-scoped SIT reports, run snapshots, chunk analyses, logs, and background job state |
| `data/protected/sit-sensitive-events.jsonl` | DPAPI CurrentUser-encrypted raw DLP event envelopes for explicitly confirmed SIT analysis |

## APIs

- `GET /api/health`
- `POST /api/dlp/collect`
- `POST /api/dlp/query`
- `POST /api/dlp/enrich-departments`
- `POST /api/remediation/plan`
- `POST /api/remediation/apply`
- `GET /api/flows`
- `POST /api/flows/run`
- `GET|POST /api/jobs`
- `POST /api/jobs/delete`
- `POST /api/response-flows/integration-code`
- `GET /api/sit/summary`
- `GET /api/sit/profiles`
- `GET /api/sit/scope?profileId=<id>`
- `POST /api/sit/analyze`
- `POST /api/sit/capture`
- `GET /api/sit/jobs`
- `GET /api/sit/runs`
- `GET /api/sit/report`

## Validate

Run `npm run check` and `npm test`. PowerShell files can be parsed without executing them using the PowerShell language parser.
