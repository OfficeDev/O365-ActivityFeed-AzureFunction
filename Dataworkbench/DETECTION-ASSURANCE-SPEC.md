# Detection Assurance — Full Feature Specification

**Product:** Data Security Workbench  
**Capability:** Detection Assurance  
**Technical module identifier:** `sit-optimize` / `sitOptimize`  
**Status:** Implemented local operator experience  
**Specification date:** 2026-08-07

## 1. Executive summary

Detection Assurance is the control-assurance capability of Data Security Workbench for Microsoft Purview. It converts synchronized DLP evidence into an operator-governed lifecycle for determining whether sensitive-data controls are accurate, explaining why they fire, producing reviewable improvements, and proving whether those improvements worked.

The complete workbench connects five operational outcomes:

1. **Observe** — investigate Purview DLP detections and establish trustworthy incident, alert, and event lineage.
2. **Explain** — assess an exact Sensitive Information Type (SIT) boundary and distinguish credible exposure from systemic noise.
3. **Improve** — convert reviewed evidence into a deployable Purview change plan with validation and rollback guidance.
4. **Prove** — compare a governed baseline with a later evidence period using the same saved profile.
5. **Respond** — apply explicitly selected incident, email, or Microsoft Teams actions through guarded workflows.

Detection Assurance complements DSPM products by focusing on operational control efficacy rather than claiming to replace broad data discovery and posture management.

## 2. Positioning

### 2.1 Category statement

> Data Security Workbench is a control-assurance and response layer for Microsoft Purview.

### 2.2 Capability statement

> Detection Assurance determines whether sensitive-data controls are behaving accurately, explains why they fire, produces reviewable improvements, and proves whether those improvements worked.

### 2.3 Competitive distinction

DSPM platforms commonly focus on discovering sensitive data, mapping access, and identifying exposure or posture. Detection Assurance focuses on the next operational questions:

- Is the deployed data security control making accurate decisions?
- Which findings represent credible risk versus systemic noise?
- What narrow change should an operator review?
- What false-negative guardrails must be preserved?
- Did the approved change measurably improve the control?
- What governed response should follow?

### 2.4 Market-facing terminology

- Customer-facing capability: **Detection Assurance**
- Technical Purview object: **Sensitive Information Type (SIT)**
- Internal compatibility identifiers remain unchanged:
  - `/sit-optimize.html`
  - `/api/sit/*`
  - `sitOptimize`
  - `data/sit-optimize/`

## 3. Goals and non-goals

### 3.1 Goals

- Provide a trustworthy operational view of synchronized Purview DLP evidence.
- Preserve Incident → Alert → Event → SIT detection lineage.
- Enforce an exact, fail-closed classification boundary.
- Support redacted context-only and explicitly confirmed protected-content assessments.
- Produce mandatory incident-level AI triage for every correlated incident.
- Separate economical high-volume analysis from stronger final consolidation.
- Generate a reviewable Purview implementation, validation, and rollback plan.
- Compare baseline and post-change evidence periods.
- Connect assurance outcomes to guarded incident, email, and Teams response actions.
- Keep browser, storage, model, and Graph trust boundaries explicit.

### 3.2 Non-goals

- Replacing the Microsoft Purview portal.
- Replacing enterprise-wide DSPM discovery, data access governance, or cloud posture products.
- Automatically deploying AI-generated Purview changes.
- Automatically executing Microsoft Graph writes.
- Sending detected values to the browser.
- Broadening an operator-selected SIT boundary through AI inference.
- Modifying Graph, OData, or KQL collection queries as part of local filtering or assessment.

## 4. Primary personas and jobs to be done

### 4.1 Data security analyst

- Investigate DLP detections and affected users.
- Understand incident-level risk and rationale.
- Separate credible exposure from recurring false positives.

### 4.2 Purview control owner

- Define exact SIT scope and operator intent.
- Evaluate classification behavior over a bounded period.
- Review narrow rule, context, confidence, proximity, or exclusion recommendations.
- Validate false-negative guardrails before deployment.

### 4.3 Security operations lead

- Prioritize incidents using privacy-safe assurance outcomes.
- Preview and authorize response actions.
- Track whether control changes reduce operational burden without hiding risk.

### 4.4 Platform administrator

- Configure Microsoft Foundry endpoint and model routing without placing secrets in the browser.
- Control protected evidence and live Graph execution.
- Review required delegated permissions.

## 5. Product topology

Data Security Workbench contains three connected operating surfaces:

1. **DLP Response**
   - Evidence synchronization and investigation
   - Filters, facets, users, incidents, and assurance triage
   - Remediation planning and guarded live actions

2. **Detection Assurance**
   - Profile authoring and exact SIT boundary
   - Baseline assessment
   - Incident triage
   - Reports and Purview change plans
   - Before/after evidence comparison

3. **Response Studio**
   - Declarative response-flow authoring
   - Dry-run-first validation
   - Incident updates and assurance comments
   - Email and one-to-one Teams notifications

All three surfaces use the same governed local evidence layer.

## 6. End-to-end lifecycle

### Step 1 — Define the control boundary

The operator creates a data-only profile containing:

- Profile ID
- Description
- DLP policy wildcard
- Finding noun
- Operator-owned analysis focus
- Exact SIT IDs and names
- Extraction, consolidation, and report-merge instructions

The authoring form starts blank. Selecting a saved profile for assessment does not silently populate or alter the authoring form. **Edit selected profile** is required to load an existing profile into the editor; **Clear** returns the editor to a blank state.

### Step 2 — Assess a baseline period

The operator selects:

- A saved profile
- Inclusive UTC start and end dates, or explicit all-history scope
- Redacted context-only or protected validation evidence
- Assessment label
- Sequential or parallel chunk analysis

The UI previews policy alerts, in-scope events, governed detections, and whether the scope is analyzable.

### Step 3 — Build the Purview change plan

A completed baseline report can be converted into a cached, portal-ready plan containing:

- Recommended control changes
- Narrow implementation guidance
- Positive and negative tests
- False-negative guardrails
- Monitoring thresholds
- Rollback guidance

Generation does not deploy or mutate Purview.

### Step 4 — Observe change and compare

After an approved change is implemented outside the workbench, the operator runs the same saved profile against a later period and compares:

- Noise occurrences
- Unique noise patterns
- Validated findings
- Linked findings or credential pairs
- Weighted false-positive reduction
- Results by SIT, workload, finding category, and risk

The comparison warns when periods overlap, differ in duration, or lack period metadata.

### Step 5 — Governed response

Assurance outcomes can be consumed by DLP Response and Response Studio. Operators can preview and explicitly authorize:

- Incident tagging and status updates
- Detection Assurance incident comments
- Email notifications to affected users
- One-to-one Microsoft Teams notifications
- Resolution of reviewed low-severity incidents

## 7. Evidence model and correlation

### 7.1 Intended hierarchy

```text
Incident
  └─ Alert
      └─ DLP alert event
          └─ Sensitive Information Type detection
```

- Incident is the response and tracking key.
- Alert is the security alert resource.
- Event contains DLP activity and SIT detection details.
- One event can contain multiple SIT detections.

### 7.2 Correlation invariant

`detectorId` identifies the detector that triggered an alert; it is not a unique alert identifier. `dlpAlertEvent.alertCorrelationId` can therefore be shared across multiple alerts and historical events.

Event ownership resolves in this order:

1. Use persisted `_dlpResponseStudio.alertId` when it identifies a known alert.
2. Otherwise require a unique detector-ID match where the event start/end lies inside the alert first/last activity window.
3. Fail closed when ownership is missing or ambiguous.

Newly synchronized events persist:

```json
{
  "_dlpResponseStudio": {
    "alertId": "parent-alert-id",
    "incidentId": "incident-id",
    "correlatedUtc": "ISO-8601 timestamp",
    "correlation": "detector-and-alert-activity-window-v2"
  }
}
```

### 7.3 Query constraint

Local ownership, date, profile, and SIT filtering must not alter the existing Microsoft Graph, OData, or KQL collection query. Any proposed collection-query change requires explicit operator approval before implementation.

## 8. Classification boundary semantics

The saved profile is an exact allow-list of SIT IDs and names.

- Multiple selected SITs use **OR** semantics.
- An event is admitted only when it contains at least one selected SIT detection.
- Within an admitted event, only matching SIT detection objects enter the assessment payload.
- Unselected SIT detections in the same event are excluded.
- AI instructions cannot broaden the selected boundary.
- Empty SIT scope fails closed and cannot run.
- Unknown SIT IDs or names cannot be saved.

Catalog tile counts represent synchronized catalog availability, not the final profile/date/policy-scoped assessment count.

## 9. Evidence fidelity modes

### 9.1 Redacted posture context

Default mode. The AI payload excludes:

- Detected values
- User identities
- Recipients
- Senders
- Content names
- Subjects
- Sensitive artifacts

The model may receive bounded metadata such as:

- Policy
- Workload
- Graph-resolved department, when available
- SIT ID and name
- Location
- Confidence
- Frequency and counts
- Incident ID

Department is joined locally using the UPN-keyed directory cache before identity redaction. The assessment payload contains the resolved department but not the UPN used for the lookup. Department context supports concentration analysis, business-owner validation, pilot selection, and post-change monitoring. It cannot broaden SIT scope or act as a standalone suppression condition.

A context-only run cannot claim a credential is active or live. Exact-value and regex conclusions must be marked as requiring controlled validation.

### 9.2 Protected validation evidence

Optional mode requiring:

- Configuration enablement
- Explicit capture confirmation phrase
- DPAPI CurrentUser-protected evidence
- Same Windows identity for decryption
- Separate per-run analysis confirmation phrase

The browser and Node APIs never decrypt or return raw protected event content. The PowerShell worker decrypts immediately before constructing the profile-scoped Foundry request. General JSONL evidence remains redacted.

For a run marked `protected-sensitive-content`, Step 2 is the sole protected-content analysis stage. Its structured output and final summary preserve exact artifacts already classified as false positives when required for a host, path, parameter, keyword, supporting element, exclusion, tested regex, or regression test. Step 3 automatically consumes that persisted Step 2 evidence and does not inspect or decrypt original events again.

Protected Step 3 planning:

- Derives its evidence mode from the completed Step 2 run rather than requesting a second sensitive-detail opt-in.
- Uses exact artifacts only where Step 2 classified them as false positives.
- Must never reproduce validated or possible credentials, personal data, message content, or unrelated detected values.
- Is not cached by the server; the result remains in browser memory unless the operator explicitly exports it.
- Must not be copied into incident comments, email, Teams, tickets, or unprotected logs.

## 10. AI processing and model routing

### 10.1 Analysis tier

Default deployment: `gpt-5.6-luna`

Responsibilities:

- High-volume chunk extraction
- Pattern classification
- Incident triage
- Structured intermediate evidence

### 10.2 Reporting tier

Default deployment: `gpt-5.6-terra`

Responsibilities:

- Bounded consolidation
- Final report
- Purview change plan
- Implementation, validation, and rollback narrative

### 10.3 Operator governance

- AI can draft profile instructions but cannot save them automatically.
- The operator reviews and saves the profile before analysis.
- Operator analysis focus is authoritative but cannot broaden SIT scope.
- AI reports are advisory and do not automatically deploy changes.
- Protected-content use requires explicit confirmation.
- Step 3 cannot broaden the protected evidence established and summarized by Step 2.

## 11. Mandatory incident triage

Every chunk prompt includes a non-overridable incident-triage contract. For every non-empty incident represented in the chunk, the model must return no more than one entry with:

```json
{
  "incident_id": "copied exactly from input",
  "priority": "HIGH|MEDIUM|LOW",
  "disposition": "LIVE_CREDENTIAL|LIKELY_CREDENTIAL|NOISE|INDETERMINATE",
  "validity_status": "ACTIVE|EXPIRED|TRUNCATED|REVOKED|INDETERMINATE",
  "evidence_count": 0,
  "security_comment": "privacy-safe analyst rationale"
}
```

### 11.1 Priority meaning

- **HIGH** — credible live or active exposure requiring immediate investigation.
- **MEDIUM** — likely exposure or material ambiguity requiring review.
- **LOW** — likely benign or noise with limited security impact.

### 11.2 Sanitization

Security comments must not contain or reconstruct:

- Credentials or detected values
- People, recipients, or senders
- File names or subjects
- URLs
- Long token-like artifacts
- Other sensitive content

The PowerShell worker sanitizes before persistence, and Node sanitizes again before use.

### 11.3 Correlation versioning

Current triage documents use:

```json
{
  "schemaVersion": 2,
  "correlationVersion": "detector-and-alert-activity-window-v2"
}
```

Legacy detector-only triage remains preserved for audit but is not attached as current incident guidance.

### 11.4 Evidence-reference binding and fallback

Before model invocation, the worker assigns every in-scope detection an opaque run-local reference such as `DLPREF-000001`. The input already contains the event ID and the incident ID resolved by explicit alert lineage or the unique alert activity window. The hidden mandatory correlation envelope requires the model to echo:

- Every evidence reference and incident ID in `evidence_bindings`.
- Applicable `evidence_refs` on incident-triage and noise-pattern entries.

The worker validates echoed references against its own deterministic map; model-generated identifiers are never trusted as ownership evidence. If the model omits incident triage or pattern references:

1. A generic privacy-safe pattern from the same analysis batch may be associated with incidents deterministically known to be in that batch.
2. The association is marked `analysis-batch-fallback` and remains MEDIUM/INDETERMINATE pending review.
3. If a prior assessment has the identical period and incident lineage, its privacy-safe incident patterns may be reused only with `prior-same-scope-fallback` provenance.
4. No fallback may change event-to-alert or alert-to-incident ownership.

## 12. Reports and change plans

A run snapshot retains:

- Profile and policy
- SIT boundary
- Assessment label
- Start date, end date, and duration
- Privacy mode and source
- Analysis and reporting models
- Event, detection, and chunk counts
- Generated report

Reports should describe:

- Executive outcome
- Counting basis
- Workload context
- Department concentration and unresolved department coverage when available
- Noise taxonomy
- Validated findings and guardrails
- Recommended refinements
- Suppression strategy
- Validation approach
- Success metrics
- Incident triage

Privacy-safe change plans are cached against a completed baseline run. Plans generated from a protected Step 2 assessment are not cached by the server. All plans remain separate from deployment.

## 13. DLP Response investigation

### 13.1 Filters

- Date range
- Minimum confidence
- Workload
- Sensitive information type
- DLP policy
- Department resolved on demand from Microsoft Graph
- User
- Sender

### 13.2 Results

The results surface displays:

- Observed date
- User
- SIT
- Confidence
- Workload
- Policy
- Incident link
- Detection Assurance priority
- Privacy-safe security comment

### 13.3 Query behavior

- Streams redacted JSONL evidence.
- Resolves alert ownership before projecting detections.
- Excludes ambiguous or unmatched events.
- Applies configured scan, display, and plan caps.
- Redacts detected values before browser or plan use.

### 13.4 Department enrichment

Department is an optional, operator-triggered directory enrichment rather than a DLP event field.

1. The browser submits only unique valid UPNs from the current affected-user result.
2. The server caps the request using `maxDepartmentEnrichmentUsers`.
3. A PowerShell worker requests delegated `User.Read.All` and reads `displayName`, `department`, and `mail` from Microsoft Graph.
4. Results are merged into the local UPN-keyed directory cache.
5. The browser reruns the unchanged local DLP query so Department becomes available in affected-user rows and facets.

Enrichment does not require live-apply enablement because it performs no Graph mutation. Failed lookups and blank departments do not remove users from unfiltered results. A named Department filter matches only users with that exact cached department, using case-insensitive comparison.

## 14. Remediation plan

The remediation drawer summarizes:

- Detection count
- Affected-user count
- Incident count
- Selected SITs
- Scope warnings
- Affected users and their detection/incident counts

### 14.1 Selectable actions

1. **Tag and update incidents**
   - Adds workbench review tags.
   - Moves matching incidents to in progress.

2. **Email affected users**
   - Sends a standard privacy-safe review request.
   - Never inserts detected values automatically.

3. **Notify affected users in Microsoft Teams**
   - Uses a reviewed 1–4,000-character message.
   - Creates or reuses a one-to-one chat.
   - HTML-encodes the message.
   - Never inserts detected values automatically.

4. **Resolve low-risk incidents**
   - Requires incident updates to be selected.
   - Applies only to low-severity incidents.
   - Resolves as false positive with a bounded resolving comment.

### 14.2 Live execution gates

- Disabled by default.
- Requires server startup enablement.
- Requires the exact confirmation phrase.
- Requires final browser confirmation.
- Enforces maximum incident and user caps.
- Records plan and execution events in the ledger.

### 14.3 Microsoft Graph permissions

- Incident updates: `SecurityIncident.ReadWrite.All`
- Department enrichment: `User.Read.All` (read-only delegated directory lookup)
- Email: `Mail.Send`
- Teams: `Chat.Create`, `ChatMessage.Send`, `User.ReadBasic.All`

## 15. Response Studio

Response Studio stores only declarative, allow-listed flow objects. Supported actions:

- `incidentPatch`
- `emailAffectedUsers`
- `teamsNotifyAffectedUsers`

Arbitrary scripts and arbitrary Graph calls are rejected.

An incident patch can opt into `includeSitTriageComment`. Dry runs preview the Detection Assurance comment; confirmed live execution can add the reviewed comment to the Microsoft Graph incident. The comment is marked AI-generated and requiring human review.

Flows support:

- Create, edit, and delete
- Import and export
- Version history and restore
- AI-assisted drafting
- Required-scope derivation
- Dry-run-first execution
- Guarded live execution

## 16. Microsoft Foundry configuration

The browser can configure only non-secret values:

- Responses endpoint
- Reporting deployment
- Analysis deployment

Accepted endpoint hosts are restricted to supported Microsoft Foundry/Azure OpenAI domains. Environment variables override saved settings and are identified in the UI.

Secrets remain process-environment-only:

- `AZURE_OPENAI_REPORTING_KEY`
- Compatible existing Azure OpenAI key environment variables

The browser never accepts, returns, or persists the API key.

## 17. Local data stores

| Location | Purpose |
|---|---|
| `data/dlp-alerts-store.jsonl` | Alert resources compacted by alert ID |
| `data/dlp-events-store.jsonl` | Append-only redacted DLP events |
| `data/dlp-sync-state.json` | Synchronization watermark and counts |
| `data/protected/sit-sensitive-events.jsonl` | DPAPI-protected sensitive events |
| `data/sit-optimize/jobs/` | Background assessment state and logs |
| `data/sit-optimize/<profile>/runs/` | Run snapshots |
| `data/sit-optimize/<profile>/reports/` | Final reports |
| `data/sit-optimize/<profile>/implementation/` | Cached Purview plans |
| `data/sit-optimize/triage/` | Incident triage interchange |
| `data/plans/` | Remediation plans and bounded detections |
| `data/results/` | Guarded worker outputs |
| `data/ledger/execution-ledger.jsonl` | Operational audit events |
| `data/user-directory.json` | Local Graph-resolved user and department cache |

## 18. HTTP API surface

### Investigation and remediation

- `GET /api/health`
- `POST /api/dlp/query`
- `POST /api/dlp/collect`
- `POST /api/dlp/enrich-departments`
- `POST /api/remediation/plan`
- `POST /api/remediation/apply`

### Detection Assurance

- `GET /api/sit/summary`
- `GET /api/sit/catalog`
- `GET /api/sit/profiles`
- `GET /api/sit/profile`
- `PUT /api/sit/profile`
- `POST /api/sit/profile/draft`
- `GET /api/sit/scope`
- `POST /api/sit/capture`
- `POST /api/sit/analyze`
- `GET /api/sit/jobs`
- `GET /api/sit/runs`
- `GET /api/sit/report`
- `POST /api/sit/compare`
- `POST /api/sit/implementation`

### Response Studio

- `GET /api/response-flows`
- `PUT /api/response-flows`
- `POST /api/response-flows/import`
- `GET /api/response-flows/versions`
- `POST /api/response-flows/versions/:id/restore`
- `GET /api/response-flows/incidents`
- `POST /api/response-flows/ai-helper`
- `POST /api/response-flows/integration-code`
- `POST /api/flows/run`

### Configuration

- `GET /api/configuration/foundry`
- `PUT /api/configuration/foundry`

## 19. Security and privacy invariants

1. General evidence is redacted before persistence and browser use.
2. Protected evidence is stored separately with DPAPI CurrentUser protection.
3. Node does not decrypt or return raw protected event content.
4. Exact SIT scope fails closed.
5. Alert ownership fails closed when ambiguous or missing.
6. Legacy detector-only triage is not treated as current guidance.
7. Browser configuration never accepts secrets.
8. AI-drafted profiles require operator review and save.
9. AI-generated change plans do not deploy automatically.
10. Graph writes are disabled by default and explicitly confirmed.
11. Declarative response flows reject executable script fields.
12. Teams and email messages never include detected values automatically.
13. File identifiers are validated and resolved under configured directories.
14. Collection queries are not changed by local scope, lineage, or assessment logic.
15. Exact false-positive artifacts can enter Step 2 summaries only during an explicitly confirmed protected assessment. Step 3 may consume those persisted patterns, but they never enter incident comments or notification channels.
16. Department enrichment validates and caps UPN input, performs read-only Graph lookups, stores no token, and never changes source DLP evidence.
17. Detection Assurance may consume cached department names as organizational context only after identity redaction; department alone cannot authorize suppression.

## 20. Error and interruption behavior

- Missing or empty evidence prevents assessment.
- Empty SIT scope prevents profile execution.
- Invalid date ranges are rejected.
- Missing Foundry endpoint or key prevents AI operations.
- Protected mode is unavailable without captured evidence and exact confirmation.
- Dead background workers are reconciled from process state and logs.
- Interrupted jobs are marked failed with an operator-readable reason.
- Stale profile, report, plan, comparison, and asynchronous scope responses are not displayed after profile changes.
- Ambiguous event ownership is excluded rather than attributed to the wrong incident.
- Scan and execution caps produce warnings and prevent unsafe broad action.

## 21. Acceptance criteria

### Evidence and lineage

- Two alerts sharing one detector resolve only the events inside their respective activity windows.
- Explicit persisted alert lineage overrides temporal fallback when valid.
- An event outside every candidate alert window is excluded.
- A fixture incident resolves to its own alert and event, not all events sharing the detector.

### Classification boundary

- A profile with no selected SIT cannot run.
- An event with no selected SIT is excluded.
- An event containing selected and unselected SITs contributes only selected detections.
- AI cannot broaden the profile boundary.

### Assessment

- Inclusive UTC dates are retained in job, run, and report metadata.
- A bounded Credentials fixture resolves only the alerts, events, detections, and incidents in the selected period and exact SIT scope.
- Every represented incident receives at most one triage entry.
- Context-only triage cannot claim active credential validity.

### UX

- Profile authoring opens blank with zero SIT selections.
- Selecting an assessment profile does not populate the authoring form.
- Explicit edit and clear actions behave predictably.
- Reports and Purview plans remain bound to the selected profile.
- Job state reflects real worker state and stage progress.
- Remediation action controls remain aligned, readable, and keyboard-operable.
- Selecting Teams reveals a reviewed-message field.
- Department enrichment reruns the same local query and exposes resolved values in the Department facet and affected-user table.
- A failed or blank department lookup leaves the affected user visible when no Department filter is active.
- Detection Assurance scope preview shows department coverage, and new run snapshots retain resolved, unresolved, and unique-department counts.

### Response

- Plan generation performs no Graph mutation.
- Live execution fails when server enablement or confirmation is absent.
- Only explicitly selected actions execute.
- Teams messages are encoded, bounded, and sent only to scoped Entra users.
- Incident comments contain privacy-safe Detection Assurance rationale only.

## 22. Demo narrative

Recommended title:

> **From DLP Alert Volume to Measurable Detection Assurance**

Recommended sequence:

1. Open DLP Response and establish the synchronized evidence and incident lineage.
2. Show Detection Assurance exact boundary and period.
3. Open a completed Credentials report and explain a scoped credential finding.
4. Show a narrow context-aware recommendation and true-positive guardrails.
5. Generate or open the deployable Purview change plan.
6. Explain baseline versus post-change proof.
7. Return to DLP Response and preview incident, email, and Teams actions.
8. Close on redaction, fail-closed scope, protected evidence, and locked Graph writes.

Thirty-second description:

> Data Security Workbench is a control-assurance and response layer for Microsoft Purview. It connects DLP incidents to their underlying evidence, uses governed AI to distinguish credible exposure from systemic noise, creates reviewable Purview improvements, measures their effect against a baseline, and operationalizes response through incidents, email, and Teams. Evidence is redacted by default, classification boundaries fail closed, and Microsoft Graph writes remain explicitly controlled.

## 23. Future considerations

- Display incident counts directly in scope preview.
- Add a non-mutating remediation action preview with per-action recipient totals.
- Add audit-mode outcome ingestion after approved Purview changes.
- Add operator disposition feedback to improve later assurance runs.
- Add tenant-aware storage isolation for hosted operation.
- Move JSONL behind a storage abstraction if scale requires indexing.
- Add formal report and triage schema version migration tooling.
- Add policy-deployment adapters only with explicit review, authorization, validation, and rollback controls.
