# SIT Tuning Studio

A local toolkit for **tuning noisy Microsoft Purview DLP Sensitive Information Types (SITs)**.
It pulls your DLP alerts from Microsoft Graph, uses an AI model to separate *real* sensitive
findings from *noise* (false positives), and produces a prioritized report of regex/pattern
changes that cut alert volume **without dropping true positives**. A local web "Studio" lets
you author new analysis profiles, run the pipeline, compare runs round-over-round, read the
generated reports, and turn a report into a **click-by-click Purview implementation plan** — all
from the browser, with no data leaving your machine except the calls you make to your own AI
endpoint. Every page can be **exported to a self-contained HTML file** you can share with others.

> Everything runs locally. Your AI API key is read from an environment variable on the machine
> running the server and is **never** sent to the browser. DLP data is pulled directly to your
> machine via Microsoft Graph.

---

## What's in the box

| File / folder | Purpose |
|---|---|
| `credpattern.ps1` | The core pipeline: Graph alert pull → chunk → AI analysis → noise/true-positive report. Per-profile incremental cache. |
| `studio-server.ps1` | Local web server + JSON API that powers the browser UI (author/test/run profiles, browse reports). |
| `VisualFactorySIT.ps1` | Renders any `.md` report into a self-contained, styled HTML dashboard (no LLM, pure local Markdown). |
| `profiles/*.psd1` | Swappable **analysis profiles** (just instruction text). One per SIT family: `Credentials`, `PII`, `Financial`, `CreditCardNumber`. |
| `web/` | The browser UI: Profile Studio, Round-over-Round Delta, Report Viewer, and Implementation Guide pages + shared styles. |
| `web/export-html.js` | Shared helper that exports any page's report/plan to a **standalone, light, print-friendly HTML file** for sharing. |
| `web/sample-*.json`, `web/sample-report.html` | **Synthetic** sample run data + a prebuilt sample comparison report (safe demo data — no real detections). |

---

## Prerequisites

1. **PowerShell 7.0+** (`pwsh`). Check with `pwsh --version`.
2. **Microsoft Graph PowerShell SDK** (Authentication module is enough):
   ```powershell
   Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
   ```
3. **An Azure OpenAI (or OpenAI-compatible) Responses endpoint** plus a model deployment.
   This package was built against the Azure OpenAI **Responses API**
   (`/openai/responses?api-version=2025-04-01-preview`).
4. **Microsoft Graph permissions** — you sign in interactively. Your account (or an admin)
   must consent to the read-only scopes below. See **[Microsoft Graph permissions](#microsoft-graph-permissions)**
   for the full list, what each is for, and how to grant admin consent.
5. *(Optional)* **Node.js 18+** — only needed if you want to rebuild the self-contained sample
   report with `web/build/build-sample-report.js`.

---

## One-time setup

### 1. Set your AI API key (per shell session, or in your profile)

```powershell
$env:AZURE_OPENAI_API_KEY = '<your-azure-openai-key>'
# Optional: if AZURE_OPENAI_API_KEY2 is set it is preferred over AZURE_OPENAI_API_KEY.
```

The key is only read **server-side**. It is never written to disk or sent to the browser.

### 2. Point the tools at your AI endpoint

The default endpoint is a placeholder:

```
https://<your-resource>.cognitiveservices.azure.com/openai/responses?api-version=2025-04-01-preview
```

Set it once in any of these ways (in order of convenience):

- **From the UI** — start the server, open the *Server connection* panel, paste your endpoint + model.
- **At launch** — `./studio-server.ps1 -OpenAIEndpoint '<url>' -Model '<deployment>'`
- **Edit the default** — change the `$OpenAIEndpoint` / `$Model` defaults at the top of
  `studio-server.ps1` and `credpattern.ps1`.

---

## Quick start (web Studio)

```powershell
$env:AZURE_OPENAI_API_KEY = '<your-key>'
./studio-server.ps1
# opens http://localhost:8787/
```

Pages (linked from the top nav of each):

- **Profile Studio** (`/`) — author and run analysis profiles. Two tracks:
  - *Run & compare* — run an existing profile end-to-end, then compare on the Delta page.
  - *Create a new profile* — describe a SIT in plain language; the agent drafts a profile, you
    test the extraction prompt on sample text, edit, save, and run the full pipeline.
- **Round-over-Round Delta** (`/index.html`) — drop a **baseline** run snapshot and a **new** run
  snapshot to measure how much noise the new SIT rules suppressed, with a true-positive guardrail
  so you can spot if tuning accidentally dropped real findings. Try it now with the bundled
  `web/sample-baseline.json` and `web/sample-current.json`, or open `web/sample-report.html`
  directly for a prebuilt demo.
- **Report Viewer** (`/report-viewer.html`) — browse the Markdown reports cached from every
  pipeline run, rendered inline. Pick a run from the dropdown; copy the raw Markdown if you want.
- **Implementation Guide** (`/implementation.html`) — pick a completed run and the agent turns its
  noise-reduction report into an ordered, click-by-click **Microsoft Purview implementation plan**:
  which SIT rule to change, whether it is built-in (copy & tune the copy) or custom (edit directly),
  the exact regex / keyword / proximity / confidence / exception edits, how to test, and the
  rollout order. Plans are cached per run under `cache/<Profile>/implementation/`; *Regenerate*
  forces a fresh plan.

Every results page (**Delta**, **Report Viewer**, **Implementation Guide**) has an **Export HTML**
button that downloads a self-contained, styled HTML file — no server or internet needed to open it —
so you can hand the comparison, report, or plan to colleagues or print it to PDF.

Press **Ctrl+C** in the terminal to stop the server cleanly.

---

## Command-line usage (pipeline directly)

You can run the analysis without the UI:

```powershell
$env:AZURE_OPENAI_API_KEY = '<your-key>'

# Analyze the "Credentials" profile against all DLP alerts from the last 120 days
./credpattern.ps1 -AnalysisProfile Credentials `
                  -OpenAIEndpoint '<your-endpoint>' `
                  -Model '<your-deployment>'
```

Useful parameters:

| Parameter | Default | Notes |
|---|---|---|
| `-AnalysisProfile <Name>` | `Credentials` | Which `profiles/<Name>.psd1` to use. |
| `-ProfilePath <file>` | — | Use a profile file from any location instead of `-AnalysisProfile`. |
| `-dlpPolicy <name>` | from profile / `*` | Filter to a specific DLP policy. |
| `-DaysBack <n>` | `120` | Lookback window for the first/full pull. |
| `-MaxEvents <n>` | `1500` | Cap on events analyzed. |
| `-FullPull` | off | Rebuild the incremental cache from scratch. |
| `-TenantId <guid>` | — | Pin sign-in to a specific tenant. |
| `-Model <name>` | `gpt-5.4` | AI model/deployment name. |
| `-ThreadCount <n>` | `8` | Parallel chunk analysis (use `-DisableMultiThreading` to serialize). |
| `-Help` | — | Show built-in help. |

Output:
- `SIT_Report.md` in the working directory (the latest report).
- A timestamped copy + a full run snapshot in the per-profile cache (see below).

Render any report to a standalone HTML dashboard:

```powershell
./VisualFactorySIT.ps1            # converts every *.md in this folder to *.html
./VisualFactorySIT.ps1 -Force     # regenerate even if HTML is newer
```

---

## Analysis profiles

A profile is a `.psd1` data file (no executable code) describing the "language" the AI should use
for one SIT family. Required keys:

- `ExtractionInstruction` — how to pull candidate findings out of a chunk of alert text.
- `ConsolidationInstruction` — how to merge per-chunk results.
- `ReportMergeInstruction` — how to assemble the final report.
- *(optional)* `Name`, `Description`, `DlpPolicy` (default policy filter).

Create new ones from the Profile Studio UI, or copy an existing file under `profiles/` and edit.
Because they are pure data, they are safe to share and review.

---

## Microsoft Graph permissions

The pipeline reads DLP alerts and their events from Microsoft Graph using an **interactive
delegated sign-in** (`Connect-MgGraph`). It requests these **read-only** delegated scopes:

| Scope | Why it's needed | Graph endpoint(s) used |
|---|---|---|
| `SecurityAlert.Read.All` | Read the DLP alerts that drive the analysis. | `GET /beta/security/alerts_v2` |
| `SecurityEvents.Read.All` | Read the per-alert DLP detection events (the matched content metadata). | `GET /beta/security/dlpAlertEvent` |
| `CustomTags.Read.All` | Read tags attached to alerts (used for context in the report). | (alert tag fields) |

The tool also calls `GET /v1.0/me` once to confirm which account/tenant you signed in as
before pulling any data.

**Important characteristics:**

- **Read-only.** None of these scopes can modify, delete, or create alerts, events, or policies.
  The pipeline never writes back to Graph.
- **Delegated, not application.** Access is limited to what *your signed-in account* is allowed
  to see — there is no client secret or app credential stored anywhere in this package.
- **`.Read.All`** means "across the tenant," so the account still needs an appropriate Purview /
  security reading role (e.g. a Security Reader or Compliance/DLP reader role) to actually return
  data. Without a suitable role the calls succeed but return nothing.

### Granting admin consent

`*.Read.All` scopes typically require **admin consent** once per tenant. Options:

- **Interactive (first run):** if your account is a Global Administrator or has the
  *Privileged Role Administrator* role, the sign-in prompt will offer a "Consent on behalf of
  your organization" checkbox. Tick it once and subsequent users won't be prompted.
- **Have an admin pre-consent** to the three scopes for the **Microsoft Graph PowerShell**
  application (app ID `14d82eec-204b-4c2f-b7e8-296a70dab67e`) in
  *Entra ID → Enterprise applications → Microsoft Graph PowerShell → Permissions*.
- **Or grant from a Global Admin shell:**
  ```powershell
  Connect-MgGraph -Scopes 'SecurityAlert.Read.All','SecurityEvents.Read.All','CustomTags.Read.All'
  # accept the "consent on behalf of your organization" prompt
  ```

### Tenant selection

If your account exists in more than one directory, pin the sign-in to the right tenant:

```powershell
./credpattern.ps1 -AnalysisProfile Credentials -TenantId <tenant-guid>
```

The script prints the resolved account and tenant after sign-in so you can confirm you're
pointed at the correct directory before any data is pulled.

---

## Cache & run snapshots

Each run keeps **per-profile, incremental** state so repeat runs only pull what changed:

```
cache/
  <ProfileName>/
    events-store.jsonl     # durable, additive event cache
    alerts-store.jsonl     # durable, additive alert cache
    sync-state.json        # incremental watermark
    reports/
      report-<UTCstamp>.md # timestamped copy of each report
    runs/
      run-<UTCstamp>.json  # full run snapshot (report + metadata + per-chunk analyses)
      runs-manifest.json
    implementation/
      run-<UTCstamp>.md    # cached AI implementation plan for that run
```

The `cache/` folder is **machine/tenant-specific and is intentionally excluded from this package.**
It is created automatically on first run. The Report Viewer, Delta page, and Implementation Guide
read from these snapshots.

---

## Security & privacy notes

- **AI key** stays on the server (`$env:AZURE_OPENAI_API_KEY[2]`); it is never sent to the browser
  or written to disk.
- **DLP data** is pulled from Microsoft Graph directly to the machine running `credpattern.ps1`
  and stored only in the local `cache/` folder.
- **AI calls** go to *your* configured endpoint only. Review your AI provider's data-handling
  terms before sending production alert text.
- The server binds to `localhost` and serves static files only from `web/`; the report API
  validates profile/file names against strict patterns before reading any snapshot.
- The bundled sample data (`web/sample-*.json`) is **synthetic** — fabricated patterns, no real
  secrets or tenant detections.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `You must set the $env:AZURE_OPENAI_API_KEY ...` | Set the env var in the same shell before launching. |
| `Analysis profile not found` | Check the name matches a file under `profiles/` (case-sensitive on some systems). |
| AI calls fail with HTTP 401/404 | Verify `-OpenAIEndpoint` and `-Model` match your deployment; the pipeline now throws the underlying API error body so the real reason is visible. |
| No alerts returned | Widen `-DaysBack`, confirm the `-dlpPolicy` filter, or run with `-FullPull` to rebuild the cache. |
| Graph sign-in uses the wrong directory | Pass `-TenantId <guid>`. |
| Report Viewer is empty | Run a profile first — reports appear after the pipeline writes a run snapshot. |

---

## Notes for adopters

- Update the `$OpenAIEndpoint` / `$Model` defaults (or pass them at runtime) to your own
  Azure OpenAI resource and deployment.
- Review and adapt the profiles under `profiles/` to your organization's SITs and policies.
- The Graph scopes are read-only; the pipeline does not modify alerts or policies.
