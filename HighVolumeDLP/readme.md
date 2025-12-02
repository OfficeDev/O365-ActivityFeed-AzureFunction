# Credential Exposure Analyst — Quick Guide

> **Purpose:** Tools and guidance for finding, classifying, triaging, and optionally removing credential-like values discovered in Microsoft 365 mailboxes using Microsoft Graph + Azure OpenAI for classifier assistance.

---

## Overview

Two PowerShell scripts included in this toolkit:

* **`multithreadanalyst.ps1`** — Fetches mailbox messages via Microsoft Graph, extracts credential-related blocks, performs parallel AI analysis, produces a consolidated CSV and a triage Markdown summary. Optionally deletes source messages that contained confirmed exposures.
* **`testcredstest.ps1`** — Generates synthetic credential/token samples to measure classifier / regex coverage. Exports: full sample set, misses (what the classifier/regEx did not match), and a summary CSV for coverage metrics.

---

## Requirements

* **PowerShell 7+**
* Modules: `Microsoft.Graph.Authentication` (and `Microsoft.Graph` if needed)
* Graph OAuth scopes required for the analyst harness: `Mail.ReadWrite`, `Mail.ReadWrite.Shared`, `email`
* Azure OpenAI (or compatible) endpoint and API key available in environment variable `AZURE_OPENAI_API_KEY` (do not hardcode keys)
* Network access to Microsoft Graph endpoints and to your Azure OpenAI endpoint

---

## Setup

1. Install PowerShell 7+ and required modules:

```powershell
# Example (run as admin or with appropriate privileges)
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
# Optionally if scripts use Graph client calls directly:
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

2. Authenticate to Graph in a session used by the harness (example interactive):

```powershell
Connect-MgGraph -Scopes "Mail.ReadWrite Mail.ReadWrite.Shared email"
```

3. Set your Azure OpenAI environment variable in the host where the harness runs (do **not** store in repo):

```powershell
$env:AZURE_OPENAI_API_KEY = "<redacted>"  # prefer secure vault or environment
$AzureOpenAIApiUrl = "https://<your-resource>.openai.azure.com/"
```

---

## Usage

> **Note:** examples assume working directory contains the two scripts: `multithreadanalyst.ps1` and `testcredstest.ps1`.

### Run analyst (default — will delete matches unless `-SkipDelete` is provided)

```powershell
# Full run (may delete messages in batches unless you pass -SkipDelete)
.\multithreadanalyst.ps1 -Verbose

# Safer: keep messages and do not delete
.\multithreadanalyst.ps1 -SkipDelete -Verbose
```

### Generate synthetic classification set (harness)

```powershell
# Produces: <harness>_main.csv, .misses.csv, .summary.csv in the output folder
.\testcredstest.ps1 -OutDir .\harness_output -Verbose
```

---

## Typical Outputs

* `dlp_items_<ts>.log` — preview list of message IDs / subjects and extracted blocks.
* `dlp_firstpass_<ts>.csv` — consolidated AI-analyzed rows (one row per candidate extraction).
* `dlp_triage_<ts>.md` — triage-friendly risk summary in Markdown (human-readable findings & recommended actions).
* Harness outputs (from `testcredstest.ps1`): `harness_main_<ts>.csv`, `harness_main_<ts>.misses.csv`, `harness_main_<ts>.summary.csv`

---

## Core Logic Highlights

* **Body filter:** mailbox fetch filter only accepts messages containing both the strings `"Policy Name"` and `"Credentials"` to reduce noise.
* **Regex base:** `Report Id:.*` is used as a starting point for block extraction (tune to your environment).
* **Chunking & parallelism:** script chunks work and uses a runspace pool (default **4** runspace threads) for concurrent AI calls and analysis.
* **JWT decoding:** extracted JWTs are decoded for `exp` to surface likely-expired vs active tokens.
* **Repeat/fallback handling:** repeated credentials in a message reduce the overall risk score if they are identical repeats.
* **Batch deletes:** deletion (if enabled) is performed in batches of 20 messages per Graph request. Use `-SkipDelete` to avoid removals.

---

## Tuning

* Refine the Graph query filter or add a `$search` clause (depending on your Graph API usage) to further narrow fetched messages.
* Introduce a **master credential regex** that runs *before* AI classification to pre-cull obvious non-credential noise.
* Carefully adjust runspace pool size — raising threads increases throughput but may hit OpenAI or Graph rate limits.
* Add new synthetic types to `testcredstest.ps1` using `Get-SampleValue` and the `$types` array to expand coverage testing.

---

## Safety & Best Practices

* **Never** hardcode API keys in scripts or source control. Use environment variables or a secure vault.
* **Mask secrets** when writing logs — the harness masks secrets showing only first 4 + last 4 characters by default.
* Use `-SkipDelete` during initial audit runs to preserve evidence and allow review of true positives before remediation.
* Always **review the CSV output** before performing any automated remediation or deletion.

---

## Troubleshooting

| Symptom              | Action                                                                                                                                                      |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No CSV outputs       | Check Azure OpenAI API key, endpoint URL, and that the network can reach both Graph and OpenAI. Verify `Connect-MgGraph` session.                           |
| Many misses          | Extend or refine the master regex list and add more synthetic test cases to `testcredstest.ps1`. Consider increasing prompt examples for the AI classifier. |
| Slow run             | Reduce chunk size or threads, or run without AI classification to isolate Graph retrieval slowness.                                                         |
| Token refresh issues | Re-run `Connect-MgGraph` to refresh access tokens for Graph. Consider longer-lived app-only auth for unattended runs.                                       |

---

## Quick Rotation Actions (Post-Discovery)

1. Revoke any exposed **high-risk tokens** immediately (Azure AD app keys, service principal secrets, API keys).
2. Add DLP tuning keywords to reduce false positives and catch recurring test credential patterns.
3. Patch/extend regex, re-run the harness, and verify that `*.misses.csv` shrinks.

---

## Minimal Cleanup

Periodically archive or remove old `dlp_*` artifacts to keep the output directory manageable. Keep a secure archive of any evidence you must retain for incident response.

---

## One-Liner Quick Start

```powershell
# Quick run keeping messages (safe):
.\multithreadanalyst.ps1 -SkipDelete | Tee-Object -FilePath dlp_run_$(Get-Date -Format s).log
```

## Classification Harness — Quick Run

```powershell
# Generate synthetic cases and run classification harness analyses:
.\testcredstest.ps1 -OutDir .\harness_output; Get-ChildItem .\harness_output -File | Select-Object Name, Length
```

---

## License / Attribution

All generated credential values in `testcredstest.ps1` are **synthetic** and safe for testing. Do not use sample outputs as real secrets.

---

## Example Remediation Workflow (recommended)

1. Run harness with `-SkipDelete` and review `dlp_firstpass_<ts>.csv` manually.
2. Validate high-risk rows (check decoded exp for JWTs, confirm provider).
3. Revoke impacted credentials in identity platform(s).
4. Re-run the harness and confirm that revoked values now appear as expired or are no longer present.

---

*Created by the Credential Exposure Analyst toolkit — keep this README alongside the `multithreadanalyst.ps1` & `testcredstest.ps1` scripts.*
