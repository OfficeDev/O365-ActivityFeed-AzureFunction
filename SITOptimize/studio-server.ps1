#requires -Version 7.0
<#
.SYNOPSIS
    Local web server for the SIT Tuning Profile Studio.

.DESCRIPTION
    Serves the static pages under .\web and exposes a small JSON API the
    Profile Studio page calls in the browser. Everything runs locally:

      GET  /                      -> web/profile-studio.html
      GET  /<file>                -> static file from web/
      POST /api/agent             -> draft a profile (Azure OpenAI)
      POST /api/test              -> run the extraction prompt on sample text
      POST /api/save              -> write profiles/<Name>.psd1
      POST /api/run               -> launch credpattern.ps1 with a profile
      GET  /api/profiles          -> list existing profiles
      GET  /api/health            -> connection / key status

    The Azure OpenAI key is read from $env:AZURE_OPENAI_API_KEY on THIS
    machine and never sent to the browser. Because the page is served by
    this server, the API calls are same-origin (no CORS, no key in the tab).

.EXAMPLE
    $env:AZURE_OPENAI_API_KEY = '<your-key>'
    .\studio-server.ps1
    # then open http://localhost:8787/
#>
param(
    [int]$Port = 8787,
    [string]$OpenAIEndpoint = "https://<your-resource>.cognitiveservices.azure.com/openai/responses?api-version=2025-04-01-preview",
    [string]$Model = "gpt-5.4",
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'

$root      = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$webDir    = Join-Path $root 'web'
$profDir   = Join-Path $root 'profiles'
$cacheDir  = Join-Path $root 'cache'
$scriptPS1 = Join-Path $root 'credpattern.ps1'

if (-not (Test-Path $webDir))  { throw "web/ folder not found at $webDir" }
if (-not (Test-Path $profDir)) { New-Item -ItemType Directory -Path $profDir | Out-Null }

# ---------------------------------------------------------------------------
# Report cache helpers
# ---------------------------------------------------------------------------
function ConvertTo-ReportHtml {
    <# Render markdown to HTML using the built-in Markdig-backed converter. #>
    param([string]$Markdown)
    if ([string]::IsNullOrWhiteSpace($Markdown)) { return '' }
    try {
        return (ConvertFrom-Markdown -InputObject $Markdown).Html
    } catch {
        # Fallback: HTML-escape and keep line breaks so the viewer still shows something.
        $esc = [System.Net.WebUtility]::HtmlEncode($Markdown)
        return "<pre>$esc</pre>"
    }
}

function Get-CachedReports {
    <# Enumerate run snapshots across every per-profile cache, newest first.
       Each run-*.json carries the final report markdown + rich metadata. #>
    $reports = [System.Collections.Generic.List[object]]::new()
    if (-not (Test-Path $cacheDir)) { return $reports }
    foreach ($slugDir in (Get-ChildItem $cacheDir -Directory -ErrorAction SilentlyContinue)) {
        $runsDir = Join-Path $slugDir.FullName 'runs'
        if (-not (Test-Path $runsDir)) { continue }
        foreach ($run in (Get-ChildItem $runsDir -Filter 'run-*.json' -ErrorAction SilentlyContinue)) {
            try {
                $snap = Get-Content -LiteralPath $run.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
            } catch { continue }
            $hasReport = -not [string]::IsNullOrWhiteSpace([string]$snap.finalReport)
            $reports.Add([pscustomobject]@{
                slug              = $slugDir.Name
                file              = $run.Name
                profile           = [string]($snap.profile ?? $slugDir.Name)
                label             = [string]($snap.label ?? $run.BaseName)
                generatedAt       = [string]$snap.generatedAt
                dlpPolicy         = [string]$snap.dlpPolicy
                rawDetectionCount = $snap.rawDetectionCount
                chunkCount        = $snap.chunkCount
                hasReport         = $hasReport
                mtime             = $run.LastWriteTimeUtc.ToString('o')
            })
        }
    }
    return ($reports | Sort-Object { $_.mtime } -Descending)
}

# ---------------------------------------------------------------------------
# Purview DLP implementation guide
# ---------------------------------------------------------------------------
# Turns a finished noise-reduction report into a concrete, click-by-click
# plan an admin can execute in the Microsoft Purview portal. The hard-won
# domain knowledge lives in the system prompt below. The key nuance: a built-in
# SIT cannot be edited IN PLACE, but most can be COPIED and the copy tuned
# (supporting keywords, character proximity, confidence/accuracy) — for many
# detections (e.g. Credit Card Number) copying and tuning the copy is the
# recommended fix. Fully custom SITs are editable end-to-end including the
# primary regex. DLP RULE controls (instance count, confidence, exceptions)
# are always available regardless of SIT type.
$purviewImplementationPrompt = @'
You are a **Microsoft Purview Data Loss Prevention implementation engineer**. You are handed a
completed SIT (Sensitive Information Type) noise-reduction analysis for one DLP policy. Your ONLY
job is to turn its findings into a precise, step-by-step implementation plan an administrator can
execute in the Microsoft Purview portal to reduce false positives WITHOUT dropping true positives.

Output Markdown only. Be concrete and operational, not theoretical. Never restate the analysis;
translate it into actions.

=====================================================================
CRITICAL DOMAIN MODEL — a Purview SIT is one or more PATTERNS. Each pattern has a CONFIDENCE LEVEL
and a PRIMARY ELEMENT, plus optional SUPPORTING ELEMENTS within a CHARACTER PROXIMITY window, plus
optional ADDITIONAL CHECKS. Confidence maps to an accuracy number: Low = 65 or below, Medium = 75,
High = 85. You tune a SIT in one of THREE places, plus the DLP rule. Choose the right one:
=====================================================================

WHAT THE SIT PATTERN EDITOR ACTUALLY EXPOSES (use these precise knobs — do not under-sell them):
- **Element types** (for primary and supporting elements): Regular expression, Keyword list,
  Keyword dictionary, or Functions (built-in Func_* validators, e.g. checksum/date functions).
- **Element groups**: combine elements as **Any of these** (OR), **All of these** (AND), or
  **Not any of these** (NONE — a real NEGATIVE/exclusion group). "Not any of these" lets you say
  "match the primary UNLESS one of these noise terms/patterns is also present" — use it to kill
  context-specific false positives without weakening the true-positive shape.
- **Character proximity**: "Detect primary AND supporting elements within N characters" (tighten,
  e.g. 150-300) — or toggle **Anywhere in the document** when supporting context is legitimately
  far away. Tighter proximity = fewer coincidental corroborations = fewer FPs.
- **Additional checks** (per pattern — powerful precision filters, often the cleanest FP fix):
    * **Exclude specific values** — drop known noise/test/sample literals outright.
    * **Starts / doesn't start with characters** — require or forbid a leading prefix.
    * **Ends / doesn't end with characters** — require or forbid a trailing suffix.
    * **Exclude duplicate characters** — drop matches like 0000-0000 / 1111111111.
    * **Include or exclude prefixes** — only count (or never count) a match next to given prefixes.
    * **Include or exclude suffixes** — only count (or never count) a match next to given suffixes.
- **Confidence level** per pattern (Low/Medium/High) — high-confidence patterns require more
  corroboration; route the DLP rule to the confidence that holds true positives but sheds noise.
=========================================================================

TIER 1 — BUILT-IN SIT, EDITED IN PLACE: NOT POSSIBLE.
   Microsoft-provided SITs (e.g. "Credit Card Number", "U.S. Social Security Number (SSN)",
   "Azure Storage Account Key", "All Full Names", named-entity bundles) are read-only as shipped.
   You cannot change the original definition. Do NOT tell the admin to edit the built-in directly.

TIER 2 — COPY THE BUILT-IN SIT AND TUNE THE COPY (the preferred fix for most built-ins, e.g.
   Credit Card Number). In the portal: open the built-in SIT -> **Copy** -> you now have an
   editable custom SIT with the full pattern editor above. On the copy you CAN:
     1. Adjust **supporting elements**: add corroborating keywords/dictionaries (e.g. "credit",
        "card", "cvv", "exp") or remove ones that drive noise; combine them as Any/All/Not-any.
     2. Add a **"Not any of these" supporting group** to exclude context-specific noise (e.g. test
        banners, sample-data markers) without touching the primary detection.
     3. Tighten the **character proximity** window so the primary match only counts when context is
        nearby (e.g. 150-300 characters).
     4. Add **Additional checks** on the copy: Exclude specific values (known test/sample literals),
        Exclude duplicate characters (kill 0000.../1111...), require/forbid prefixes & suffixes,
        starts/ends-with constraints — these are precise, low-risk FP cutters.
     5. Raise the **confidence/accuracy** so weak matches drop out (Low<=65 / Medium=75 / High=85),
        and point the DLP rule at High confidence.
     6. For function-based primaries (Func_*) you generally CANNOT rewrite the function itself, but
        you tune everything around it (supporting elements, groups, proximity, additional checks,
        confidence). If the primary is a plain regex on the copy, you may also tighten that regex
        (show BEFORE / AFTER) — but keep it forward-matching only; never add lookbehind/lookahead.
   Then repoint the DLP rule from the built-in to your tuned copy. ALWAYS name this as
   "copy & tune" and state that the original built-in stays untouched (instant rollback).

TIER 3 — FULLY CUSTOM SIT (created in your tenant): everything is editable.
     1. **Primary element:** choose regex / keyword list / keyword dictionary / function. For a
        regex, tighten it — anchor it, restrict character classes, add word boundaries, require
        structure — to remove the false-positive shape. Show BEFORE / AFTER.
        **DO NOT put exclusions inside the regex.** Never use lookbehind ((?<=...) / (?<!...)) or
        lookahead ((?=...) / (?!...)) in the primary pattern: Purview's regex engine does not
        reliably support them and they silently fail or behave unexpectedly (a lookbehind can make
        the whole pattern stop matching, dropping real true positives). Keep the regex a plain,
        forward-matching pattern that describes the entity shape. Do ALL exclusion logic OUTSIDE the
        regex — via a **"Not any of these"** group and the **Additional checks** (Exclude specific
        values, doesn't-start/end-with, exclude prefixes/suffixes).
     2. **Supporting elements + groups + proximity:** require corroborating keywords/regex within a
        character window; use **Any of these** / **All of these** to set how much corroboration is
        needed, and **Not any of these** to EXCLUDE noise terms/patterns near the match.
     3. **Additional checks:** Exclude specific values, Exclude duplicate characters, starts/ends
        with (or doesn't), include/exclude prefixes & suffixes — use these for surgical FP removal.
     4. **Confidence levels:** route corroborated matches to High; let weak matches fall lower.
     5. **Keywords:** add corroborating, remove over-broad, use a dictionary when large.
   The SIT editor DOES support exclusions — but do them with "Not any of these" groups and the
   Additional checks, NOT with regex lookbehind/lookahead. Prefer these targeted exclusions plus
   requiring more corroboration over loosening the primary pattern.

ALWAYS AVAILABLE — DLP RULE CONTROLS / PREDICATE EXCEPTIONS (work for any SIT type, built-in or
custom, with no SIT edit). Crucially, the exception predicates you can use DEPEND ON THE WORKLOAD
the rule covers (Exchange email, SharePoint/OneDrive, Teams chat & channel, Endpoint/Devices):
     1. Raise the **minimum instance count** (e.g. require 5+ matches instead of 1).
     2. Require a higher **confidence level** on the SIT condition (Low -> Medium -> High).
     3. Add **predicate exceptions** ("Add exception" / NOT conditions) directly in the rule. Pick
        predicates that exist for the rule's workload(s):
        - **Exchange / email:** except if sender / recipient is (domain, group, member);
          except if sender IP is in range; except if subject/body/header contains words or matches
          a pattern; except by attachment type/extension/size.
        - **SharePoint / OneDrive:** except if document property / managed-metadata matches; except
          by site / library / path; except by file extension or file name; except by sensitivity label.
        - **Teams (chat & channel):** except by sender / recipient (internal vs external); except if
          content contains words/patterns.
        - **Endpoint / Devices:** except by file path / file extension; except by app or browser;
          except by network/domain. (Many email-only predicates like sender/recipient do NOT exist
          here.)
        Common noise exceptions: except when content contains `test`, `sample`, `example`,
        `dummy`; except for known service/noreply senders; except for a docs/templates site.
   Use rule controls and predicate exceptions as the zero-risk quick win, and/or alongside a
   copy-and-tune. ALWAYS match the exception predicate to the workload — never propose a
   sender/recipient exception for a SharePoint-only or Endpoint-only rule.

CRITICAL — SAFE EXCEPTION TERMS (avoid mass false exclusions):
A "content contains words/phrases" exception is a SUBSTRING match applied to the WHOLE item. A
short, generic, or fragmented term silently suppresses huge volumes of legitimate matches (real
true positives), which is far worse than a false positive. Treat every content-keyword exception
as high-risk and follow these rules:
- NEVER use fragmentary or structural substrings as exception terms — e.g. `&p=`, `?e=`, `&s=`,
  `=`, `id=`, `LinkId=`, `destination=`, `http`, `www`, `.com`, single words like `link`, `token`,
  `key`, `id`, `user`. These appear in normal content everywhere and will gut detection.
- DO NOT split a known noise string into pieces (e.g. breaking a URL into `&p=` + `destination=`).
  Matching the pieces matches everything; only the FULL, distinctive string is safe.
- Prefer **specific, long, distinctive, anchored** terms: a full unique host/FQDN
  (`safelinks.protection.outlook.com`), a complete unique product/banner phrase, or a full unique
  template sentence — something that essentially only ever appears in the noise source.
- Strongly PREFER a **structural predicate over a content keyword** whenever one exists for the
  workload: sender domain / URL domain / header value (Exchange), site or path (SharePoint),
  file path/extension (Endpoint). These are precise and do not substring-scan the whole body.
- For each exception term you DO propose, you MUST state why it is safe (why it will not appear in
  genuine sensitive content) and call out any residual true-positive-suppression risk.
- When in doubt, prefer raising instance count / confidence, or tightening the SIT (copy & tune),
  over a content-keyword exception.
- PREFER an in-SIT exclusion over a rule content-keyword exception when the noise has a stable
  shape: the SIT's **Exclude specific values**, **Not any of these** group, **Exclude duplicate
  characters**, or prefix/suffix rules are scoped to the matched entity (precise), whereas a rule
  "content contains" exception scans the WHOLE item (blunt). Reach for the rule exception only for
  routing/metadata noise (sender, site, path, extension) the SIT can't see.

DECIDE PER FINDING:
- Built-in SIT with noisy CONTEXT (placeholders, test data, low corroboration) -> **copy & tune**
  the SIT (Tier 2): tighten proximity, add corroboration, add a **Not any of these** group or
  **Exclude specific values** for the noise, raise confidence — and/or add **rule thresholds**.
- Custom SIT with a noisy PATTERN shape -> **edit the regex/supporting elements + additional
  checks** (Tier 3); use Exclude specific values / Exclude duplicate characters / prefix-suffix
  rules to cut the shape precisely.
- Need a fast, reversible win -> **DLP rule** instance count / confidence / predicate exceptions
  first. When you recommend a predicate exception, state the WORKLOAD it applies to and pick a
  predicate that exists for that workload (the noise findings carry a source_workload — use it).
If you cannot tell whether a named SIT is built-in or custom, INFER from the name (well-known
Microsoft names = built-in) and STATE the assumption; default built-ins to the copy-and-tune path.

=====================================================================
PORTAL NAVIGATION (label clearly; UI labels can shift between compliance.microsoft.com and the
Microsoft Purview portal)
=====================================================================
- Copy & tune a built-in SIT:  Microsoft Purview portal -> Data classification -> Classifiers ->
  Sensitive info types -> <built-in SIT> -> **Copy** -> edit the copy's pattern: Confidence level,
  Primary element, Supporting elements/groups (Any/All/Not-any), Character proximity, and
  **Add additional checks** (Exclude specific values, Starts/Ends with, Exclude duplicate
  characters, Include/Exclude prefixes & suffixes) -> Test -> Save/Publish -> repoint the rule.
- Edit a custom SIT:  ... -> Sensitive info types -> <custom SIT> -> Edit -> edit pattern
  (Primary element, Supporting elements/groups, Confidence, Character proximity, Additional checks)
  -> Test -> Save/Publish.
- Tune a DLP rule:  Microsoft Purview portal -> Data Loss Prevention -> Policies -> <policy> ->
  Edit policy -> <rule> -> Edit -> Conditions / Exceptions -> adjust instance count, confidence,
  and add exceptions.

=====================================================================
REQUIRED OUTPUT STRUCTURE (Markdown)
=====================================================================
# Purview DLP Implementation Plan — <policy name>

## At a glance
One short paragraph: how many changes, projected FP reduction, and the single highest-impact action.
A table summarising every change:
| # | Target SIT rule | SIT type (built-in / custom / unknown) | Fix location (copy & tune SIT / edit custom SIT / DLP rule) | Workload (Exchange / SharePoint / OneDrive / Teams / Endpoint / all) | Change type (regex / keyword / proximity / confidence / instance count / exception) | Est. FP reduction | True-positive risk |

## Prioritised changes
For EACH change, a numbered subsection with this exact shape:
### N. <short title> — <Target SIT rule>
- **SIT type:** built-in / custom / unknown (assumed …)
- **Fix location:** copy & tune the SIT (Tier 2) / edit the custom SIT (Tier 3) / DLP rule control.
  If built-in, explicitly say the original stays untouched and the rule is repointed to the copy.
- **Workload:** which workload(s) this applies to (from the finding's source_workload). If the fix
  is a DLP predicate exception, name the workload-specific predicate you are using (e.g. Exchange
  sender domain, SharePoint site/path, Endpoint file extension) — and only one that exists for that
  workload.
- **Why:** the false-positive pattern this removes (1-2 lines, from the findings).
- **Where:** the exact portal path (from the navigation list above).
- **Steps:** numbered, click-by-click. For regex/keyword edits show **Before** and **After** in
  fenced code blocks. For proximity/confidence give the exact value (e.g. proximity 300, confidence
  High = 85). For rule controls give the exact exception/threshold to set.
- **Exception safety (only if the fix adds a content-keyword exception):** list each term and a
  one-line justification of why it is distinctive enough that it will NOT appear in genuine
  sensitive content. Use full, specific strings (full FQDNs/phrases), never fragments like `&p=` or
  `id=`. If a structural predicate (sender/URL domain, site, path, extension) would be safer, say so
  and prefer it.
- **Test:** how to verify in the Purview SIT **Test** tool and/or DLP **simulation / test mode**
  before enforcing.
- **Expected impact:** approximate FP reduction and any true-positive risk to watch.

## Validation & rollout
- Use **simulation / test mode** (alerts without enforcement) first; compare alert volume
  before/after (the Delta page in this tool can quantify it).
- Note propagation time: SIT/rule changes can take up to ~1 hour (sometimes longer) to take effect
  and require re-crawl for data-at-rest.
- **Rollback:** built-in originals are never edited; for copies and rules, keep the prior version so
  you can revert instantly.

## Sequencing
Ordered checklist of what to ship first (highest impact + zero true-positive risk), then next.

RULES:
- Ground every recommendation in the supplied findings (use the real SIT rule names, patterns, and
  counts that appear there). Do not invent SIT rules that are not referenced.
- Prefer the changes with the largest false-positive reduction and the lowest true-positive risk.
- For built-in SITs, never instruct editing the original in place — use copy & tune or rule controls.
- Be explicit and copy-pasteable. An admin should be able to follow this without re-reading the
  analysis.
'@

function Get-ImplementationGuide {
    <# Generate (and cache) a Purview implementation plan from a run snapshot's
       finished noise-reduction report. Cached as a sidecar markdown file next
       to the run so repeat views are instant; pass -Refresh to regenerate. #>
    param(
        [string]$Slug,
        [string]$File,
        [string]$ModelName,
        [string]$Endpoint,
        [switch]$Refresh
    )
    $runPath = Join-Path (Join-Path $cacheDir $Slug) (Join-Path 'runs' $File)
    if (-not (Test-Path -LiteralPath $runPath)) {
        return @{ ok = $false; error = "Report not found: $Slug/$File" }
    }
    try {
        $snap = Get-Content -LiteralPath $runPath -Raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return @{ ok = $false; error = "Failed to read snapshot: $($_.Exception.Message)" }
    }
    $sourceReport = [string]$snap.finalReport
    if ([string]::IsNullOrWhiteSpace($sourceReport)) {
        return @{ ok = $false; error = 'This run has no saved report to build an implementation plan from.' }
    }

    $implDir = Join-Path (Join-Path $cacheDir $Slug) 'implementation'
    $cacheFile = Join-Path $implDir ($File -replace '\.json$', '.md')

    if (-not $Refresh -and (Test-Path -LiteralPath $cacheFile)) {
        $cachedMd = Get-Content -LiteralPath $cacheFile -Raw
        return @{
            ok          = $true
            cached      = $true
            profile     = [string]($snap.profile ?? $Slug)
            dlpPolicy   = [string]$snap.dlpPolicy
            generatedAt = [string]$snap.generatedAt
            markdown    = $cachedMd
            html        = (ConvertTo-ReportHtml $cachedMd)
        }
    }

    $policy = if (-not [string]::IsNullOrWhiteSpace([string]$snap.dlpPolicy)) { [string]$snap.dlpPolicy } else { [string]($snap.profile ?? $Slug) }
    $userPrompt = @"
DLP policy: $policy
Sensitive information domain / profile: $([string]($snap.profile ?? $Slug))

Below is the completed SIT noise-reduction analysis report for this policy. Produce the Purview
implementation plan exactly as specified.

----- BEGIN ANALYSIS REPORT -----
$sourceReport
----- END ANALYSIS REPORT -----
"@

    try {
        $md = Invoke-OpenAI -SystemPrompt $purviewImplementationPrompt -UserPrompt $userPrompt -MaxOutputTokens 16000 -ModelName $ModelName -Endpoint $Endpoint
    } catch {
        return @{ ok = $false; error = "Implementation plan generation failed: $($_.Exception.Message)" }
    }
    if ([string]::IsNullOrWhiteSpace($md)) {
        return @{ ok = $false; error = 'The model returned an empty implementation plan.' }
    }

    try {
        if (-not (Test-Path $implDir)) { New-Item -ItemType Directory -Path $implDir -Force | Out-Null }
        Set-Content -LiteralPath $cacheFile -Value $md -Encoding UTF8
    } catch { <# caching is best-effort #> }

    return @{
        ok          = $true
        cached      = $false
        profile     = [string]($snap.profile ?? $Slug)
        dlpPolicy   = [string]$snap.dlpPolicy
        generatedAt = [string]$snap.generatedAt
        markdown    = $md
        html        = (ConvertTo-ReportHtml $md)
    }
}

# ---------------------------------------------------------------------------
# Azure OpenAI call (mirrors credpattern.ps1 Analyze-Data)
# ---------------------------------------------------------------------------
function Resolve-OpenAIKey {
    <#
        Single source of truth for which credential the server uses.
        Prefers AZURE_OPENAI_API_KEY2 (matches credpattern.ps1), then falls back
        to AZURE_OPENAI_API_KEY, so the server and pipeline use the same key.
        Returns: @{ Key=<string|$null>; Source=<'AZURE_OPENAI_API_KEY2'|'AZURE_OPENAI_API_KEY'|$null> }
    #>
    if ($env:AZURE_OPENAI_API_KEY2 -and $env:AZURE_OPENAI_API_KEY2 -notlike '*REPLACE*') {
        return @{ Key = $env:AZURE_OPENAI_API_KEY2; Source = 'AZURE_OPENAI_API_KEY2' }
    }
    if ($env:AZURE_OPENAI_API_KEY -and $env:AZURE_OPENAI_API_KEY -notlike '*REPLACE*') {
        return @{ Key = $env:AZURE_OPENAI_API_KEY; Source = 'AZURE_OPENAI_API_KEY' }
    }
    return @{ Key = $null; Source = $null }
}

function Test-OpenAIConnection {
    <#
        Performs a real, minimal call against the configured endpoint to prove
        the credential actually works (not just that an env var is set).
        Returns: @{ ok=<bool>; status=<int|$null>; source=<string|$null>; error=<string|$null> }
    #>
    param([string]$ModelName, [string]$Endpoint)

    $resolved = Resolve-OpenAIKey
    if (-not $resolved.Key) {
        return @{ ok = $false; status = $null; source = $null; error = 'No API key set (AZURE_OPENAI_API_KEY2 or AZURE_OPENAI_API_KEY).' }
    }
    if (-not $ModelName) { $ModelName = $Model }
    if ([string]::IsNullOrWhiteSpace($Endpoint)) { $Endpoint = $OpenAIEndpoint }

    $payload = @{
        input             = @(@{ role = 'user'; content = @(@{ type = 'input_text'; text = 'ping' }) })
        max_output_tokens = 16
        model             = $ModelName
    } | ConvertTo-Json -Depth 12
    $headers = @{ 'Content-Type' = 'application/json'; 'api-key' = $resolved.Key }

    try {
        Invoke-RestMethod -Method POST -Uri $Endpoint -Headers $headers -Body $payload -TimeoutSec 20 | Out-Null
        return @{ ok = $true; status = 200; source = $resolved.Source; error = $null }
    } catch {
        $status = $null
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $status = [int]$_.Exception.Response.StatusCode.value__
        }
        $msg = switch ($status) {
            401     { 'Key rejected (401) - the credential is set but not valid for this endpoint.' }
            403     { 'Forbidden (403) - the credential lacks access to this resource/model.' }
            404     { 'Endpoint or model not found (404) - check the endpoint URL and model name.' }
            429     { 'Rate limited (429) - the resource is reachable but throttling.' }
            default { $_.Exception.Message }
        }
        return @{ ok = $false; status = $status; source = $resolved.Source; error = $msg }
    }
}

function Invoke-OpenAI {
    param(
        [string]$SystemPrompt,
        [string]$UserPrompt,
        [int]$MaxOutputTokens = 16000,
        [string]$ModelName,
        [string]$Endpoint
    )
    $resolved = Resolve-OpenAIKey
    $apiKey = $resolved.Key
    if (-not $apiKey) {
        throw "No API key set on the server (AZURE_OPENAI_API_KEY2 or AZURE_OPENAI_API_KEY)."
    }
    if (-not $ModelName) { $ModelName = $Model }
    if ([string]::IsNullOrWhiteSpace($Endpoint)) { $Endpoint = $OpenAIEndpoint }

    $payload = @{
        input = @(
            @{ role = 'system'; content = @(@{ type = 'input_text'; text = $SystemPrompt }) },
            @{ role = 'user';   content = @(@{ type = 'input_text'; text = $UserPrompt }) }
        )
        max_output_tokens = $MaxOutputTokens
        model             = $ModelName
    } | ConvertTo-Json -Depth 12

    $headers = @{ 'Content-Type' = 'application/json'; 'api-key' = $apiKey }

    $maxRetries = 3
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        try {
            $resp = Invoke-RestMethod -Method POST -Uri $Endpoint -Headers $headers -Body $payload
            return ($resp.output.content.text -join "`n")
        } catch {
            $status = $null
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $status = [int]$_.Exception.Response.StatusCode.value__
            }
            if ($status -eq 429 -and $attempt -lt $maxRetries) {
                Start-Sleep -Seconds 20
                continue
            }
            if ($attempt -ge $maxRetries) { throw }
        }
    }
}

# ---------------------------------------------------------------------------
# Canonical JSON schema the extraction prompt MUST keep verbatim so the delta
# tool and report consolidation keep working across every profile.
# ---------------------------------------------------------------------------
$canonicalSchema = @'
{
    "credential_summary": {
        "total_credentials_identified": 0,
        "validated_credential_count": 0,
        "credential_pair_count": 0,
        "counting_method": ""
    },
  "noise_patterns": [
    {
      "pattern": "",
      "triggering_sit_rule": "",
      "reason_false_positive": "",
      "occurrence_count": 0,
      "shannon_entropy": 0.0,
      "source_workload": "",
      "noise_signal_keywords": [],
      "suppression_strategy": "",
      "estimated_fp_reduction": 0
    }
  ],
  "validated_credentials": [
    {
      "pattern": "",
      "type": "",
      "triggering_sit_rule": "",
      "validity_status": "ACTIVE|EXPIRED|TRUNCATED|REVOKED|INDETERMINATE",
      "shannon_entropy": 0.0,
      "proximity_keywords": [],
      "source_workload": "",
      "content_type": "",
      "confidence_justification": "",
      "count": 0,
      "risk_level": "HIGH|MEDIUM|LOW"
    }
  ],
  "credential_pairs": [
    {
      "components": ["primary_pattern", "secondary_pattern"],
      "pair_type": "",
      "source_workload": "",
      "risk_level": "HIGH|MEDIUM|LOW",
      "count": 0
    }
  ],
  "low_frequency_patterns": [
    {
      "pattern": "",
      "count": 0,
      "shannon_entropy": 0.0,
      "reason": "",
      "classification": "NOISE|INVESTIGATE|TRUE_POSITIVE",
      "exclusion_rule_candidate": ""
    }
  ],
  "regex_refinements": [
    {
      "triggering_sit_rule": "",
      "current_regex": "",
      "improved_regex": "",
      "false_positive_reduction": "",
      "false_negative_risk": ""
    }
  ],
  "multi_encoded_artifacts": [
    {
      "pattern": "",
      "encoding_layers": [],
      "reason_false_positive": "",
      "count": 0
    }
  ],
  "workload_context": [
    {
      "workload": "",
      "location": "",
      "content_field": "",
      "full_recipients": [],
      "content_info": "",
      "detected_values_count": 0,
      "user_id": "",
      "sender": "",
      "sensitive_type_name": "",
      "subject": "",
      "risk_assessment": ""
    }
  ],
  "exclusion_rules": [{"rule": "", "scope": "", "reason": ""}],
  "recommendations": "..."
}
'@

# ---------------------------------------------------------------------------
# Agent: turn a SIT description into a full profile (3 instruction blocks)
# ---------------------------------------------------------------------------
function New-ProfileDraft {
    param([hashtable]$Spec, [string]$ModelName, [string]$Endpoint)

    $sys = @"
You are an expert in Microsoft Purview Data Loss Prevention and Sensitive
Information Type (SIT) tuning. You write the domain-specific "language" (the
analysis prompts) used by an automated SIT noise-reduction pipeline.

THE MISSION OF EVERY PROFILE YOU WRITE:
The pipeline exists to TUNE a noisy SIT by finding and suppressing FALSE
POSITIVES. The prompts are NOT a data-discovery / hunting tool. Their primary
job is to explain WHY the SIT is over-firing and HOW to stop it firing on
benign content, while protecting the small set of genuine true positives so
tuning never blinds the SIT to real sensitive data. Optimize the prompts to:
  - Identify false positives / noise as the PRIMARY, first-listed task.
  - Diagnose the root cause of each false positive (what benign content trips
    the regex, in which workload/context).
  - Recommend concrete suppression strategies: exclusion rules, context/proximity
    filters, regex refinements, supporting-element / checksum requirements.
  - Treat true-positive identification as a GUARDRAIL (confirm a residual set so
    suppression does not remove real detections), not as the goal.
  - Quantify estimated false-positive reduction wherever possible.

You will be given a description of a sensitive information type. Produce a
tuning profile consisting of three prompt blocks plus a short description.

CRITICAL RULES:
1. The ExtractionInstruction MUST instruct the downstream model to return ONLY
   valid JSON using EXACTLY this schema, with these EXACT key names unchanged.
   Do not rename keys. Do not add or remove top-level keys. You may adapt the
   wording of "validity_status" / "risk_level" enum values and the descriptive
   guidance, but keep the key names identical:

$canonicalSchema

   The keys are named after credentials for historical reasons but represent
   generic concepts: noise_patterns = false positives; validated_credentials =
   confirmed true-positive findings; credential_pairs = linked/correlated
   findings; etc. Keep the key names verbatim regardless of the SIT domain.

2. The ExtractionInstruction MUST lead with false-positive / noise
   identification as the explicit PRIMARY FOCUS (state this first), then root
   cause analysis, then suppression strategy, and only then the true-positive
   guardrail. Include domain-specific noise categories (e.g. test/sample data,
   documentation placeholders, system-generated identifiers, lookalike formats
   from other SITs, quoted references) and the signals that separate noise from
   a real match (checksums, proximity keywords, supporting elements, entropy or
   format validity as appropriate to THIS domain).

3. Tailor ALL wording, persona, entity types, examples, noise categories,
   validity/checksum signals, and risk guidance to the described SIT domain.

4. The persona should be a subject-matter expert for THIS domain (e.g.
   "Healthcare Data Privacy Expert", "Financial Compliance Expert").

5. ConsolidationInstruction: a markdown report generator that merges multiple
   chunk analyses into one executive-ready NOISE-REDUCTION report. It must
   prioritize false-positive elimination: executive summary with noise/FP rate
   and FP-reduction opportunity, a noise pattern taxonomy grouped by root cause,
   a suppression strategy table (noise type -> suppression rule -> estimated FP
   reduction), regex refinements, a before/after FP projection, workload
   context, and a validated-findings table used only as a true-positive
   guardrail. Instruct it to prioritize noise elimination over discovering new
   matches.

6. ReportMergeInstruction: merges multiple partial markdown reports into one
   final markdown report with no duplication, preserving the noise-reduction
   focus.

7. MINIMUM INPUT: You may be given only a SIT name or a single line. Infer
   every missing field yourself from domain knowledge: a short Description, a
   safe alphanumeric profile Name (letters/digits/_/- only, no spaces, e.g.
   "Health", "AUTaxFileNumber"), a sensible DlpPolicy wildcard filter (e.g.
   "*Health*"), a singular FindingNoun (e.g. "health record"), the typical
   entity types/formats, the common false-positive sources for this domain, and
   the realistic validity/checksum/proximity signals. Use any optional detail
   the user did provide as authoritative and do not override it.

Return ONLY valid JSON, no markdown fences, with EXACTLY these keys:
{
  "name": "alphanumeric profile id (no spaces)",
  "dlpPolicy": "wildcard policy filter",
  "findingNoun": "singular noun",
  "description": "one sentence",
  "extractionInstruction": "full prompt text",
  "consolidationInstruction": "full prompt text",
  "reportMergeInstruction": "full prompt text"
}
"@

    $user = @"
SIT (name or one-line description): $([string]::IsNullOrWhiteSpace($Spec.display) ? $Spec.detects : $Spec.display)

Optional steering detail (infer anything left blank):
- Profile name: $([string]::IsNullOrWhiteSpace($Spec.name) ? '(infer)' : $Spec.name)
- Finding noun (singular): $([string]::IsNullOrWhiteSpace($Spec.findingNoun) ? '(infer)' : $Spec.findingNoun)
- DLP policy filter: $([string]::IsNullOrWhiteSpace($Spec.dlpPolicy) ? '(infer)' : $Spec.dlpPolicy)
- What it detects (entity types / formats / examples): $([string]::IsNullOrWhiteSpace($Spec.detects) ? '(infer typical ones for this SIT)' : $Spec.detects)
- Known noise / false-positive sources: $([string]::IsNullOrWhiteSpace($Spec.noise) ? '(infer common ones for this domain)' : $Spec.noise)
- Validity / validation signals: $([string]::IsNullOrWhiteSpace($Spec.validity) ? '(infer reasonable ones for this domain)' : $Spec.validity)

Generate the profile now.
"@

    $raw = Invoke-OpenAI -SystemPrompt $sys -UserPrompt $user -MaxOutputTokens 16000 -ModelName $ModelName -Endpoint $Endpoint
    return $raw
}

# ---------------------------------------------------------------------------
# Build a .psd1 file body from profile fields
# ---------------------------------------------------------------------------
function ConvertTo-Psd1 {
    param([hashtable]$P)

    function Esc1([string]$s) {
        if ($null -eq $s) { return '' }
        # single-quoted here-strings: only risk is a line that is exactly '@
        return ($s -replace "(?m)^'@", " '@")
    }

    $name   = ($P.name   -replace "'", "''")
    $desc   = ($P.description -replace "'", "''")
    $policy = ($P.dlpPolicy -replace "'", "''")
    $noun   = ($P.findingNoun -replace "'", "''")

    $ext  = Esc1 $P.extractionInstruction
    $cons = Esc1 $P.consolidationInstruction
    $merge= Esc1 $P.reportMergeInstruction

    @"
@{
    # ---------------------------------------------------------------------
    # Analysis profile: $name
    # Generated by the SIT Tuning Profile Studio.
    # ---------------------------------------------------------------------
    # Keep the JSON container keys in ExtractionInstruction identical across
    # every profile (noise_patterns, validated_credentials, credential_pairs,
    # ...). The web delta tool and report consolidation rely on them.
    # Select this profile with:  .\credpattern.ps1 -AnalysisProfile $name
    # ---------------------------------------------------------------------

    Name        = '$name'
    Description = '$desc'
    DlpPolicy   = '$policy'
    FindingNoun = '$noun'

    ExtractionInstruction = @'
$ext
'@

    ConsolidationInstruction = @'
$cons
'@

    ReportMergeInstruction = @'
$merge
'@
}
"@
}

# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------
$mime = @{
    '.html' = 'text/html; charset=utf-8'
    '.js'   = 'text/javascript; charset=utf-8'
    '.css'  = 'text/css; charset=utf-8'
    '.json' = 'application/json; charset=utf-8'
    '.svg'  = 'image/svg+xml'
    '.png'  = 'image/png'
    '.ico'  = 'image/x-icon'
}

function Read-Body([System.Net.HttpListenerContext]$ctx) {
    $enc = $ctx.Request.ContentEncoding
    if (-not $enc) { $enc = [Text.Encoding]::UTF8 }
    $reader = [System.IO.StreamReader]::new($ctx.Request.InputStream, $enc)
    try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
}

function Send-Json([System.Net.HttpListenerContext]$ctx, [int]$status, $obj) {
    $json = if ($obj -is [string]) { $obj } else { $obj | ConvertTo-Json -Depth 12 }
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $ctx.Response.StatusCode = $status
    $ctx.Response.ContentType = 'application/json; charset=utf-8'
    $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $ctx.Response.OutputStream.Close()
}

function Send-File([System.Net.HttpListenerContext]$ctx, [string]$path) {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $ext = [System.IO.Path]::GetExtension($path).ToLowerInvariant()
    $ctx.Response.ContentType = $mime[$ext] ?? 'application/octet-stream'
    $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $ctx.Response.OutputStream.Close()
}

$listener = [System.Net.HttpListener]::new()
$prefix = "http://localhost:$Port/"
$listener.Prefixes.Add($prefix)
$listener.Start()

Write-Host ""
Write-Host "  SIT Tuning Profile Studio" -ForegroundColor Cyan
Write-Host "  Serving $webDir" -ForegroundColor DarkGray
Write-Host "  Listening on $prefix" -ForegroundColor Green
if (-not (Resolve-OpenAIKey).Key) {
    Write-Host "  WARNING: no API key set (AZURE_OPENAI_API_KEY2 or AZURE_OPENAI_API_KEY) - agent/test calls will fail." -ForegroundColor Yellow
} else {
    Write-Host "  Key source: $((Resolve-OpenAIKey).Source)" -ForegroundColor DarkGray
}
Write-Host "  Press Ctrl+C to stop." -ForegroundColor DarkGray
Write-Host ""

if (-not $NoBrowser) {
    try { Start-Process "$prefix" } catch { }
}

try {
    while ($listener.IsListening) {
        # GetContext() is a blocking native call; PowerShell can't service Ctrl+C
        # while parked in it (the server would only stop on the NEXT request).
        # Wait on the async version in short slices so the engine gets a chance to
        # raise the pipeline-stopped (Ctrl+C) exception between waits.
        $task = $listener.GetContextAsync()
        while (-not $task.AsyncWaitHandle.WaitOne(200)) {
            if (-not $listener.IsListening) { break }
        }
        if (-not $listener.IsListening) { break }
        $ctx = $task.GetAwaiter().GetResult()
        try {
            $method = $ctx.Request.HttpMethod
            $path   = $ctx.Request.Url.AbsolutePath

            # ---- API routes ----
            if ($path -eq '/api/health') {
                $resolved = Resolve-OpenAIKey
                $result = @{
                    ok        = [bool]$resolved.Key
                    keySet    = [bool]$resolved.Key
                    keySource = $resolved.Source
                    model     = $Model
                    endpoint  = $OpenAIEndpoint
                    hasScript = (Test-Path $scriptPS1)
                }
                # ?probe=1 performs a real call so "ready" actually means reachable.
                if ($ctx.Request.QueryString['probe'] -eq '1') {
                    $probe = Test-OpenAIConnection -ModelName $Model -Endpoint $OpenAIEndpoint
                    $result.probed     = $true
                    $result.reachable  = $probe.ok
                    $result.probeStatus = $probe.status
                    $result.error      = $probe.error
                    if ($probe.source) { $result.keySource = $probe.source }
                }
                Send-Json $ctx 200 $result
                continue
            }

            if ($path -eq '/api/profiles') {
                $list = @()
                if (Test-Path $profDir) {
                    $list = Get-ChildItem $profDir -Filter '*.psd1' | ForEach-Object {
                        try {
                            $p = Import-PowerShellDataFile $_.FullName
                            @{ name = $p.Name ?? $_.BaseName; description = $p.Description; dlpPolicy = $p.DlpPolicy; file = $_.Name }
                        } catch {
                            @{ name = $_.BaseName; description = '(failed to parse)'; file = $_.Name }
                        }
                    }
                }
                Send-Json $ctx 200 @{ profiles = $list }
                continue
            }

            if ($path -eq '/api/profile') {
                $name = [string]$ctx.Request.QueryString['name']
                if ($name -notmatch '^[A-Za-z0-9_-]+$') {
                    Send-Json $ctx 400 @{ ok = $false; error = 'Invalid profile name.' }
                    continue
                }
                $file = Join-Path $profDir "$name.psd1"
                if (-not (Test-Path $file)) {
                    Send-Json $ctx 404 @{ ok = $false; error = "profiles/$name.psd1 not found." }
                    continue
                }
                try {
                    $p = Import-PowerShellDataFile $file
                    Send-Json $ctx 200 @{
                        ok                       = $true
                        name                     = [string]($p.Name ?? $name)
                        description              = [string]$p.Description
                        dlpPolicy                = [string]$p.DlpPolicy
                        findingNoun              = [string]$p.FindingNoun
                        extractionInstruction    = [string]$p.ExtractionInstruction
                        consolidationInstruction = [string]$p.ConsolidationInstruction
                        reportMergeInstruction   = [string]$p.ReportMergeInstruction
                    }
                } catch {
                    Send-Json $ctx 200 @{ ok = $false; error = "Failed to load profile: $($_.Exception.Message)" }
                }
                continue
            }

            if ($path -eq '/api/reports') {
                $reports = @(Get-CachedReports)
                Send-Json $ctx 200 @{ ok = $true; reports = $reports }
                continue
            }

            if ($path -eq '/api/report') {
                $slug = [string]$ctx.Request.QueryString['slug']
                $file = [string]$ctx.Request.QueryString['file']
                if ($slug -notmatch '^[A-Za-z0-9_-]+$' -or $file -notmatch '^run-[0-9_]+\.json$') {
                    Send-Json $ctx 400 @{ ok = $false; error = 'Invalid report identifier.' }
                    continue
                }
                $runPath = Join-Path (Join-Path $cacheDir $slug) (Join-Path 'runs' $file)
                if (-not (Test-Path -LiteralPath $runPath)) {
                    Send-Json $ctx 404 @{ ok = $false; error = "Report not found: $slug/$file" }
                    continue
                }
                try {
                    $snap = Get-Content -LiteralPath $runPath -Raw | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    Send-Json $ctx 200 @{ ok = $false; error = "Failed to read snapshot: $($_.Exception.Message)" }
                    continue
                }
                $md = [string]$snap.finalReport
                Send-Json $ctx 200 @{
                    ok          = $true
                    profile     = [string]($snap.profile ?? $slug)
                    label       = [string]$snap.label
                    generatedAt = [string]$snap.generatedAt
                    dlpPolicy   = [string]$snap.dlpPolicy
                    markdown    = $md
                    html        = (ConvertTo-ReportHtml $md)
                }
                continue
            }

            if ($path -eq '/api/implementation') {
                $slug = [string]$ctx.Request.QueryString['slug']
                $file = [string]$ctx.Request.QueryString['file']
                if ($slug -notmatch '^[A-Za-z0-9_-]+$' -or $file -notmatch '^run-[0-9_]+\.json$') {
                    Send-Json $ctx 400 @{ ok = $false; error = 'Invalid report identifier.' }
                    continue
                }
                $refresh = ([string]$ctx.Request.QueryString['refresh'] -eq '1')
                $reqModel    = [string]$ctx.Request.QueryString['model']
                $reqEndpoint = [string]$ctx.Request.QueryString['endpoint']
                $result = Get-ImplementationGuide -Slug $slug -File $file -ModelName $reqModel -Endpoint $reqEndpoint -Refresh:$refresh
                Send-Json $ctx 200 $result
                continue
            }

            if ($path -eq '/api/agent' -and $method -eq 'POST') {
                $req = Read-Body $ctx | ConvertFrom-Json
                $spec = @{
                    display     = [string]$req.display
                    name        = [string]$req.name
                    dlpPolicy   = [string]$req.dlpPolicy
                    findingNoun = [string]$req.findingNoun
                    detects     = [string]$req.detects
                    noise       = [string]$req.noise
                    validity    = [string]$req.validity
                }
                $modelName = if ($req.model) { [string]$req.model } else { $Model }
                $endpoint  = if ($req.endpoint) { [string]$req.endpoint } else { $OpenAIEndpoint }
                $raw = New-ProfileDraft -Spec $spec -ModelName $modelName -Endpoint $endpoint

                # Strip accidental code fences and parse
                $clean = ($raw -replace '^```[a-zA-Z]*\s*', '' -replace '```\s*$', '').Trim()
                $parsed = $null
                try { $parsed = $clean | ConvertFrom-Json } catch { }
                if (-not $parsed) {
                    Send-Json $ctx 200 @{ ok = $false; error = 'Model did not return valid JSON.'; raw = $raw }
                    continue
                }

                # Prefer user-supplied values; fall back to what the agent inferred.
                $outName = if ([string]::IsNullOrWhiteSpace($spec.name)) { [string]$parsed.name } else { $spec.name }
                $outName = ($outName -replace '[^A-Za-z0-9_-]', '')
                if ([string]::IsNullOrWhiteSpace($outName)) { $outName = 'NewProfile' }
                $outPolicy = if ([string]::IsNullOrWhiteSpace($spec.dlpPolicy)) { [string]$parsed.dlpPolicy } else { $spec.dlpPolicy }
                if ([string]::IsNullOrWhiteSpace($outPolicy)) { $outPolicy = "*$outName*" }
                $outNoun = if ([string]::IsNullOrWhiteSpace($spec.findingNoun)) { [string]$parsed.findingNoun } else { $spec.findingNoun }
                if ([string]::IsNullOrWhiteSpace($outNoun)) { $outNoun = 'finding' }

                Send-Json $ctx 200 @{
                    ok          = $true
                    name        = $outName
                    dlpPolicy   = $outPolicy
                    findingNoun = $outNoun
                    description = [string]$parsed.description
                    extractionInstruction    = [string]$parsed.extractionInstruction
                    consolidationInstruction = [string]$parsed.consolidationInstruction
                    reportMergeInstruction   = [string]$parsed.reportMergeInstruction
                }
                continue
            }

            if ($path -eq '/api/test' -and $method -eq 'POST') {
                $req = Read-Body $ctx | ConvertFrom-Json
                $instruction = [string]$req.extraction
                $sample      = [string]$req.sample
                $modelName   = if ($req.model) { [string]$req.model } else { $Model }
                $endpoint    = if ($req.endpoint) { [string]$req.endpoint } else { $OpenAIEndpoint }
                if ([string]::IsNullOrWhiteSpace($instruction) -or [string]::IsNullOrWhiteSpace($sample)) {
                    Send-Json $ctx 400 @{ ok = $false; error = 'extraction and sample are required.' }
                    continue
                }
                $out = Invoke-OpenAI -SystemPrompt $instruction -UserPrompt "Analyze the following data block:`n$sample" -MaxOutputTokens 8000 -ModelName $modelName -Endpoint $endpoint
                $clean = ($out -replace '^```[a-zA-Z]*\s*', '' -replace '```\s*$', '').Trim()
                $parsed = $null
                try { $parsed = $clean | ConvertFrom-Json } catch { }
                Send-Json $ctx 200 @{ ok = $true; raw = $out; parsedOk = [bool]$parsed; parsed = $parsed }
                continue
            }

            if ($path -eq '/api/save' -and $method -eq 'POST') {
                $req = Read-Body $ctx | ConvertFrom-Json
                $name = ([string]$req.name).Trim()
                if ($name -notmatch '^[A-Za-z0-9_-]+$') {
                    Send-Json $ctx 400 @{ ok = $false; error = 'Profile name must be alphanumeric (A-Z, 0-9, _, -).' }
                    continue
                }
                $body = ConvertTo-Psd1 @{
                    name                     = $name
                    description              = [string]$req.description
                    dlpPolicy                = [string]$req.dlpPolicy
                    findingNoun              = [string]$req.findingNoun
                    extractionInstruction    = [string]$req.extractionInstruction
                    consolidationInstruction = [string]$req.consolidationInstruction
                    reportMergeInstruction   = [string]$req.reportMergeInstruction
                }
                $target = Join-Path $profDir "$name.psd1"
                Set-Content -Path $target -Value $body -Encoding UTF8
                # Validate it loads
                $loadOk = $false; $loadErr = ''
                try { Import-PowerShellDataFile $target | Out-Null; $loadOk = $true }
                catch { $loadErr = $_.Exception.Message }
                Send-Json $ctx 200 @{ ok = $loadOk; file = "profiles/$name.psd1"; path = $target; loadError = $loadErr }
                continue
            }

            if ($path -eq '/api/run' -and $method -eq 'POST') {
                $req = Read-Body $ctx | ConvertFrom-Json
                $name = ([string]$req.name).Trim()
                if ($name -notmatch '^[A-Za-z0-9_-]+$') {
                    Send-Json $ctx 400 @{ ok = $false; error = 'Invalid profile name.' }
                    continue
                }
                if (-not (Test-Path $scriptPS1)) {
                    Send-Json $ctx 400 @{ ok = $false; error = 'credpattern.ps1 not found.' }
                    continue
                }
                $profileFile = Join-Path $profDir "$name.psd1"
                if (-not (Test-Path $profileFile)) {
                    Send-Json $ctx 400 @{ ok = $false; error = "Profile not saved yet: profiles/$name.psd1 does not exist. Click 'Save to profiles/' first." }
                    continue
                }
                # Build a single, fully-quoted -Command string. Using -Command
                # (which consumes the remainder of the line) plus single-quoted
                # values is robust against spaces in e.g. a DLP policy override,
                # which would otherwise be split into separate tokens and bind to
                # the wrong positional parameter.
                function QuoteSq([string]$s) { "'" + ($s -replace "'", "''") + "'" }
                $cmd = "& " + (QuoteSq $scriptPS1) + " -AnalysisProfile " + (QuoteSq $name)
                if ($req.dlpPolicy -and -not [string]::IsNullOrWhiteSpace([string]$req.dlpPolicy)) {
                    $cmd += " -dlpPolicy " + (QuoteSq ([string]$req.dlpPolicy))
                }
                if ($req.endpoint -and -not [string]::IsNullOrWhiteSpace([string]$req.endpoint)) {
                    $cmd += " -OpenAIEndpoint " + (QuoteSq ([string]$req.endpoint))
                }
                if ($req.model -and -not [string]::IsNullOrWhiteSpace([string]$req.model)) {
                    $cmd += " -Model " + (QuoteSq ([string]$req.model))
                }
                if ($req.tenantId -and -not [string]::IsNullOrWhiteSpace([string]$req.tenantId)) {
                    $cmd += " -TenantId " + (QuoteSq ([string]$req.tenantId))
                }
                if ($req.fullPull) { $cmd += " -FullPull" }
                if ($req.maxEvents) {
                    $me = 0
                    if ([int]::TryParse([string]$req.maxEvents, [ref]$me) -and $me -gt 0) {
                        $cmd += " -MaxEvents $me"
                    }
                }
                if ($req.daysBack) {
                    $db = 0
                    if ([int]::TryParse([string]$req.daysBack, [ref]$db) -and $db -gt 0) {
                        $cmd += " -DaysBack $db"
                    }
                }
                Start-Process pwsh -ArgumentList @('-NoExit', '-Command', $cmd) -WorkingDirectory $root | Out-Null
                Send-Json $ctx 200 @{ ok = $true; launched = $true; profile = $name; command = $cmd }
                continue
            }

            # ---- Static files ----
            if ($method -eq 'GET') {
                $rel = $path.TrimStart('/')
                if ([string]::IsNullOrWhiteSpace($rel)) { $rel = 'profile-studio.html' }
                $full = Join-Path $webDir $rel
                # prevent path traversal
                $resolved = [System.IO.Path]::GetFullPath($full)
                if (-not $resolved.StartsWith([System.IO.Path]::GetFullPath($webDir), [System.StringComparison]::OrdinalIgnoreCase)) {
                    Send-Json $ctx 403 @{ error = 'forbidden' }
                    continue
                }
                if (Test-Path $resolved -PathType Leaf) {
                    Send-File $ctx $resolved
                } else {
                    Send-Json $ctx 404 @{ error = "not found: $rel" }
                }
                continue
            }

            Send-Json $ctx 405 @{ error = 'method not allowed' }
        }
        catch {
            try { Send-Json $ctx 500 @{ ok = $false; error = $_.Exception.Message } } catch { }
        }
    }
}
finally {
    Write-Host ""
    Write-Host "  Shutting down studio server..." -ForegroundColor DarkGray
    try { $listener.Stop() } catch { }
    try { $listener.Close() } catch { }
}
