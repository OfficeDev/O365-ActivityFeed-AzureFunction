# Initialize variables
param(
    [string]$dlpPolicy="",
    [int]$MaxEvents = 1500,
    [int]$DaysBack = 120,
    [string]$OpenAIEndpoint = "https://<your-resource>.cognitiveservices.azure.com/openai/responses?api-version=2025-04-01-preview",
    [string]$Model = "gpt-5.4",
    [string]$AnalysisResultsReferencePath = "SIT_ChunkAnalyses.json",
    [string]$AnalysisProfile = "Credentials",
    [string]$ProfilePath = "",
    [string]$TenantId = "",
    [switch]$SkipDelete,
    [switch]$Help,
    [switch]$DisableMultiThreading,
    [int]$ThreadCount = 8,
    [switch]$FullPull,
    [string]$EventStorePath = "",
    [string]$AlertStorePath = "",
    [string]$SyncStatePath = "",
    [int]$WatermarkBufferHours = 1,
    [string]$RunLabel = "",
    [string]$RunSnapshotDir = ""
)

# --- Incremental sync store/state paths -------------------------------------
# The collector keeps a durable, additive JSON cache of events and alerts so
# that each run only pulls what changed since the last watermark instead of
# doing a full re-pull. Use -FullPull to rebuild the stores from scratch.
#
# IMPORTANT: the cache + snapshots are scoped PER PROFILE (see below, after the
# profile is loaded). Each sensitive information type keeps independent
# incremental state so a stale watermark from one profile cannot suppress the
# alert pull for another. Explicit -EventStorePath/-AlertStorePath/-SyncStatePath
# /-RunSnapshotDir still override the per-profile defaults.
$cacheRoot = if ($PSScriptRoot) { Join-Path -Path $PSScriptRoot -ChildPath 'cache' } else { Join-Path -Path (Get-Location) -ChildPath 'cache' }

# --- Analysis profile -------------------------------------------------------
# The domain-specific "language" (the AI prompts) lives in swappable profile
# files under profiles/<Name>.psd1. This lets an organization point the exact
# same tuning pipeline at any sensitive information type (Credentials, PII,
# Financial, health records, ...) without editing this script. Select one with
# -AnalysisProfile <Name>, or supply a custom file with -ProfilePath <path>.
function Import-AnalysisProfile {
    param(
        [string]$ProfileName,
        [string]$ProfileFilePath,
        [string]$ScriptRoot
    )

    $resolvedPath = $ProfileFilePath
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        $profileDir = if ($ScriptRoot) { Join-Path -Path $ScriptRoot -ChildPath 'profiles' } else { Join-Path -Path (Get-Location) -ChildPath 'profiles' }
        $resolvedPath = Join-Path -Path $profileDir -ChildPath ("{0}.psd1" -f $ProfileName)
    }

    if (-not (Test-Path -LiteralPath $resolvedPath)) {
        throw "Analysis profile not found: '$resolvedPath'. Available profiles live under the 'profiles' folder; pass -AnalysisProfile <Name> or -ProfilePath <file>."
    }

    # Import-PowerShellDataFile parses data only (no arbitrary code execution),
    # which is safe for loading instruction text from disk.
    $data = Import-PowerShellDataFile -LiteralPath $resolvedPath

    foreach ($required in 'ExtractionInstruction', 'ConsolidationInstruction', 'ReportMergeInstruction') {
        if ([string]::IsNullOrWhiteSpace([string]$data[$required])) {
            throw "Analysis profile '$resolvedPath' is missing required key '$required'."
        }
    }
    if ([string]::IsNullOrWhiteSpace([string]$data.Name)) { $data.Name = [System.IO.Path]::GetFileNameWithoutExtension($resolvedPath) }
    $data.SourcePath = $resolvedPath
    return $data
}

$activeProfile = Import-AnalysisProfile -ProfileName $AnalysisProfile -ProfileFilePath $ProfilePath -ScriptRoot $PSScriptRoot

# Profile supplies the default DLP policy filter; an explicit -dlpPolicy wins.
if (-not $PSBoundParameters.ContainsKey('dlpPolicy') -or [string]::IsNullOrWhiteSpace($dlpPolicy)) {
    $dlpPolicy = if (-not [string]::IsNullOrWhiteSpace([string]$activeProfile.DlpPolicy)) { [string]$activeProfile.DlpPolicy } else { '*' }
}
Write-Output ("Analysis profile: {0} ({1}) | DLP policy filter: {2}" -f $activeProfile.Name, $activeProfile.Description, $dlpPolicy)

# --- Per-profile cache + snapshot paths -------------------------------------
# Resolve the durable store / sync-state / snapshot locations now that the
# active profile is known, so each SIT keeps its own incremental state. Without
# this, a recent watermark written by one profile would make the next profile's
# alert pull incremental and return no alerts (hence no events). Explicit path
# parameters supplied by the caller still win.
$profileSlug = ($activeProfile.Name -replace '[^A-Za-z0-9_-]', '_')
if ([string]::IsNullOrWhiteSpace($profileSlug)) { $profileSlug = 'default' }
$profileCacheDir = Join-Path -Path $cacheRoot -ChildPath $profileSlug
if ([string]::IsNullOrWhiteSpace($EventStorePath)) { $EventStorePath = Join-Path -Path $profileCacheDir -ChildPath 'events-store.jsonl' }
if ([string]::IsNullOrWhiteSpace($AlertStorePath)) { $AlertStorePath = Join-Path -Path $profileCacheDir -ChildPath 'alerts-store.jsonl' }
if ([string]::IsNullOrWhiteSpace($SyncStatePath))  { $SyncStatePath  = Join-Path -Path $profileCacheDir -ChildPath 'sync-state.json' }
if ([string]::IsNullOrWhiteSpace($RunSnapshotDir)) { $RunSnapshotDir = Join-Path -Path $profileCacheDir -ChildPath 'runs' }
Write-Output ("Cache scope: {0}" -f $profileCacheDir)

# Validate Azure OpenAI API Key
if (-not $env:AZURE_OPENAI_API_KEY -and -not $env:AZURE_OPENAI_API_KEY2) {
    Write-Host "ERROR: You must set the `$env:AZURE_OPENAI_API_KEY (or `$env:AZURE_OPENAI_API_KEY2) environment variable to your Azure OpenAI API key secret before running this script." -ForegroundColor Red
    exit 1
}

# Azure OpenAI configuration (prefer: $env:AZURE_OPENAI_API_KEY2, then $env:AZURE_OPENAI_API_KEY)
$apiKey = if ($env:AZURE_OPENAI_API_KEY2) { $env:AZURE_OPENAI_API_KEY2 } else { $env:AZURE_OPENAI_API_KEY }

# Authenticate using Managed Identity and get access token for Graph API
if (-not ($token)) {
    $graphScopes = "SecurityEvents.Read.All","SecurityAlert.Read.All","CustomTags.Read.All"
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        # Pin the sign-in to a specific tenant so the run can't silently use a
        # cached account from the wrong directory.
        Connect-MgGraph -Scopes $graphScopes -TenantId $TenantId -NoWelcome
    } else {
        Connect-MgGraph -Scopes $graphScopes -NoWelcome
    }
}

# Surface exactly which account/tenant we authenticated as so the operator can
# confirm the right credentials before any data is pulled.
$mgContext = Get-MgContext
if ($mgContext) {
    Write-Host "Connected to Microsoft Graph as '$($mgContext.Account)' (tenant $($mgContext.TenantId))." -ForegroundColor Cyan
} else {
    Write-Host "WARNING: No Microsoft Graph context after Connect-MgGraph." -ForegroundColor Yellow
}

$resource = "https://graph.microsoft.com"
$mgrequest = Invoke-MgGraphRequest -Method GET  -Uri "https://graph.microsoft.com/v1.0/me" -OutputType HttpResponseMessage
$token = $mgRequest.RequestMessage.Headers.Authorization.Parameter

$headerParams = @{
    'Authorization'    = "Bearer $token"
    'ConsistencyLevel' = 'eventual'
}


# --- Incremental sync helpers ----------------------------------------------
function Get-DlpIso8601 {
    param([Parameter(Mandatory)][datetime]$Value)
    return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

# Load a JSONL store (one JSON object per line) into an ordered dictionary keyed
# by the object's id. Lines that fail to parse are skipped.
function Read-DlpJsonlStore {
    param([Parameter(Mandatory)][string]$Path)
    $map = [ordered]@{}
    if (-not (Test-Path -LiteralPath $Path)) { return $map }
    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $obj = $line | ConvertFrom-Json -ErrorAction Stop
        } catch { continue }
        $key = [string]$obj.id
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        $map[$key] = $obj
    }
    return $map
}

# Persist an id-keyed dictionary back to a JSONL store atomically.
function Write-DlpJsonlStore {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Map
    )
    $dir = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $sb = [System.Text.StringBuilder]::new()
    foreach ($key in $Map.Keys) {
        [void]$sb.AppendLine(($Map[$key] | ConvertTo-Json -Depth 50 -Compress))
    }
    $tmp = "$Path.tmp"
    [System.IO.File]::WriteAllText($tmp, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

# Append objects to a JSONL store without rewriting existing content. Used for
# the large, append-only event store so an incremental run only writes the new
# events instead of rewriting the entire file. The reader is last-write-wins, so
# even appended upserts are safe (a later line for the same id overrides earlier).
function Add-DlpJsonlAppend {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][System.Collections.IEnumerable]$Items
    )
    $dir = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $sb = [System.Text.StringBuilder]::new()
    $count = 0
    foreach ($item in $Items) {
        [void]$sb.AppendLine(($item | ConvertTo-Json -Depth 50 -Compress))
        $count++
    }
    if ($count -eq 0) { return }
    [System.IO.File]::AppendAllText($Path, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
}

function Read-DlpSyncState {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
    } catch { return $null }
}

function Write-DlpSyncState {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable]$State
    )
    $dir = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, ($State | ConvertTo-Json -Depth 10), [System.Text.UTF8Encoding]::new($false))
}

# Load existing stores + sync state (unless a full rebuild was requested).
$eventStore = [ordered]@{}
$alertStore = [ordered]@{}
$syncState  = $null
if ($FullPull) {
    Write-Output "FullPull requested: rebuilding event and alert stores from scratch."
} else {
    $eventStore = Read-DlpJsonlStore -Path $EventStorePath
    $alertStore = Read-DlpJsonlStore -Path $AlertStorePath
    $syncState  = Read-DlpSyncState -Path $SyncStatePath
    Write-Output ("Loaded stores: {0} events, {1} alerts from prior runs." -f $eventStore.Count, $alertStore.Count)
}

# Compute the incremental watermark (with overlap buffer). Null = full pull.
$alertWatermark = $null
if (-not $FullPull -and $syncState -and $syncState.lastAlertWatermark) {
    try {
        $alertWatermark = ([datetime]$syncState.lastAlertWatermark).AddHours(-1 * [Math]::Abs($WatermarkBufferHours))
    } catch { $alertWatermark = $null }
}


# Fetch DLP alerts with alertPolicyId filter
$filterParts = @("detectionSource eq 'microsoftDataLossPrevention'")

# In incremental mode, only pull alerts updated since the watermark (minus
# buffer); otherwise pull all DLP alerts within the configured lookback window.
if ($alertWatermark) {
    $filterParts += ("lastUpdateDateTime ge {0}" -f (Get-DlpIso8601 -Value $alertWatermark))
    Write-Output ("Incremental alert pull: only alerts updated since {0}." -f (Get-DlpIso8601 -Value $alertWatermark))
} else {
    $lookback = (Get-Date).AddDays(-$daysback).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filterParts += "createdDateTime ge $lookback"
}

$alertsUri = "https://graph.microsoft.com/beta/security/alerts_v2?`$filter=$($filterParts -join ' and ')"

$dlpAlertsList = [System.Collections.Generic.List[object]]::new()
$graphCall = $alertsUri
while ($graphCall) {
    $alertsResponse = Invoke-MgGraphRequest -Method GET -Uri $graphCall -Headers $headerParams
    foreach ($alertItem in $alertsResponse.value) {
        $dlpAlertsList.Add($alertItem)
    }
    $graphCall = $alertsResponse.'@odata.nextLink'
}

Write-Output "Retrieved $($dlpAlertsList.Count) DLP alerts this run"

# Filter the freshly retrieved alerts on additionaldata.alertPolicytitle. Only
# policy-matching alerts are kept in the durable cache so it stays scoped to
# this script's purpose.
$changedAlerts = @($dlpAlertsList | Where-Object { $_.additionalData.alertPolicytitle -like $dlpPolicy })

Write-Output ("Filtered to {0} changed DLP alert(s) with alertPolicytitle to process this run" -f $changedAlerts.Count)

# Diagnostic: if alerts were retrieved but none matched the policy filter, show
# the distinct policy titles actually present so the operator can correct the
# -dlpPolicy wildcard (a too-narrow filter is a common "no events" cause).
if ($changedAlerts.Count -eq 0 -and $dlpAlertsList.Count -gt 0) {
    $titles = @($dlpAlertsList | ForEach-Object { [string]$_.additionalData.alertPolicytitle } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    Write-Warning ("No alerts matched the DLP policy filter '{0}'." -f $dlpPolicy)
    if ($titles.Count -gt 0) {
        Write-Host ("Policy titles present in the retrieved alerts ({0}):" -f $titles.Count) -ForegroundColor Yellow
        foreach ($t in ($titles | Select-Object -First 25)) { Write-Host ("  - {0}" -f $t) -ForegroundColor Yellow }
        Write-Host "Re-run with -dlpPolicy '<wildcard matching one of the above>' (e.g. '*' for all)." -ForegroundColor Yellow
    } else {
        Write-Host "Retrieved alerts have no alertPolicytitle set; use -dlpPolicy '*' to include them all." -ForegroundColor Yellow
    }
}

# Upsert changed alerts into the alert store (by alert id).
foreach ($alert in $changedAlerts) {
    $aid = [string]$alert.id
    if ([string]::IsNullOrWhiteSpace($aid)) { continue }
    $alertStore[$aid] = $alert
}

# Downstream aggregation/analysis operates over the full merged alert store.
$dlpAlerts = @($alertStore.Values)
Write-Output ("Alert store now holds {0} DLP alert(s)." -f $dlpAlerts.Count)

# Extract alert details. Events are only (re)fetched for alerts that changed
# this run (in full-pull mode that is every alert); unchanged alerts keep their
# events already present in the store.
$alertDetails = [System.Collections.Generic.List[hashtable]]::new()

foreach ($alert in $changedAlerts) {
    $alertDetail = @{
        AlertId            = $alert.id
        AlertPolicyId      = $alert.alertPolicyId
        AlertCorrelationId = $alert.detectorId
        StartDateTime      = ([datetime]$alert.firstActivityDateTime).ToString('yyyy-MM-ddTHH:mm:ssZ')
        EndDateTime        = ([datetime]$alert.lastActivityDateTime).ToString('yyyy-MM-ddTHH:mm:ssZ')
        Title              = $alert.title
        Description        = $alert.description
        Tags               = $alert.tags
    }
    $alertDetails.Add($alertDetail)
}

# Fetch DLP Alert Events with pagination.
# New events merge into the durable $eventStore; the HashSet is seeded from the
# store so we never re-add events captured by a previous run. $MaxEvents bounds
# NEW events pulled per run.
$seenEventIds  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($existingId in $eventStore.Keys) { [void]$seenEventIds.Add([string]$existingId) }
$newEventCount = 0
$newEvents = [System.Collections.Generic.List[object]]::new()
foreach ($detail in $alertDetails) {
    if ($newEventCount -ge $MaxEvents) { break }

    if ([string]::IsNullOrWhiteSpace([string]$detail.AlertCorrelationId)) { continue }

    $filterString = "alertCorrelationId eq '$($detail.AlertCorrelationId)' and startDateTime ge $($detail.StartDateTime) and endDateTime le $($detail.EndDateTime)"
    $eventsUri = "https://graph.microsoft.com/beta/security/dlpAlertEvent?`$filter=$filterString"

    $graphCall = $eventsUri
    while ($graphCall -and $newEventCount -lt $MaxEvents) {
        try {
            $eventsResponse = Invoke-MgGraphRequest -Method GET -Uri $graphCall -Headers $headerParams
        } catch {
            Write-Warning ("dlpAlertEvent query failed for alertId={0}: {1}" -f $detail.AlertId, $_.Exception.Message)
            break
        }
        foreach ($eventItem in $eventsResponse.value) {
            $evtId = [string]$eventItem.id
            if ([string]::IsNullOrWhiteSpace($evtId)) { continue }
            if (-not $seenEventIds.Add($evtId)) { continue }
            $eventStore[$evtId] = $eventItem
            [void]$newEvents.Add($eventItem)
            $newEventCount++
            if ($newEventCount -ge $MaxEvents) { break }
        }

        if ($newEventCount -ge $MaxEvents) { break }
        $graphCall = $eventsResponse.'@odata.nextLink'
    }
}
# Downstream detection extraction/analysis operates over the full merged event store.
$dlpEvents = @($eventStore.Values)

Write-Output ("Fetched {0} new event(s) this run; event store now holds {1} unique DLP event(s) (cap/run=$MaxEvents)." -f $newEventCount, $dlpEvents.Count)

# Persist the durable stores and advance the sync watermark.
# Event store is append-only: an incremental run appends just this run's new
# events instead of rewriting the entire (large) file. A full pull rebuilds it.
if ($FullPull) {
    Write-DlpJsonlStore -Path $EventStorePath -Map $eventStore
} else {
    Add-DlpJsonlAppend -Path $EventStorePath -Items $newEvents
}
# Alert store is small and uses upsert semantics, so a full rewrite keeps it compact.
Write-DlpJsonlStore -Path $AlertStorePath -Map $alertStore

$nowIso = Get-DlpIso8601 -Value (Get-Date)
# Watermark = latest alert lastUpdateDateTime we have seen (fall back to now).
$maxAlertUpdate = $null
foreach ($alert in $dlpAlerts) {
    $candidate = $null
    if ($alert.PSObject.Properties.Name -contains 'lastUpdateDateTime' -and $alert.lastUpdateDateTime) {
        try { $candidate = [datetime]$alert.lastUpdateDateTime } catch { $candidate = $null }
    } elseif ($alert.lastActivityDateTime) {
        try { $candidate = [datetime]$alert.lastActivityDateTime } catch { $candidate = $null }
    }
    if ($candidate -and (-not $maxAlertUpdate -or $candidate -gt $maxAlertUpdate)) { $maxAlertUpdate = $candidate }
}
$alertWatermarkIso = if ($maxAlertUpdate) { Get-DlpIso8601 -Value $maxAlertUpdate } else { $nowIso }
# Preserve the original firstRunAt. ConvertFrom-Json rehydrates ISO strings into
# [datetime], so normalize back to ISO 8601 to avoid locale-formatted timestamps.
$firstRunAt = $nowIso
if ($syncState -and $syncState.firstRunAt) {
    try { $firstRunAt = Get-DlpIso8601 -Value ([datetime]$syncState.firstRunAt) } catch { $firstRunAt = $nowIso }
}
Write-DlpSyncState -Path $SyncStatePath -State @{
    firstRunAt           = $firstRunAt
    lastRunAt            = $nowIso
    lastAlertWatermark   = $alertWatermarkIso
    lastEventWatermark   = $nowIso
    eventStoreCount      = $dlpEvents.Count
    alertStoreCount      = $dlpAlerts.Count
    lastRunNewEvents     = $newEventCount
    lastRunChangedAlerts = $changedAlerts.Count
    fullPull             = [bool]$FullPull
}
Write-Output ("Sync state saved. Alert watermark={0}; store totals: {1} alerts, {2} events." -f $alertWatermarkIso, $dlpAlerts.Count, $dlpEvents.Count)


# Extract SensitiveInformationDetections from audit records for AI analysis
$detectionData = [System.Collections.Generic.List[hashtable]]::new()
foreach ($dlpEvent in $dlpEvents) {
    $auditRecord = $null
    
    # Attempt to parse auditRecord JSON if it exists
    if ($dlpEvent.auditRecord) {
        try {
            $auditRecord = $dlpEvent.auditRecord | ConvertFrom-Json -ErrorAction SilentlyContinue
        } catch {
            $auditRecord = $dlpEvent.auditRecord
        }
    }
    
    # Extract SensitiveInformationDetections from nested structure
    if ($auditRecord) {
        $policyDetails = $auditRecord.PolicyDetails
        if ($policyDetails) {
            foreach ($policy in $policyDetails) {
                foreach ($rule in $policy.Rules) {
                    $conditions = $rule.ConditionsMatched
                    if ($conditions -and $conditions.SensitiveInformation) {
                        foreach ($sensInfo in $conditions.SensitiveInformation) {
                            if ($sensInfo.SensitiveInformationDetections) {
                                $detection = @{
                                    SensitiveType              = $sensInfo.SensitiveType
                                    SensitiveTypeName          = $sensInfo.SensitiveInformationTypeName
                                    Location                   = $sensInfo.Location
                                    DetectedValues             = $sensInfo.SensitiveInformationDetections.DetectedValues.Value
                                    AlertId                    = $dlpEvent.id
                                    ResponseTime               = $dlpEvent.createdDateTime
                                    UserId                     = $auditRecord.UserId
                                    Workload                   = $auditRecord.Workload
                                    FullRecipients             = $auditRecord.FullRecipients
                                    ContentInfo                   = $auditRecord.ContentInfo.FullName
                                    Sender                     = if ($auditRecord.EnrichedEmailInfo) { $auditRecord.EnrichedEmailInfo.Sender } else { "unknown" }
                                    Subject                    = if ($auditRecord.EnrichedEmailInfo) { $auditRecord.EnrichedEmailInfo.Subject } else { "unknown" }
                                }
                                $detectionData.Add($detection)
                            }
                        }
                    }
                }
            }
        }
    }
}

Write-Output "Extracted $($detectionData.Count) sensitive information detections"

# Domain-specific AI instructions come from the selected analysis profile so
# the same pipeline can target any sensitive information type. See profiles/.
$dlpInstruction          = [string]$activeProfile.ExtractionInstruction
$consolidationInstruction = [string]$activeProfile.ConsolidationInstruction
$reportMergeInstruction  = [string]$activeProfile.ReportMergeInstruction

function Get-DlpAnalysisBody {
    <# Builds the responses-API JSON body for a single analysis call. Single source of truth
       so the sequential and parallel code paths can never diverge. #>
    param(
        [Parameter(Mandatory)][string]$Instruction,
        [Parameter(Mandatory)][string]$Result,
        [string]$Model = 'gpt-5.4',
        [int]$MaxOutputTokens = 16000
    )
    $input1 = @(
        @{ role = 'system'; content = @(@{ type = 'input_text'; text = $Instruction }) },
        @{ role = 'user';   content = @(@{ type = 'input_text'; text = "Analyze the following data block:`n$Result" }) }
    )
    return (@{
        input             = $input1
        max_output_tokens = $MaxOutputTokens
        model             = $Model
    } | ConvertTo-Json -Depth 10)
}

function Invoke-DlpOpenAIRequest {
    <#
    .SYNOPSIS
        Resilient Azure OpenAI request: retries transient failures, surfaces real errors.
    .DESCRIPTION
        Ported from the SecurityPersonaAgent OpenAIClient. Honours a server Retry-After hint,
        otherwise backs off exponentially with jitter (capped at 90s). Only genuinely transient
        errors are retried (429/5xx/timeouts/connection resets); real client errors (400/401/404
        content filter, token limits, auth) throw IMMEDIATELY with the full HTTP response body so
        the failure can actually be reviewed instead of being swallowed.
    .OUTPUTS
        The deserialized response object from Invoke-RestMethod.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][string]$Body,
        [int]$MaxRetries = 6,
        [int]$TimeoutSec = 600,
        [string]$Label = 'OpenAI analysis'
    )

    $attemptCount = [Math]::Max(1, $MaxRetries)
    for ($attempt = 1; $attempt -le $attemptCount; $attempt++) {
        try {
            return Invoke-RestMethod -Uri $Uri -Method Post -Headers $Headers -Body $Body -TimeoutSec $TimeoutSec
        } catch {
            $ex = $_.Exception
            $message = [string]$ex.Message
            $statusCode = 0
            $retryAfter = $null
            $responseBody = $null

            # The actual API error detail (content filter, token limit, auth reason) lives here.
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $responseBody = [string]$_.ErrorDetails.Message }

            $response = $null
            if ($ex.PSObject.Properties.Name -contains 'Response') { $response = $ex.Response }
            elseif ($ex.InnerException -and $ex.InnerException.PSObject.Properties.Name -contains 'Response') { $response = $ex.InnerException.Response }
            if ($response -and $response.PSObject.Properties.Name -contains 'StatusCode') {
                try { $statusCode = [int]$response.StatusCode } catch { $statusCode = 0 }
            }
            if ($response -and $response.PSObject.Properties.Name -contains 'Headers' -and $response.Headers) {
                try {
                    $ra = $response.Headers.RetryAfter
                    if ($ra -and $ra.PSObject.Properties.Name -contains 'Delta' -and $ra.Delta) { $retryAfter = [int][math]::Ceiling(([timespan]$ra.Delta).TotalSeconds) }
                } catch { $retryAfter = $null }
            }

            $isTransient = $false
            if ($statusCode -in @(408, 409, 425, 429, 500, 502, 503, 504)) { $isTransient = $true }
            elseif ($message -match 'Backend error|no_capacity|too_many_requests|exceeds the maximum usage|high demand|rate limit|Provisioned Throughput|temporarily unavailable|timed out|timeout|forcibly closed by the remote host|Unable to read data from the transport connection|The request was aborted|server_error|internal_error|No such host is known|name or service not known|Name does not resolve|could not be resolved|actively refused|connection attempt failed|connection was reset|connection reset by peer|An existing connection was forcibly closed') { $isTransient = $true }

            $detail = $message
            if ($responseBody) { $detail = "$message`n$responseBody" }

            if ($attempt -ge $attemptCount -or -not $isTransient) {
                throw ("{0} failed (HTTP {1}) after {2} attempt(s): {3}" -f $Label, $statusCode, $attempt, $detail)
            }

            if ($null -ne $retryAfter -and $retryAfter -gt 0) {
                $delaySeconds = [Math]::Min(90, $retryAfter + 1)
                $reason = 'server Retry-After'
            } else {
                $expBackoff = [Math]::Min(90, 3 * [Math]::Pow(2, ($attempt - 1)))
                $jitter = Get-Random -Minimum 0 -Maximum 3
                $delaySeconds = [int]([Math]::Max(2, $expBackoff + $jitter))
                $reason = 'exponential backoff'
            }
            Write-Host ("{0} hit a transient error on attempt {1}/{2} (HTTP {3}, {4}). Retrying in {5}s..." -f $Label, $attempt, $attemptCount, $statusCode, $reason, $delaySeconds) -ForegroundColor Yellow
            Start-Sleep -Seconds $delaySeconds
        }
    }
}

function Analyze-Data {
    param(
        [string]$result,
        [string]$instruction,
        [string]$apiKey,
        [string]$openAIEndpoint
    )
    if (-not $apiKey -or $apiKey -like "*REPLACE*") {
        Write-Warning "API key not set; skipping AI analysis."
        return $null
    }
    $body = Get-DlpAnalysisBody -Instruction $instruction -Result $result -Model $Model
    $headers = @{
        "Content-Type" = "application/json"
        "api-key"      = $apiKey
    }

    try {
        $resp = Invoke-DlpOpenAIRequest -Uri $openAIEndpoint -Headers $headers -Body $body -Label 'AI analysis'
        return $resp.output.content.text
    } catch {
        # Surface the real reason loudly so it can be reviewed, then signal failure to the caller.
        Write-Warning ("AI analysis failed: {0}" -f $_)
        return $null
    }
}

function Export-AnalysisResultsReference {
    param(
        [System.Collections.Generic.List[string]]$AnalysisResults,
        [string]$Path
    )

    if (-not $AnalysisResults -or $AnalysisResults.Count -eq 0 -or -not $Path) {
        return
    }

    $referenceItems = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $AnalysisResults.Count; $index++) {
        $analysisText = $AnalysisResults[$index]
        $parsedAnalysis = $null
        $parsedSuccessfully = $false

        try {
            $parsedAnalysis = $analysisText | ConvertFrom-Json -Depth 100
            $parsedSuccessfully = $true
        } catch {
            $parsedAnalysis = $null
        }

        $referenceItems.Add([pscustomobject]@{
            chunk_index = $index + 1
            parsed_json = $parsedSuccessfully
            analysis_result = if ($parsedSuccessfully) { $parsedAnalysis } else { $analysisText }
        })
    }

    $referenceItems | ConvertTo-Json -Depth 100 | Out-File $Path -Encoding UTF8
    Write-Host "Chunk analysis reference saved to $Path" -ForegroundColor Cyan
}

function Export-RunSnapshot {
    param(
        [System.Collections.Generic.List[string]]$AnalysisResults,
        [string]$SnapshotDir,
        [string]$Label,
        [int]$RawDetectionCount,
        [int]$EventStoreCount,
        [int]$AlertStoreCount,
        [string]$DlpPolicy,
        [string]$ProfileName,
        [string]$FinalReportMarkdown
    )

    if (-not $AnalysisResults -or $AnalysisResults.Count -eq 0 -or [string]::IsNullOrWhiteSpace($SnapshotDir)) {
        return
    }

    if (-not (Test-Path -LiteralPath $SnapshotDir)) {
        New-Item -ItemType Directory -Path $SnapshotDir -Force | Out-Null
    }

    # Re-parse each chunk's analysis so the snapshot carries structured JSON the
    # web comparison tool can aggregate (falls back to raw text if unparseable).
    $chunkAnalyses = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $AnalysisResults.Count; $index++) {
        $analysisText = $AnalysisResults[$index]
        $parsedAnalysis = $null
        $parsedSuccessfully = $false
        try {
            $parsedAnalysis = $analysisText | ConvertFrom-Json -Depth 100
            $parsedSuccessfully = $true
        } catch {
            $parsedAnalysis = $null
        }
        $chunkAnalyses.Add([pscustomobject]@{
            chunk_index     = $index + 1
            parsed_json     = $parsedSuccessfully
            analysis_result = if ($parsedSuccessfully) { $parsedAnalysis } else { $analysisText }
        })
    }

    $generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss')
    $resolvedLabel = if ([string]::IsNullOrWhiteSpace($Label)) { $stamp } else { $Label }

    $snapshot = [pscustomobject]@{
        label             = $resolvedLabel
        generatedAt       = $generatedAt
        profile           = $ProfileName
        dlpPolicy         = $DlpPolicy
        rawDetectionCount = $RawDetectionCount
        eventStoreCount   = $EventStoreCount
        alertStoreCount   = $AlertStoreCount
        chunkCount        = $chunkAnalyses.Count
        finalReport       = $FinalReportMarkdown
        chunkAnalyses     = $chunkAnalyses
    }

    $snapshotPath = Join-Path -Path $SnapshotDir -ChildPath ("run-{0}.json" -f $stamp)
    $snapshot | ConvertTo-Json -Depth 100 | Out-File -FilePath $snapshotPath -Encoding UTF8
    Write-Host ("Run snapshot saved to {0}" -f $snapshotPath) -ForegroundColor Cyan

    # Maintain a manifest so the web tool / scripts can enumerate available runs.
    $manifestPath = Join-Path -Path $SnapshotDir -ChildPath 'runs-manifest.json'
    $manifest = [System.Collections.Generic.List[object]]::new()
    if (Test-Path -LiteralPath $manifestPath) {
        try {
            $existing = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
            foreach ($entry in @($existing)) { $manifest.Add($entry) }
        } catch { }
    }
    $manifest.Add([pscustomobject]@{
        file              = Split-Path -Path $snapshotPath -Leaf
        label             = $resolvedLabel
        generatedAt       = $generatedAt
        profile           = $ProfileName
        dlpPolicy         = $DlpPolicy
        rawDetectionCount = $RawDetectionCount
        chunkCount        = $chunkAnalyses.Count
    })
    $manifest | ConvertTo-Json -Depth 20 | Out-File -FilePath $manifestPath -Encoding UTF8
}

function Invoke-BoundedConsolidation {
    param(
        [System.Collections.Generic.List[string]]$Inputs,
        [string]$InitialInstruction,
        [string]$MergeInstruction,
        [string]$ApiKey,
        [string]$OpenAIEndpoint,
        [int]$MaxMergedLength
    )

    if ($Inputs.Count -eq 0) {
        return $null
    }

    $separator = "`n---CHUNK---`n"
    $currentInputs = [System.Collections.Generic.List[string]]::new()
    foreach ($inputItem in $Inputs) {
        $currentInputs.Add($inputItem)
    }

    $instruction = $InitialInstruction
    $passNumber = 1

    while ($true) {
        if ($currentInputs.Count -eq 1 -and $currentInputs[0].Length -le $MaxMergedLength) {
            return Analyze-Data -result $currentInputs[0] -instruction $instruction -apiKey $ApiKey -openAIEndpoint $OpenAIEndpoint
        }

        $groups = [System.Collections.Generic.List[string]]::new()
        $currentGroup = [System.Collections.Generic.List[string]]::new()
        $currentLength = 0

        foreach ($inputText in $currentInputs) {
            $additionalLength = $inputText.Length
            if ($currentGroup.Count -gt 0) {
                $additionalLength += $separator.Length
            }

            if (($currentLength + $additionalLength) -gt $MaxMergedLength -and $currentGroup.Count -gt 0) {
                $groups.Add(($currentGroup -join $separator))
                $currentGroup = [System.Collections.Generic.List[string]]::new()
                $currentLength = 0
            }

            $currentGroup.Add($inputText)
            if ($currentLength -gt 0) {
                $currentLength += $separator.Length
            }
            $currentLength += $inputText.Length
        }

        if ($currentGroup.Count -gt 0) {
            $groups.Add(($currentGroup -join $separator))
        }

        Write-Host "Consolidation pass ${passNumber}: processing $($groups.Count) grouped request(s)." -ForegroundColor Cyan

        $outputs = [System.Collections.Generic.List[string]]::new()
        for ($groupIndex = 0; $groupIndex -lt $groups.Count; $groupIndex++) {
            $groupPayload = $groups[$groupIndex]
            Write-Host "Consolidation pass ${passNumber}: merging group $($groupIndex + 1)/$($groups.Count) (length=$($groupPayload.Length))." -ForegroundColor DarkCyan
            $groupResult = Analyze-Data -result $groupPayload -instruction $instruction -apiKey $ApiKey -openAIEndpoint $OpenAIEndpoint
            if ($groupResult) {
                $outputs.Add($groupResult)
            } else {
                Write-Host "Consolidation pass ${passNumber}: group $($groupIndex + 1) failed." -ForegroundColor Yellow
            }
        }

        if ($outputs.Count -eq 0) {
            return $null
        }

        if ($outputs.Count -eq 1) {
            return $outputs[0]
        }

        $currentInputs = [System.Collections.Generic.List[string]]::new()
        foreach ($outputItem in $outputs) {
            $currentInputs.Add($outputItem)
        }

        $instruction = $MergeInstruction
        $passNumber++
    }
}

function Invoke-ChunkAnalysis {
    param(
        [System.Collections.Generic.List[string]]$Chunks,
        [string]$Instruction,
        [string]$ApiKey,
        [string]$OpenAIEndpoint,
        [int]$ThreadCount,
        [switch]$DisableMultiThreading
    )

    $analysisResults = [System.Collections.Generic.List[string]]::new()
    if ($Chunks.Count -eq 0) {
        return $analysisResults
    }

    if ($DisableMultiThreading -or $Chunks.Count -eq 1 -or $ThreadCount -le 1) {
        for ($c = 0; $c -lt $Chunks.Count; $c++) {
            $chunkText = $Chunks[$c]
            Write-Host "`n--- Analyzing chunk $($c+1)/$($Chunks.Count) (length=$($chunkText.Length)) ---" -ForegroundColor Cyan
            $res = Analyze-Data -result $chunkText -instruction $Instruction -apiKey $ApiKey -openAIEndpoint $OpenAIEndpoint
            if ($res) {
                $analysisResults.Add($res)
            } else {
                Write-Host "Chunk $($c+1) analysis failed." -ForegroundColor Yellow
            }
        }

        return $analysisResults
    }

    $effectiveThreadCount = [Math]::Min([Math]::Max($ThreadCount, 1), $Chunks.Count)
    Write-Host "Created $($Chunks.Count) chunk(s) for analysis. Using up to $effectiveThreadCount parallel worker(s)." -ForegroundColor Cyan

    # Serialize the shared helpers so each thread-job runspace can dot-source identical
    # request-building + resilient-retry logic (thread jobs don't inherit parent functions).
    $helperSource = @"
function Get-DlpAnalysisBody {
$((Get-Command Get-DlpAnalysisBody).Definition)
}
function Invoke-DlpOpenAIRequest {
$((Get-Command Invoke-DlpOpenAIRequest).Definition)
}
"@

    $jobs = [System.Collections.Generic.List[object]]::new()
    $orderedResults = [string[]]::new($Chunks.Count)

    function Receive-CompletedChunkJobs {
        param(
            [System.Collections.Generic.List[object]]$Jobs,
            [string[]]$OrderedResults,
            [switch]$Wait
        )

        if ($Jobs.Count -eq 0) {
            return
        }

        $completedJobs = @()
        if ($Wait) {
            $completed = Wait-Job -Job $Jobs -Any
            if ($completed) {
                $completedJobs = @($completed)
            }
        } else {
            $completedJobs = @($Jobs | Where-Object { $_.State -in @('Completed', 'Failed', 'Stopped') })
        }

        foreach ($job in $completedJobs) {
            $jobOutput = Receive-Job -Job $job -Keep
            Remove-Job -Job $job -Force
            [void]$Jobs.Remove($job)

            if ($jobOutput) {
                foreach ($jobResult in $jobOutput) {
                    if ($null -ne $jobResult.Index -and $jobResult.Result) {
                        $OrderedResults[$jobResult.Index] = $jobResult.Result
                        Write-Host "Completed chunk $($jobResult.Index + 1)/$($Chunks.Count)." -ForegroundColor Green
                    } elseif ($null -ne $jobResult.Index) {
                        Write-Host "Chunk $($jobResult.Index + 1) analysis failed." -ForegroundColor Yellow
                        if ($jobResult.Error) {
                            Write-Warning ("Chunk $($jobResult.Index + 1) error: {0}" -f $jobResult.Error)
                        }
                    }
                }
            } else {
                Write-Host "Chunk analysis job $($job.Id) returned no data." -ForegroundColor Yellow
            }
        }
    }

    for ($c = 0; $c -lt $Chunks.Count; $c++) {
        while ($jobs.Count -ge $effectiveThreadCount) {
            Receive-CompletedChunkJobs -Jobs $jobs -OrderedResults $orderedResults -Wait
        }

        $chunkText = $Chunks[$c]
    Write-Host "Queueing chunk $($c+1)/$($Chunks.Count) (length=$($chunkText.Length))" -ForegroundColor DarkCyan
        $job = Start-ThreadJob -ArgumentList $c, $chunkText, $Instruction, $ApiKey, $OpenAIEndpoint, $helperSource, $Model -ScriptBlock {
            param($chunkIndex, $result, $instruction, $apiKey, $openAIEndpoint, $helperSource, $modelName)

            # Re-create the shared resilient helpers inside this runspace (thread jobs do not
            # inherit parent-scope functions) so retry/backoff and error surfacing match the
            # sequential path exactly.
            . ([scriptblock]::Create($helperSource))

            $body = Get-DlpAnalysisBody -Instruction $instruction -Result $result -Model $modelName
            $headers = @{
                "Content-Type" = "application/json"
                "api-key"      = $apiKey
            }

            $chunkResult = $null
            $chunkError = $null
            try {
                $resp = Invoke-DlpOpenAIRequest -Uri $openAIEndpoint -Headers $headers -Body $body -Label "Chunk $($chunkIndex + 1)"
                $chunkResult = $resp.output.content.text
            } catch {
                $chunkError = [string]$_
            }

            [pscustomobject]@{
                Index = $chunkIndex
                Result = $chunkResult
                Error = $chunkError
            }
        }

        $jobs.Add($job)
        Receive-CompletedChunkJobs -Jobs $jobs -OrderedResults $orderedResults
    }

    while ($jobs.Count -gt 0) {
        Receive-CompletedChunkJobs -Jobs $jobs -OrderedResults $orderedResults -Wait
    }

    foreach ($orderedResult in $orderedResults) {
        if ($orderedResult) {
            $analysisResults.Add($orderedResult)
        }
    }

    return $analysisResults
}

if ($detectionData.Count -gt 0) {
    # Build individually labeled items with metadata

    $maxLen = 220000
    $maxMergedLen = 355000
    $chunks = [System.Collections.Generic.List[string]]::new()
    $current = [System.Collections.Generic.List[object]]::new()
    $currentLen = 2
    foreach ($item in $detectionData) {
        $itemJson = $item | ConvertTo-Json -Depth 10 -Compress
        $separatorLen = if ($current.Count -gt 0) { 1 } else { 0 }
        $candidateLen = $currentLen + $separatorLen + $itemJson.Length
        if ($candidateLen -gt $maxLen -and $current.Count -gt 0) {
            $chunks.Add(($current | ConvertTo-Json -Depth 10 -Compress))
            $current = [System.Collections.Generic.List[object]]::new()
            $currentLen = 2
        }
        $separatorLen = if ($current.Count -gt 0) { 1 } else { 0 }
        $current.Add($item)
        $currentLen += $separatorLen + $itemJson.Length
    }
    if ($current.Count -gt 0) {
        $chunks.Add(($current | ConvertTo-Json -Depth 10 -Compress))
    }

    $analysisResults = Invoke-ChunkAnalysis -Chunks $chunks -Instruction $dlpInstruction -ApiKey $apiKey -OpenAIEndpoint $openAIEndpoint -ThreadCount $ThreadCount -DisableMultiThreading:$DisableMultiThreading

        if ($analysisResults.Count -ge 1) {
            Export-AnalysisResultsReference -AnalysisResults $analysisResults -Path $AnalysisResultsReferencePath
            Write-Output "`n--- Consolidating $($analysisResults.Count) analyses ---"

            $mergedInput = ($analysisResults | ForEach-Object { $_ }) -join "`n---CHUNK---`n"
            if ($mergedInput.Length -gt $maxMergedLen) {
                Write-Host "Merged consolidation input length $($mergedInput.Length) exceeds $maxMergedLen. Running bounded multi-pass consolidation." -ForegroundColor Yellow
                $finalMergedReport = Invoke-BoundedConsolidation -Inputs $analysisResults -InitialInstruction $consolidationInstruction -MergeInstruction $reportMergeInstruction -ApiKey $apiKey -OpenAIEndpoint $openAIEndpoint -MaxMergedLength $maxMergedLen
            } else {
                $finalMergedReport = Analyze-Data -result $mergedInput -instruction $consolidationInstruction -apiKey $apiKey -openAIEndpoint $openAIEndpoint
            }
            if ($finalMergedReport) {
                Write-Host "`n--- Final Consolidated Report (Markdown) ---" -ForegroundColor Cyan
                Write-Host $finalMergedReport
                $finalMergedReport | Out-File "SIT_Report.md" -Encoding UTF8
                Write-Output "Report saved to SIT_Report.md"

                # Also preserve a timestamped copy in the per-profile cache so the
                # built-in report viewer can browse historical reports per SIT.
                $reportCacheDir = Join-Path -Path $profileCacheDir -ChildPath 'reports'
                if (-not (Test-Path -LiteralPath $reportCacheDir)) {
                    New-Item -ItemType Directory -Path $reportCacheDir -Force | Out-Null
                }
                $reportStamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss')
                $cachedReportPath = Join-Path -Path $reportCacheDir -ChildPath ("report-{0}.md" -f $reportStamp)
                $finalMergedReport | Out-File -FilePath $cachedReportPath -Encoding UTF8
                Write-Host ("Report cached at {0}" -f $cachedReportPath) -ForegroundColor Cyan
            } else {
                Write-Output "Consolidation step failed."
            }

            # Preserve this round (chunk analyses + headline metrics + report) so a
            # later run after SIT tuning can be diffed in the web comparison tool.
            Export-RunSnapshot -AnalysisResults $analysisResults -SnapshotDir $RunSnapshotDir -Label $RunLabel -RawDetectionCount $detectionData.Count -EventStoreCount $dlpEvents.Count -AlertStoreCount $dlpAlerts.Count -DlpPolicy $dlpPolicy -ProfileName $activeProfile.Name -FinalReportMarkdown $finalMergedReport
        }
    
} else {
    Write-Output "No matches found"
}

