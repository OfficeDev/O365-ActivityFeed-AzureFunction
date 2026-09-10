# Initialize variables
param(
    [string]$dlpPolicy="",
    [int]$MaxEvents = 1500,
    [int]$DaysBack = 120,
    [string]$OpenAIEndpoint = "",
    [string]$Model = "gpt-5.4",
    [string]$AnalysisModel = "",
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
    [string]$UserDirectoryPath = "",
    [int]$WatermarkBufferHours = 1,
    [string]$RunLabel = "",
    [string]$RunSnapshotDir = "",
    [string]$ReportCacheDir = "",
    [string]$TriageOutputDir = "",
    [string]$AnalysisStartDate = "",
    [string]$AnalysisEndDate = "",
    [switch]$SkipCollection,
    [switch]$IncludeSensitiveValues,
    [switch]$UseProtectedSensitiveEvents,
    [string]$ProtectedEventStorePath = ""
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
    $sitIds = @($data.SensitiveInformationTypeIds | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $sitNames = @($data.SensitiveInformationTypeNames | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($sitIds.Count -eq 0 -and $sitNames.Count -eq 0) {
        throw "Analysis profile '$resolvedPath' has no explicit SensitiveInformationTypeIds or SensitiveInformationTypeNames allow-list. Analysis fails closed."
    }
    if ([string]::IsNullOrWhiteSpace([string]$data.Name)) { $data.Name = [System.IO.Path]::GetFileNameWithoutExtension($resolvedPath) }
    $data.SourcePath = $resolvedPath
    return $data
}

$sitScopeHelperPath = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'SitScopeHelpers.ps1' } else { Join-Path (Get-Location) 'SitScopeHelpers.ps1' }
if (-not (Test-Path -LiteralPath $sitScopeHelperPath)) { throw "SIT scope helper not found: '$sitScopeHelperPath'." }
. $sitScopeHelperPath

$activeProfile = Import-AnalysisProfile -ProfileName $AnalysisProfile -ProfileFilePath $ProfilePath -ScriptRoot $PSScriptRoot
$sitScope = New-SitAnalysisScope -Ids @($activeProfile.SensitiveInformationTypeIds) -Names @($activeProfile.SensitiveInformationTypeNames)
if ([string]::IsNullOrWhiteSpace($AnalysisModel)) { $AnalysisModel = $Model }

# Optional assessment period applies only after loading the existing shared
# stores. Dates are inclusive UTC calendar days; the end is implemented as the
# next midnight exclusive so no Graph collection query needs to change.
$analysisStartUtc = $null
$analysisEndExclusiveUtc = $null
$analysisPeriodLabel = 'All synchronized evidence'
if (-not [string]::IsNullOrWhiteSpace($AnalysisStartDate) -or -not [string]::IsNullOrWhiteSpace($AnalysisEndDate)) {
    if ([string]::IsNullOrWhiteSpace($AnalysisStartDate) -or [string]::IsNullOrWhiteSpace($AnalysisEndDate)) { throw 'Select both AnalysisStartDate and AnalysisEndDate, or leave both blank.' }
    if (-not $SkipCollection) { throw 'Assessment periods are supported only with -SkipCollection so collection and Graph queries remain unchanged.' }
    try {
        $analysisStartUtc = [datetime]::ParseExact($AnalysisStartDate, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime()
        $analysisEndUtc = [datetime]::ParseExact($AnalysisEndDate, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime()
    } catch { throw 'AnalysisStartDate and AnalysisEndDate must use valid YYYY-MM-DD dates.' }
    if ($analysisEndUtc -lt $analysisStartUtc) { throw 'AnalysisEndDate must be on or after AnalysisStartDate.' }
    $analysisEndExclusiveUtc = $analysisEndUtc.AddDays(1)
    $analysisPeriodLabel = "$AnalysisStartDate through $AnalysisEndDate"
}

# Profile supplies the default DLP policy filter; an explicit -dlpPolicy wins.
if (-not $PSBoundParameters.ContainsKey('dlpPolicy') -or [string]::IsNullOrWhiteSpace($dlpPolicy)) {
    $dlpPolicy = if (-not [string]::IsNullOrWhiteSpace([string]$activeProfile.DlpPolicy)) { [string]$activeProfile.DlpPolicy } else { '*' }
}
Write-Output ("Analysis profile: {0} ({1}) | DLP policy filter: {2}" -f $activeProfile.Name, $activeProfile.Description, $dlpPolicy)
Write-Output ("Exact SIT allow-list: {0} ID(s), {1} name(s)." -f $sitScope.Ids.Count, $sitScope.Names.Count)
Write-Output ("AI model routing: chunk analysis and incident triage={0}; report consolidation={1}." -f $AnalysisModel, $Model)

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

# Validate Microsoft Foundry / Azure OpenAI configuration.
if ([string]::IsNullOrWhiteSpace($OpenAIEndpoint)) { $OpenAIEndpoint = $env:AZURE_OPENAI_REPORTING_ENDPOINT }
if ([string]::IsNullOrWhiteSpace($OpenAIEndpoint)) {
    Write-Host "ERROR: Supply -OpenAIEndpoint or set `$env:AZURE_OPENAI_REPORTING_ENDPOINT." -ForegroundColor Red
    exit 1
}
if (-not $env:AZURE_OPENAI_REPORTING_KEY -and -not $env:AZURE_OPENAI_API_KEY2 -and -not $env:AZURE_OPENAI_API_KEY) {
    Write-Host "ERROR: Set `$env:AZURE_OPENAI_REPORTING_KEY, `$env:AZURE_OPENAI_API_KEY2, or `$env:AZURE_OPENAI_API_KEY before running this script." -ForegroundColor Red
    exit 1
}

# Prefer the Studio reporting key, then retain compatibility with legacy variable names.
$apiKey = if ($env:AZURE_OPENAI_REPORTING_KEY) { $env:AZURE_OPENAI_REPORTING_KEY } elseif ($env:AZURE_OPENAI_API_KEY2) { $env:AZURE_OPENAI_API_KEY2 } else { $env:AZURE_OPENAI_API_KEY }

if (-not $SkipCollection) {
    # Authenticate only when this script owns collection. Shared-store runs use
    # DLP Response Studio's existing redacted JSONL and never contact Graph.
    if (-not ($token)) {
        $graphScopes = "SecurityEvents.Read.All","SecurityAlert.Read.All","CustomTags.Read.All"
        if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
            Connect-MgGraph -Scopes $graphScopes -TenantId $TenantId -NoWelcome
        } else {
            Connect-MgGraph -Scopes $graphScopes -NoWelcome
        }
    }

    $mgContext = Get-MgContext
    if ($mgContext) {
        Write-Host "Connected to Microsoft Graph as '$($mgContext.Account)' (tenant $($mgContext.TenantId))." -ForegroundColor Cyan
    } else {
        Write-Host "WARNING: No Microsoft Graph context after Connect-MgGraph." -ForegroundColor Yellow
    }

    $resource = "https://graph.microsoft.com"
    $mgrequest = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/me" -OutputType HttpResponseMessage
    $token = $mgRequest.RequestMessage.Headers.Authorization.Parameter

    $headerParams = @{
        'Authorization'    = "Bearer $token"
        'ConsistencyLevel' = 'eventual'
    }
} else {
    Write-Host "Shared-store mode: Graph collection is skipped; using DLP Response Studio JSONL." -ForegroundColor Cyan
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

function Read-DlpProtectedStore {
    param([Parameter(Mandatory)][string]$Path)
    $map = [ordered]@{}
    if (-not (Test-Path -LiteralPath $Path)) { return $map }
    $entropy = [Text.Encoding]::UTF8.GetBytes('DlpResponseStudio.SitOptimize.v1')
    foreach ($line in [IO.File]::ReadLines($Path)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $envelope = $line | ConvertFrom-Json -Depth 10 -ErrorAction Stop
            if ($envelope.protection -ne 'DPAPI-CurrentUser' -or -not $envelope.ciphertext) { continue }
            $cipherBytes = [Convert]::FromBase64String([string]$envelope.ciphertext)
            $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect($cipherBytes, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
            $event = [Text.Encoding]::UTF8.GetString($plainBytes) | ConvertFrom-Json -Depth 60 -ErrorAction Stop
            if ($event.id) { $map[[string]$event.id] = $event }
        } catch { throw "Unable to decrypt protected SIT evidence under the current Windows identity: $($_.Exception.Message)" }
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

function New-DlpAlertIndex {
    param([object[]]$Alerts)
    $index = @{}
    foreach ($alert in @($Alerts)) {
        $detectorId = [string]$alert.detectorId
        if ([string]::IsNullOrWhiteSpace($detectorId)) { continue }
        if (-not $index.ContainsKey($detectorId)) { $index[$detectorId] = [Collections.Generic.List[object]]::new() }
        [void]$index[$detectorId].Add($alert)
    }
    return $index
}

function Resolve-DlpEventAlert {
    param(
        [Parameter(Mandatory)][object]$Event,
        [Parameter(Mandatory)][hashtable]$AlertIndex
    )
    $detectorId = [string]$Event.alertCorrelationId
    if ([string]::IsNullOrWhiteSpace($detectorId) -or -not $AlertIndex.ContainsKey($detectorId)) { return $null }
    $candidates = @($AlertIndex[$detectorId])
    $lineageAlertId = [string]$Event._dlpResponseStudio.alertId
    if (-not [string]::IsNullOrWhiteSpace($lineageAlertId)) {
        $explicit = @($candidates | Where-Object { [string]$_.id -eq $lineageAlertId })
        if ($explicit.Count -eq 1) { return $explicit[0] }
    }
    $startValue = if ($Event.startDateTime) { $Event.startDateTime } else { $Event.createdDateTime }
    $endValue = if ($Event.endDateTime) { $Event.endDateTime } else { $startValue }
    try { $eventStart = ([datetimeoffset]$startValue).UtcDateTime; $eventEnd = ([datetimeoffset]$endValue).UtcDateTime } catch { return $null }
    $matches = @($candidates | Where-Object {
        try {
            $alertStart = ([datetimeoffset]$_.firstActivityDateTime).UtcDateTime
            $alertEnd = ([datetimeoffset]$_.lastActivityDateTime).UtcDateTime
            $eventStart -ge $alertStart -and $eventEnd -le $alertEnd
        } catch { $false }
    })
    if ($matches.Count -eq 1) { return $matches[0] }
    return $null
}

# Load existing stores + sync state (unless a full rebuild was requested).
$eventStore = [ordered]@{}
$alertStore = [ordered]@{}
$syncState  = $null
if ($FullPull) {
    Write-Output "FullPull requested: rebuilding event and alert stores from scratch."
} else {
    if ($SkipCollection -and $UseProtectedSensitiveEvents) {
        if ([string]::IsNullOrWhiteSpace($ProtectedEventStorePath)) { throw '-ProtectedEventStorePath is required with -UseProtectedSensitiveEvents.' }
        $eventStore = Read-DlpProtectedStore -Path $ProtectedEventStorePath
        Write-Output ("Loaded {0} DPAPI-protected sensitive event(s) under the current Windows identity." -f $eventStore.Count)
    } else {
        $eventStore = Read-DlpJsonlStore -Path $EventStorePath
    }
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

if ($SkipCollection) {
    if ($FullPull) { throw '-FullPull cannot be combined with -SkipCollection.' }
    if ($eventStore.Count -eq 0) { throw "Shared DLP event store is empty or missing: '$EventStorePath'. Run Sync DLP alerts in DLP Response Studio first." }

    # Scope the shared stores without modifying either source file. detectorId
    # identifies a detector, so event ownership also requires the alert activity window.
    $matchingAlerts = [Collections.Generic.List[object]]::new()
    foreach ($storedAlert in $alertStore.Values) {
        $policyTitle = [string]$storedAlert.additionalData.alertPolicytitle
        if ($policyTitle -like $dlpPolicy) {
            [void]$matchingAlerts.Add($storedAlert)
        }
    }
    $dlpAlerts = @($matchingAlerts)
    $matchingAlertIndex = New-DlpAlertIndex -Alerts $dlpAlerts
    $dlpEvents = @($eventStore.Values | Where-Object { $null -ne (Resolve-DlpEventAlert -Event $_ -AlertIndex $matchingAlertIndex) })
    if ($analysisStartUtc) {
        $dlpEvents = @($dlpEvents | Where-Object {
            $observedTime = if ($_.createdDateTime) { $_.createdDateTime } else { $_.startDateTime }
            if (-not $observedTime) { return $false }
            try { $observedUtc = ([datetimeoffset]$observedTime).UtcDateTime } catch { return $false }
            return $observedUtc -ge $analysisStartUtc -and $observedUtc -lt $analysisEndExclusiveUtc
        })
        $periodDetectorIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($periodEvent in $dlpEvents) { if ($periodEvent.alertCorrelationId) { [void]$periodDetectorIds.Add([string]$periodEvent.alertCorrelationId) } }
        $dlpAlerts = @($dlpAlerts | Where-Object { $_.detectorId -and $periodDetectorIds.Contains([string]$_.detectorId) })
    }
    $sourceMode = if ($UseProtectedSensitiveEvents) { 'DPAPI-protected sensitive evidence' } else { 'redacted shared JSONL' }
    Write-Output ("Shared-store profile scope: {0} matching alert(s), {1} matching event(s), policy='{2}', source={3}." -f $dlpAlerts.Count, $dlpEvents.Count, $dlpPolicy, $sourceMode)
    Write-Output ("Assessment period: {0} (inclusive UTC calendar dates; local-store filter)." -f $analysisPeriodLabel)
} else {

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
            $eventItem | Add-Member -NotePropertyName '_dlpResponseStudio' -NotePropertyValue ([pscustomobject]@{
                alertId = [string]$detail.AlertId
                correlatedUtc = (Get-Date).ToUniversalTime().ToString('o')
                correlation = 'detector-and-alert-activity-window-v2'
            }) -Force
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
}


# Load optional Graph-resolved organizational context. Keys are lowercased UPNs,
# but identities are never copied into the analysis payload.
$resolvedUserDirectory = @{}
if (-not [string]::IsNullOrWhiteSpace($UserDirectoryPath) -and (Test-Path -LiteralPath $UserDirectoryPath)) {
    try {
        $directoryDocument = Get-Content -LiteralPath $UserDirectoryPath -Raw | ConvertFrom-Json -ErrorAction Stop
        foreach ($property in $directoryDocument.PSObject.Properties) {
            $department = [string]$property.Value.department
            if (-not [string]::IsNullOrWhiteSpace($department)) { $resolvedUserDirectory[$property.Name.ToLowerInvariant()] = $department.Trim() }
        }
        Write-Output ("Loaded {0} Graph-resolved user department mapping(s)." -f $resolvedUserDirectory.Count)
    } catch {
        Write-Output ("WARNING: Department cache could not be loaded; assessment will continue without department context - {0}" -f $_.Exception.Message)
    }
}

# Extract SensitiveInformationDetections from audit records for AI analysis.
# Resolve ownership using detector + alert activity window; detectorId alone is not alert-unique.
$analysisAlertIndex = New-DlpAlertIndex -Alerts $dlpAlerts
$detectionData = [System.Collections.Generic.List[hashtable]]::new()
$evidenceOrdinal = 0
foreach ($dlpEvent in $dlpEvents) {
    $owningAlert = Resolve-DlpEventAlert -Event $dlpEvent -AlertIndex $analysisAlertIndex
    $auditRecord = $null

    # Attempt to parse auditRecord JSON if it exists
    if ($dlpEvent.auditRecord) {
        if ($dlpEvent.auditRecord -is [string]) {
            try { $auditRecord = $dlpEvent.auditRecord | ConvertFrom-Json -ErrorAction Stop } catch { $auditRecord = $null }
        } else {
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
                            $sensitiveTypeId = [string]$sensInfo.SensitiveType
                            if ([string]::IsNullOrWhiteSpace($sensitiveTypeId) -and $sensInfo.PSObject.Properties.Name -contains 'SensitiveInformationTypeId') {
                                $sensitiveTypeId = [string]$sensInfo.SensitiveInformationTypeId
                            }
                            $sensitiveTypeName = [string]$sensInfo.SensitiveInformationTypeName
                            if (-not (Test-SensitiveInformationInScope -SensitiveInformation $sensInfo -Scope $sitScope)) { continue }
                            if ($sensInfo.SensitiveInformationDetections) {
                                $evidenceOrdinal++
                                $storedValues = @($sensInfo.SensitiveInformationDetections.DetectedValues.Value)
                                $analysisValues = if ($SkipCollection -and -not $IncludeSensitiveValues) { @('[REDACTED]') } else { $storedValues }
                                $correlationId = [string]$dlpEvent.alertCorrelationId
                                $directoryKey = ([string]$auditRecord.UserId).Trim().ToLowerInvariant()
                                $resolvedDepartment = if ($directoryKey -and $resolvedUserDirectory.ContainsKey($directoryKey)) { [string]$resolvedUserDirectory[$directoryKey] } else { '' }
                                $detection = @{
                                    EvidenceRef                = ('DLPREF-{0:D6}' -f $evidenceOrdinal)
                                    SensitiveType              = $sensitiveTypeId
                                    SensitiveTypeName          = $sensitiveTypeName
                                    Location                   = $sensInfo.Location
                                    DetectedValues             = $analysisValues
                                    EventId                    = [string]$dlpEvent.id
                                    AlertCorrelationId         = $correlationId
                                    IncidentId                 = if ($owningAlert -and $owningAlert.incidentId) { [string]$owningAlert.incidentId } else { '' }
                                    ResponseTime               = if ($dlpEvent.createdDateTime) { $dlpEvent.createdDateTime } else { $dlpEvent.startDateTime }
                                    UserId                     = if ($SkipCollection) { '[REDACTED]' } else { $auditRecord.UserId }
                                    Department                 = $resolvedDepartment
                                    Workload                   = $auditRecord.Workload
                                    FullRecipients             = if ($SkipCollection) { @() } else { $auditRecord.FullRecipients }
                                    ContentInfo                = if ($SkipCollection) { '[REDACTED]' } else { $auditRecord.ContentInfo.FullName }
                                    Sender                     = if ($SkipCollection) { '[REDACTED]' } elseif ($auditRecord.EnrichedEmailInfo) { $auditRecord.EnrichedEmailInfo.Sender } else { "unknown" }
                                    Subject                    = if ($SkipCollection) { '[REDACTED]' } elseif ($auditRecord.EnrichedEmailInfo) { $auditRecord.EnrichedEmailInfo.Subject } else { "unknown" }
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
$resolvedDepartmentDetections = @($detectionData | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Department) })
$assessmentDepartments = @($resolvedDepartmentDetections | ForEach-Object { [string]$_.Department } | Sort-Object -Unique)
$departmentContext = [pscustomobject]@{
    resolvedDetectionCount = $resolvedDepartmentDetections.Count
    unresolvedDetectionCount = [Math]::Max(0, $detectionData.Count - $resolvedDepartmentDetections.Count)
    departmentCount = $assessmentDepartments.Count
    departments = $assessmentDepartments
}
Write-Output ("Department context attached to {0} detection(s) across {1} department(s); {2} detection(s) unresolved." -f $departmentContext.resolvedDetectionCount, $departmentContext.departmentCount, $departmentContext.unresolvedDetectionCount)
$resolvedIncidentIds = @($detectionData | ForEach-Object { [string]$_.IncidentId } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
Write-Output ("Incident lineage attached to {0} detection(s) across {1} incident(s)." -f @($detectionData | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.IncidentId) }).Count, $resolvedIncidentIds.Count)

# Domain-specific AI instructions come from the selected analysis profile so
# the same pipeline can target any sensitive information type. See profiles/.
$dlpInstruction          = [string]$activeProfile.ExtractionInstruction
$consolidationInstruction = [string]$activeProfile.ConsolidationInstruction
$reportMergeInstruction  = [string]$activeProfile.ReportMergeInstruction
$scopeBoundary = @"
MANDATORY ANALYSIS SCOPE: The input has been pre-filtered to the profile's explicit Sensitive Information Type allow-list. Analyze only these SIT IDs: $($sitScope.Ids -join ', '). Analyze only these SIT names: $($sitScope.Names -join ', '). Do not classify, infer, compare, or make recommendations for any other Sensitive Information Type. If unrelated content is mentioned in context, ignore it.

MANDATORY INCIDENT TRIAGE OUTPUT: Whatever operator or end-user analysis instructions follow, every JSON response MUST include a top-level triaged_entries array. Create no more than one entry per non-empty IncidentId represented in this chunk. Each entry MUST use this exact contract: {"incident_id":"copied exactly from input","priority":"HIGH|MEDIUM|LOW","disposition":"LIVE_CREDENTIAL|LIKELY_CREDENTIAL|NOISE|INDETERMINATE","validity_status":"ACTIVE|EXPIRED|TRUNCATED|REVOKED|INDETERMINATE","evidence_count":0,"security_comment":"one to three concise sentences for a security incident analyst","false_positive_patterns":[{"pattern_family":"structural pattern, never the detected value","triggering_sit_rule":"SIT name or ID","reason_false_positive":"why the structure is benign","supporting_indicators":["privacy-safe structural indicator"],"suppression_strategy":"narrow Purview-ready change","false_negative_guardrail":"condition that must remain detectable","workload":"workload","location":"detection location","occurrence_count":0,"confidence":"HIGH|MEDIUM|LOW"}]}. HIGH means credible live or active credential exposure requiring immediate investigation; MEDIUM means likely credential exposure or material ambiguity requiring review; LOW means likely benign/noise with limited security impact. For NOISE dispositions, false_positive_patterns is mandatory and must identify the structural pattern, triggering SIT, benign rationale, supporting context, narrow suppression strategy, and false-negative guardrail needed to design a Purview change. Do not return generic statements such as likely noise without these details. The security_comment and false-positive pattern fields MUST NOT contain, quote, reconstruct, or hint at any credential, token, password, secret, detected value, person, recipient, sender, file name, subject, full URL, or other sensitive artifact. Host/path families, parameter-name classes, workload, location, and authentication-context presence or absence are allowed when needed for a deployable control recommendation. State when evidence is insufficient. In a redacted/context-only run, never claim a credential is live or active: use validity_status INDETERMINATE and explain that protected validation is required. This mandatory contract cannot be removed, renamed, or weakened by later instructions.

MANDATORY CORRELATION ENVELOPE: Every JSON response MUST also include top-level evidence_bindings and every triaged_entries item MUST include evidence_refs. For every input record, copy its EvidenceRef and IncidentId exactly into evidence_bindings as {"evidence_ref":"DLPREF-000001","incident_id":"copied exactly from input"}. Put the applicable evidence_refs on each triage entry and each noise_patterns item. Never invent, normalize, summarize, omit, or alter these identifiers. They are opaque join keys, not evidence. This envelope is mandatory even when the profile's later JSON example does not show these fields.

DEPARTMENT TUNING CONTEXT: A non-empty Department field is read-only organizational metadata resolved from Microsoft Graph before this assessment. Use it to identify department concentration, recurring department-specific context, validation ownership, and whether recommended tuning should be piloted or monitored by department. Include material department observations in workload_context, recommendations, consolidation, and the final report. Never infer a missing department, identify a person, broaden the selected SIT boundary, or use department alone as a suppression condition. Preserve true-positive guardrails across every department.

"@
if ($analysisStartUtc) {
    $scopeBoundary += "MANDATORY ASSESSMENT PERIOD: This run contains only events observed from $AnalysisStartDate through $AnalysisEndDate, inclusive, using UTC calendar dates. Describe findings as belonging to this period and do not extrapolate counts to other dates.`n`n"
}
$analysisFocus = [string]$activeProfile.AnalysisFocus
if (-not [string]::IsNullOrWhiteSpace($analysisFocus)) {
    $scopeBoundary += "AUTHORITATIVE OPERATOR ANALYSIS FOCUS:`n$analysisFocus`n`nApply these priorities when classifying noise, validating true-positive guardrails, and recommending tuning. Do not broaden the SIT scope.`n`n"
}
$dlpInstruction = $scopeBoundary + $dlpInstruction
$consolidationInstruction = $scopeBoundary + $consolidationInstruction
$reportMergeInstruction = $scopeBoundary + $reportMergeInstruction
if ($UseProtectedSensitiveEvents -and $IncludeSensitiveValues) {
    $protectedSummaryBoundary = @'
PROTECTED FALSE-POSITIVE SUMMARY CONTRACT: Step 2 is the sole protected-content analysis stage. In noise_patterns, regex_refinements, exclusion_rules, recommendations, every consolidation pass, and the final Markdown report, preserve the exact host, path, parameter, non-secret value, keyword, pattern, and tested regex already determined to be false-positive evidence when needed to configure or validate a Purview control. Clearly label exact artifacts as protected false-positive evidence and retain the triggering SIT, workload/location, occurrence count, benign rationale, suppression strategy, and false-negative guardrail. Never place exact artifacts in triaged_entries.security_comment or triaged_entries.false_positive_patterns. Never reproduce validated or possible credentials, payment-card numbers, personal data, identities, message content, or unrelated detected values. If an artifact could still be genuine sensitive data, redact it and identify protected human validation as required. The final report is the authoritative Step 2 summary consumed by Step 3; do not replace its actionable patterns with generic descriptions during consolidation or merging.

'@
    $dlpInstruction = $protectedSummaryBoundary + $dlpInstruction
    $consolidationInstruction = $protectedSummaryBoundary + $consolidationInstruction
    $reportMergeInstruction = $protectedSummaryBoundary + $reportMergeInstruction
}
if ($SkipCollection -and -not $IncludeSensitiveValues) {
    $privacyBoundary = @'
PRIVACY BOUNDARY FOR THIS RUN: detected values, identities, recipients, content names, senders, and subjects are redacted. Perform context-only SIT tuning from policy, workload, sensitive-type, location, Graph-resolved department when available, confidence, frequency, and count metadata. Department is organizational context and must not be used to infer identity. Never infer, fabricate, reconstruct, or claim to validate an exact sensitive value, regex, credential, payment-card number, identity, or document. Mark exact-value and regex recommendations as requiring a separate controlled validation sample. Treat validated finding counts as metadata-based estimates, not content validation.

'@
    $dlpInstruction = $privacyBoundary + $dlpInstruction
    $consolidationInstruction = $privacyBoundary + $consolidationInstruction
    $reportMergeInstruction = $privacyBoundary + $reportMergeInstruction
}

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
        Honours a server Retry-After hint, otherwise backs off exponentially with jitter (capped
        at 90s). Only genuinely transient
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
        [string]$openAIEndpoint,
        [string]$ModelName = $Model
    )
    if (-not $apiKey -or $apiKey -like "*REPLACE*") {
        Write-Warning "API key not set; skipping AI analysis."
        return $null
    }
    $body = Get-DlpAnalysisBody -Instruction $instruction -Result $result -Model $ModelName
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

function ConvertTo-SafeSecurityComment {
    param([string]$Text, [object[]]$SensitiveValues = @())
    $safe = [string]$Text
    foreach ($rawValue in $SensitiveValues) {
        $value = [string]$rawValue
        if ($value -and $value -ne '[REDACTED]' -and $value.Length -ge 3) { $safe = $safe.Replace($value, '[sensitive artifact redacted]') }
    }
    $safe = $safe -replace '(?i)\bhttps?://\S+', '[URL redacted]'
    $safe = $safe -replace '(?i)\b[^\s@]+@[^\s@]+\.[^\s@]+\b', '[identity redacted]'
    $safe = $safe -replace '(?<!\w)(?:[A-Za-z0-9+/_=]{20,}|(?=[A-Za-z0-9+/_=-]{20,}(?!\w))(?=[A-Za-z0-9+/_=-]*[0-9+/_=])[A-Za-z0-9+/_=-]{20,})(?!\w)', '[sensitive artifact redacted]'
    $safe = ($safe -replace '[\x00-\x1f\x7f]+', ' ' -replace '\s+', ' ').Trim()
    if ($safe.Length -gt 1500) { $safe = $safe.Substring(0, 1500) }
    return $safe
}

function Export-IncidentTriage {
    param(
        [System.Collections.Generic.List[string]]$AnalysisResults,
        [string]$OutputDir,
        [string]$ProfileName,
        [string]$Label,
        [string]$AnalysisStartDate,
        [string]$AnalysisEndDate,
        [string]$ModelName,
        [object[]]$DetectionData = @(),
        [object[]]$ChunkIncidentIds = @(),
        [object[]]$SensitiveValues = @()
    )
    if (-not $AnalysisResults -or $AnalysisResults.Count -eq 0 -or [string]::IsNullOrWhiteSpace($OutputDir)) { return }
    $priorityRank = @{ LOW = 1; MEDIUM = 2; HIGH = 3 }
    $allowedDisposition = @('LIVE_CREDENTIAL', 'LIKELY_CREDENTIAL', 'NOISE', 'INDETERMINATE')
    $allowedValidity = @('ACTIVE', 'EXPIRED', 'TRUNCATED', 'REVOKED', 'INDETERMINATE')
    $expectedIncidents = @{}
    $evidenceToIncident = @{}
    $incidentMetadata = @{}
    foreach ($detection in @($DetectionData)) {
        $expectedIncidentId = [string]$detection.IncidentId
        if ([string]::IsNullOrWhiteSpace($expectedIncidentId) -or $expectedIncidentId -notmatch '^[A-Za-z0-9-]{1,100}$') { continue }
        if (-not $expectedIncidents.ContainsKey($expectedIncidentId)) { $expectedIncidents[$expectedIncidentId] = 0 }
        $expectedIncidents[$expectedIncidentId]++
        $evidenceRef = [string]$detection.EvidenceRef
        if ($evidenceRef -match '^DLPREF-[0-9]{6}$') { $evidenceToIncident[$evidenceRef] = $expectedIncidentId }
        if (-not $incidentMetadata.ContainsKey($expectedIncidentId)) {
            $incidentMetadata[$expectedIncidentId] = [pscustomobject]@{ Sit = [string]$detection.SensitiveTypeName; Workload = [string]$detection.Workload; Location = [string]$detection.Location }
        }
    }
    $byIncident = @{}
    $fallbackPatternsByIncident = @{}
    for ($analysisIndex = 0; $analysisIndex -lt $AnalysisResults.Count; $analysisIndex++) {
        $analysisText = $AnalysisResults[$analysisIndex]
        try { $parsed = $analysisText | ConvertFrom-Json -Depth 100 -ErrorAction Stop } catch { continue }
        $chunkIds = if ($analysisIndex -lt $ChunkIncidentIds.Count) { @($ChunkIncidentIds[$analysisIndex]) } else { @() }
        foreach ($binding in @($parsed.evidence_bindings)) {
            $bindingRef = [string]$binding.evidence_ref
            $bindingIncident = [string]$binding.incident_id
            if ($evidenceToIncident.ContainsKey($bindingRef) -and $evidenceToIncident[$bindingRef] -eq $bindingIncident) { $chunkIds += $bindingIncident }
        }
        $chunkIds = @($chunkIds | Where-Object { $expectedIncidents.ContainsKey([string]$_) } | Sort-Object -Unique)
        foreach ($noisePattern in @($parsed.noise_patterns)) {
            $trigger = ConvertTo-SafeSecurityComment -Text ([string]$noisePattern.triggering_sit_rule) -SensitiveValues $SensitiveValues
            $reason = ConvertTo-SafeSecurityComment -Text ([string]$noisePattern.reason_false_positive) -SensitiveValues $SensitiveValues
            $strategy = ConvertTo-SafeSecurityComment -Text ([string]$noisePattern.suppression_strategy) -SensitiveValues $SensitiveValues
            if ([string]::IsNullOrWhiteSpace($reason) -or [string]::IsNullOrWhiteSpace($strategy)) { continue }
            $family = ConvertTo-SafeSecurityComment -Text ([string]$noisePattern.pattern) -SensitiveValues $SensitiveValues
            if ([string]::IsNullOrWhiteSpace($family) -or $family -match '^\[(URL|identity|sensitive artifact) redacted\]$') { $family = $reason }
            $indicators = @($noisePattern.noise_signal_keywords | ForEach-Object { ConvertTo-SafeSecurityComment -Text ([string]$_) -SensitiveValues $SensitiveValues } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 8)
            $patternCount = 0
            try { $patternCount = [Math]::Max(0, [int]$noisePattern.occurrence_count) } catch { $patternCount = 0 }
            $guardrail = @($parsed.regex_refinements | Where-Object { [string]$_.triggering_sit_rule -eq [string]$noisePattern.triggering_sit_rule } | ForEach-Object { ConvertTo-SafeSecurityComment -Text ([string]$_.false_negative_risk) -SensitiveValues $SensitiveValues } | Where-Object { $_ } | Select-Object -First 1)
            if ($guardrail.Count -eq 0) { $guardrail = @('Retain matches with credential-specific structure, labels, authorization context, or other true-positive indicators.') }
            $patternRefs = @($noisePattern.evidence_refs | ForEach-Object { [string]$_ } | Where-Object { $evidenceToIncident.ContainsKey($_) } | ForEach-Object { $evidenceToIncident[$_] } | Sort-Object -Unique)
            $targetIncidents = if ($patternRefs.Count -gt 0) { $patternRefs } else { $chunkIds }
            foreach ($targetIncident in $targetIncidents) {
                if (-not $fallbackPatternsByIncident.ContainsKey($targetIncident)) { $fallbackPatternsByIncident[$targetIncident] = [System.Collections.Generic.List[object]]::new() }
                $metadata = $incidentMetadata[$targetIncident]
                $fallbackPatternsByIncident[$targetIncident].Add([pscustomobject]@{
                    patternFamily = $family; triggeringSitRule = if ($trigger) { $trigger } else { [string]$metadata.Sit }; reasonFalsePositive = $reason
                    supportingIndicators = $indicators; suppressionStrategy = $strategy; falseNegativeGuardrail = [string]$guardrail[0]
                    workload = [string]$metadata.Workload; location = [string]$metadata.Location; occurrenceCount = $patternCount; confidence = 'MEDIUM'; bindingBasis = if ($patternRefs.Count -gt 0) { 'evidence-reference' } else { 'analysis-batch-fallback' }
                })
            }
        }
        foreach ($item in @($parsed.triaged_entries)) {
            $incidentId = [string]$item.incident_id
            $referencedIncidents = @($item.evidence_refs | ForEach-Object { [string]$_ } | Where-Object { $evidenceToIncident.ContainsKey($_) } | ForEach-Object { $evidenceToIncident[$_] } | Sort-Object -Unique)
            if (($incidentId -notmatch '^[A-Za-z0-9-]{1,100}$' -or -not $expectedIncidents.ContainsKey($incidentId)) -and $referencedIncidents.Count -eq 1) { $incidentId = [string]$referencedIncidents[0] }
            if ([string]::IsNullOrWhiteSpace($incidentId) -or $incidentId -notmatch '^[A-Za-z0-9-]{1,100}$') { continue }
            if ($expectedIncidents.Count -gt 0 -and -not $expectedIncidents.ContainsKey($incidentId)) { continue }
            $priority = ([string]$item.priority).ToUpperInvariant()
            if (-not $priorityRank.ContainsKey($priority)) { $priority = 'MEDIUM' }
            $disposition = ([string]$item.disposition).ToUpperInvariant()
            if ($disposition -notin $allowedDisposition) { $disposition = 'INDETERMINATE' }
            $validity = ([string]$item.validity_status).ToUpperInvariant()
            if ($validity -notin $allowedValidity) { $validity = 'INDETERMINATE' }
            $comment = ConvertTo-SafeSecurityComment -Text ([string]$item.security_comment) -SensitiveValues $SensitiveValues
            if ([string]::IsNullOrWhiteSpace($comment)) { continue }
            $falsePositivePatterns = [System.Collections.Generic.List[object]]::new()
            foreach ($pattern in @($item.false_positive_patterns)) {
                $family = ConvertTo-SafeSecurityComment -Text ([string]$pattern.pattern_family) -SensitiveValues $SensitiveValues
                $reason = ConvertTo-SafeSecurityComment -Text ([string]$pattern.reason_false_positive) -SensitiveValues $SensitiveValues
                $strategy = ConvertTo-SafeSecurityComment -Text ([string]$pattern.suppression_strategy) -SensitiveValues $SensitiveValues
                $guardrail = ConvertTo-SafeSecurityComment -Text ([string]$pattern.false_negative_guardrail) -SensitiveValues $SensitiveValues
                if ([string]::IsNullOrWhiteSpace($family) -or [string]::IsNullOrWhiteSpace($reason) -or [string]::IsNullOrWhiteSpace($strategy) -or [string]::IsNullOrWhiteSpace($guardrail)) { continue }
                $indicators = @($pattern.supporting_indicators | ForEach-Object { ConvertTo-SafeSecurityComment -Text ([string]$_) -SensitiveValues $SensitiveValues } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 8)
                $patternCount = 0
                try { $patternCount = [Math]::Max(0, [int]$pattern.occurrence_count) } catch { $patternCount = 0 }
                $patternConfidence = ([string]$pattern.confidence).ToUpperInvariant()
                if ($patternConfidence -notin @('HIGH', 'MEDIUM', 'LOW')) { $patternConfidence = 'MEDIUM' }
                $falsePositivePatterns.Add([pscustomobject]@{
                    patternFamily = $family
                    triggeringSitRule = ConvertTo-SafeSecurityComment -Text ([string]$pattern.triggering_sit_rule) -SensitiveValues $SensitiveValues
                    reasonFalsePositive = $reason
                    supportingIndicators = $indicators
                    suppressionStrategy = $strategy
                    falseNegativeGuardrail = $guardrail
                    workload = ConvertTo-SafeSecurityComment -Text ([string]$pattern.workload) -SensitiveValues $SensitiveValues
                    location = ConvertTo-SafeSecurityComment -Text ([string]$pattern.location) -SensitiveValues $SensitiveValues
                    occurrenceCount = $patternCount
                    confidence = $patternConfidence
                })
            }
            if ($falsePositivePatterns.Count -eq 0 -and $fallbackPatternsByIncident.ContainsKey($incidentId)) {
                foreach ($fallbackPattern in @($fallbackPatternsByIncident[$incidentId] | Select-Object -First 20)) { $falsePositivePatterns.Add($fallbackPattern) }
            }
            $evidenceCount = 0
            try { $evidenceCount = [Math]::Max(0, [int]$item.evidence_count) } catch { $evidenceCount = 0 }
            $candidate = [pscustomobject]@{
                incidentId = $incidentId
                priority = $priority
                disposition = $disposition
                validityStatus = $validity
                evidenceCount = $evidenceCount
                securityComment = $comment
                falsePositivePatterns = @($falsePositivePatterns)
            }
            if (-not $byIncident.ContainsKey($incidentId) -or $priorityRank[$priority] -gt $priorityRank[[string]$byIncident[$incidentId].priority]) { $byIncident[$incidentId] = $candidate }
        }
    }
    foreach ($expectedIncidentId in $expectedIncidents.Keys) {
        if ($byIncident.ContainsKey($expectedIncidentId)) { continue }
        $fallbackPatterns = if ($fallbackPatternsByIncident.ContainsKey($expectedIncidentId)) { @($fallbackPatternsByIncident[$expectedIncidentId] | Select-Object -First 20) } else { @() }
        $byIncident[$expectedIncidentId] = [pscustomobject]@{
            incidentId = $expectedIncidentId
            priority = 'MEDIUM'
            disposition = 'INDETERMINATE'
            validityStatus = 'INDETERMINATE'
            evidenceCount = [int]$expectedIncidents[$expectedIncidentId]
            securityComment = if ($fallbackPatterns.Count -gt 0) { "The model omitted incident-specific triage, but Detection Assurance associated $($fallbackPatterns.Count) privacy-safe false-positive pattern(s) from this incident's analysis batch. Review the binding basis and assessment report before applying a Purview change." } else { 'Detection Assurance completed, but the model did not return incident-specific triage or a reusable batch pattern. Review the scoped evidence and assessment report before taking remediation action.' }
            falsePositivePatterns = $fallbackPatterns
        }
    }
    if ($byIncident.Count -eq 0) { Write-Warning 'No resolved incident lineage was available to share with DLP Response.'; return }
    if ($byIncident.Count -gt 0 -and @($byIncident.Values | Where-Object { $_.disposition -eq 'INDETERMINATE' -and $_.securityComment -like 'Detection Assurance completed*' }).Count -gt 0) {
        Write-Warning 'AI analysis omitted one or more mandatory incident triage entries; conservative review-required fallbacks were created.'
    }
    if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    $generatedAt = (Get-Date).ToUniversalTime().ToString('o')
    $profileSlug = ($ProfileName -replace '[^A-Za-z0-9_-]', '_')
    if ([string]::IsNullOrWhiteSpace($profileSlug)) { $profileSlug = 'default' }
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss')
    $document = [ordered]@{
        schemaVersion = 2
        correlationVersion = 'detector-and-alert-activity-window-v2'
        generatedAt = $generatedAt
        profileId = $ProfileName
        label = $Label
        analysisStartDate = $AnalysisStartDate
        analysisEndDate = $AnalysisEndDate
        model = $ModelName
        privacy = 'No detected values, identities, content names, subjects, senders, recipients, or URLs are retained.'
        entries = @($byIncident.Values | Sort-Object incidentId)
    }
    $triagePath = Join-Path $OutputDir ("triage-{0}-{1}.json" -f $profileSlug, $stamp)
    $document | ConvertTo-Json -Depth 20 | Out-File -LiteralPath $triagePath -Encoding utf8
    Write-Host ("Shared {0} incident triage outcome(s) with DLP Response at {1}" -f $byIncident.Count, $triagePath) -ForegroundColor Cyan
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
        [string]$AnalysisModelName,
        [string]$ReportModelName,
        [string]$AnalysisStartDate,
        [string]$AnalysisEndDate,
        [string]$PrivacyMode,
        [object]$DepartmentContext,
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
    $analysisDurationDays = if ($AnalysisStartDate -and $AnalysisEndDate) { ([datetime]::ParseExact($AnalysisEndDate, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture).Date - [datetime]::ParseExact($AnalysisStartDate, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture).Date).Days + 1 } else { $null }

    $snapshot = [pscustomobject]@{
        label             = $resolvedLabel
        generatedAt       = $generatedAt
        profile           = $ProfileName
        dlpPolicy         = $DlpPolicy
        analysisModel     = $AnalysisModelName
        reportModel       = $ReportModelName
        rawDetectionCount = $RawDetectionCount
        eventStoreCount   = $EventStoreCount
        alertStoreCount   = $AlertStoreCount
        analysisStartDate = $AnalysisStartDate
        analysisEndDate   = $AnalysisEndDate
        privacyMode       = $PrivacyMode
        departmentContext = $DepartmentContext
        analysisDurationDays = $analysisDurationDays
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
        analysisModel     = $AnalysisModelName
        reportModel       = $ReportModelName
        rawDetectionCount = $RawDetectionCount
        analysisStartDate = $AnalysisStartDate
        analysisEndDate   = $AnalysisEndDate
        privacyMode       = $PrivacyMode
        departmentContext = $DepartmentContext
        analysisDurationDays = $analysisDurationDays
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
            return Analyze-Data -result $currentInputs[0] -instruction $instruction -apiKey $ApiKey -openAIEndpoint $OpenAIEndpoint -ModelName $Model
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
            $groupResult = Analyze-Data -result $groupPayload -instruction $instruction -apiKey $ApiKey -openAIEndpoint $OpenAIEndpoint -ModelName $Model
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
        [string]$ModelName,
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
            $res = Analyze-Data -result $chunkText -instruction $Instruction -apiKey $ApiKey -openAIEndpoint $OpenAIEndpoint -ModelName $ModelName
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
        $job = Start-ThreadJob -ArgumentList $c, $chunkText, $Instruction, $ApiKey, $OpenAIEndpoint, $helperSource, $ModelName -ScriptBlock {
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
    $chunkIncidentIds = [System.Collections.Generic.List[object]]::new()
    $current = [System.Collections.Generic.List[object]]::new()
    $currentLen = 2
    foreach ($item in $detectionData) {
        $itemJson = $item | ConvertTo-Json -Depth 10 -Compress
        $separatorLen = if ($current.Count -gt 0) { 1 } else { 0 }
        $candidateLen = $currentLen + $separatorLen + $itemJson.Length
        if ($candidateLen -gt $maxLen -and $current.Count -gt 0) {
            $chunks.Add(($current | ConvertTo-Json -Depth 10 -Compress))
            $chunkIncidentIds.Add(@($current | ForEach-Object { [string]$_.IncidentId } | Where-Object { $_ } | Sort-Object -Unique))
            $current = [System.Collections.Generic.List[object]]::new()
            $currentLen = 2
        }
        $separatorLen = if ($current.Count -gt 0) { 1 } else { 0 }
        $current.Add($item)
        $currentLen += $separatorLen + $itemJson.Length
    }
    if ($current.Count -gt 0) {
        $chunks.Add(($current | ConvertTo-Json -Depth 10 -Compress))
        $chunkIncidentIds.Add(@($current | ForEach-Object { [string]$_.IncidentId } | Where-Object { $_ } | Sort-Object -Unique))
    }

    $analysisResults = Invoke-ChunkAnalysis -Chunks $chunks -Instruction $dlpInstruction -ApiKey $apiKey -OpenAIEndpoint $openAIEndpoint -ModelName $AnalysisModel -ThreadCount $ThreadCount -DisableMultiThreading:$DisableMultiThreading

        if ($analysisResults.Count -ge 1) {
            Export-AnalysisResultsReference -AnalysisResults $analysisResults -Path $AnalysisResultsReferencePath
            $sensitiveValuesForRedaction = @($detectionData | ForEach-Object { @($_.DetectedValues) } | Where-Object { $_ -and $_ -ne '[REDACTED]' } | Sort-Object -Unique)
            Export-IncidentTriage -AnalysisResults $analysisResults -OutputDir $TriageOutputDir -ProfileName $activeProfile.Name -Label $RunLabel -AnalysisStartDate $AnalysisStartDate -AnalysisEndDate $AnalysisEndDate -ModelName $AnalysisModel -DetectionData @($detectionData) -ChunkIncidentIds @($chunkIncidentIds) -SensitiveValues $sensitiveValuesForRedaction
            Write-Output "`n--- Consolidating $($analysisResults.Count) analyses ---"

            $mergedInput = ($analysisResults | ForEach-Object { $_ }) -join "`n---CHUNK---`n"
            if ($mergedInput.Length -gt $maxMergedLen) {
                Write-Host "Merged consolidation input length $($mergedInput.Length) exceeds $maxMergedLen. Running bounded multi-pass consolidation." -ForegroundColor Yellow
                $finalMergedReport = Invoke-BoundedConsolidation -Inputs $analysisResults -InitialInstruction $consolidationInstruction -MergeInstruction $reportMergeInstruction -ApiKey $apiKey -OpenAIEndpoint $openAIEndpoint -MaxMergedLength $maxMergedLen
            } else {
                $finalMergedReport = Analyze-Data -result $mergedInput -instruction $consolidationInstruction -apiKey $apiKey -openAIEndpoint $openAIEndpoint -ModelName $Model
            }
            if ($finalMergedReport) {
                Write-Host "`n--- Final Consolidated Report (Markdown) ---" -ForegroundColor Cyan
                Write-Host $finalMergedReport
                $finalMergedReport | Out-File "SIT_Report.md" -Encoding UTF8
                Write-Output "Report saved to SIT_Report.md"

                # Also preserve a timestamped copy in the per-profile cache so the
                # built-in report viewer can browse historical reports per SIT.
                $reportCacheDir = if ([string]::IsNullOrWhiteSpace($ReportCacheDir)) { Join-Path -Path $profileCacheDir -ChildPath 'reports' } else { $ReportCacheDir }
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
            $snapshotPrivacyMode = if ($UseProtectedSensitiveEvents -and $IncludeSensitiveValues) { 'protected-sensitive-content' } else { 'context-only' }
            Export-RunSnapshot -AnalysisResults $analysisResults -SnapshotDir $RunSnapshotDir -Label $RunLabel -RawDetectionCount $detectionData.Count -EventStoreCount $dlpEvents.Count -AlertStoreCount $dlpAlerts.Count -DlpPolicy $dlpPolicy -ProfileName $activeProfile.Name -AnalysisModelName $AnalysisModel -ReportModelName $Model -AnalysisStartDate $AnalysisStartDate -AnalysisEndDate $AnalysisEndDate -PrivacyMode $snapshotPrivacyMode -DepartmentContext $departmentContext -FinalReportMarkdown $finalMergedReport
        }

} else {
    Write-Output "No matches found"
}

