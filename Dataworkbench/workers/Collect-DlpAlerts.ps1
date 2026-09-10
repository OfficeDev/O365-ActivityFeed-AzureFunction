<#
.SYNOPSIS
Incrementally collects Microsoft Purview DLP alerts and alert events into JSONL stores.
.DESCRIPTION
Uses delegated Microsoft Graph authentication. Detected values are redacted at rest by default.
Use -RetainDetectedValues only after an explicit privacy and secret-handling review.
Use -CaptureSensitiveEvents to write a separate DPAPI-protected SIT evidence store while
keeping the general event store redacted.
#>
[CmdletBinding()]
param(
    [int]$MaxEvents = 50000,
    [int]$LookbackDays = 90,
    [int]$WatermarkBufferHours = 1,
    [switch]$FullPull,
    [switch]$RetainDetectedValues,
    [switch]$CaptureSensitiveEvents,
    [ValidateRange(1, 365)][int]$SensitiveRetentionDays = 30,
    [string]$DataRoot = (Join-Path $PSScriptRoot '..\data')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$DataRoot = [IO.Path]::GetFullPath($DataRoot)
$eventStorePath = Join-Path $DataRoot 'dlp-events-store.jsonl'
$alertStorePath = Join-Path $DataRoot 'dlp-alerts-store.jsonl'
$statePath = Join-Path $DataRoot 'dlp-sync-state.json'
$protectedRoot = Join-Path $DataRoot 'protected'
$protectedEventStorePath = Join-Path $protectedRoot 'sit-sensitive-events.jsonl'
New-Item -ItemType Directory -Path $DataRoot -Force | Out-Null

function Read-JsonlMap {
    param([string]$Path)
    $map = [ordered]@{}
    if (-not (Test-Path -LiteralPath $Path)) { return $map }
    foreach ($line in [IO.File]::ReadLines($Path)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $item = $line | ConvertFrom-Json -Depth 60 -ErrorAction Stop } catch { continue }
        $itemId = Get-ObjectMemberValue -InputObject $item -Name 'id'
        if ($itemId) { $map[[string]$itemId] = $item }
    }
    return $map
}

function Write-JsonlMapAtomic {
    param([string]$Path, [System.Collections.Specialized.OrderedDictionary]$Map)
    $temp = "$Path.$PID.tmp"
    $writer = [IO.StreamWriter]::new($temp, $false, [Text.UTF8Encoding]::new($false))
    try { foreach ($key in $Map.Keys) { $writer.WriteLine(($Map[$key] | ConvertTo-Json -Depth 60 -Compress)) } } finally { $writer.Dispose() }
    Move-Item -LiteralPath $temp -Destination $Path -Force
}

function Add-JsonlItems {
    param([string]$Path, [object[]]$Items)
    if ($Items.Count -eq 0) { return }
    $writer = [IO.StreamWriter]::new($Path, $true, [Text.UTF8Encoding]::new($false))
    try { foreach ($item in $Items) { $writer.WriteLine(($item | ConvertTo-Json -Depth 60 -Compress)) } } finally { $writer.Dispose() }
}

function Get-ObjectMemberValue {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Set-ObjectMemberValue {
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][object]$Value
    )
    if ($InputObject -is [Collections.IDictionary]) {
        $InputObject[$Name] = $Value
        return
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { $property.Value = $Value }
    else { $InputObject | Add-Member -NotePropertyName $Name -NotePropertyValue $Value }
}

function Protect-SensitiveEvent {
    param([Parameter(Mandatory)][object]$Event)
    $eventId = Get-ObjectMemberValue -InputObject $Event -Name 'id'
    if (-not $eventId) { return $null }
    $json = $Event | ConvertTo-Json -Depth 60 -Compress
    $plainBytes = [Text.Encoding]::UTF8.GetBytes($json)
    $entropy = [Text.Encoding]::UTF8.GetBytes('DlpResponseStudio.SitOptimize.v1')
    $cipherBytes = [Security.Cryptography.ProtectedData]::Protect($plainBytes, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [pscustomobject]@{
        schemaVersion = 1
        id = [string]$eventId
        protection = 'DPAPI-CurrentUser'
        capturedUtc = (Get-Date).ToUniversalTime().ToString('o')
        observedUtc = [string](Get-ObjectMemberValue -InputObject $Event -Name 'createdDateTime')
        ciphertext = [Convert]::ToBase64String($cipherBytes)
    }
}

function Set-ProtectedStoreAcl {
    param([Parameter(Mandatory)][string]$Path)
    if (-not $IsWindows -or -not (Test-Path -LiteralPath $Path)) { return }
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleAll($rule) }
        $isDirectory = (Get-Item -LiteralPath $Path).PSIsContainer
        $inheritance = if ($isDirectory) { [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit } else { [Security.AccessControl.InheritanceFlags]::None }
        $propagation = [Security.AccessControl.PropagationFlags]::None
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', $inheritance, $propagation, 'Allow'))
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new('NT AUTHORITY\SYSTEM', 'FullControl', $inheritance, $propagation, 'Allow'))
        Set-Acl -LiteralPath $Path -AclObject $acl
    } catch { Write-Warning "Unable to restrict the protected SIT store ACL: $($_.Exception.Message)" }
}

function Get-GraphPages {
    param([string]$Uri)
    $items = [Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -Headers $script:GraphHeaders
        foreach ($item in @(Get-ObjectMemberValue -InputObject $response -Name 'value')) {
            if ($null -ne $item) { $items.Add($item) }
        }
        $next = [string](Get-ObjectMemberValue -InputObject $response -Name '@odata.nextLink')
    }
    return $items.ToArray()
}

function Protect-EventAtRest {
    param([object]$Event)
    if ($RetainDetectedValues) { return $Event }
    $audit = Get-ObjectMemberValue -InputObject $Event -Name 'auditRecord'
    if ($null -eq $audit) { return $Event }
    if ($audit -is [string]) { try { $audit = $audit | ConvertFrom-Json -Depth 60 } catch { return $Event } }
    foreach ($policy in @(Get-ObjectMemberValue -InputObject $audit -Name 'PolicyDetails')) {
        if ($null -eq $policy) { continue }
        foreach ($rule in @(Get-ObjectMemberValue -InputObject $policy -Name 'Rules')) {
            if ($null -eq $rule) { continue }
            $conditions = Get-ObjectMemberValue -InputObject $rule -Name 'ConditionsMatched'
            foreach ($sensitive in @(Get-ObjectMemberValue -InputObject $conditions -Name 'SensitiveInformation')) {
                if ($null -eq $sensitive) { continue }
                $detections = Get-ObjectMemberValue -InputObject $sensitive -Name 'SensitiveInformationDetections'
                if ($null -ne $detections -and $null -ne (Get-ObjectMemberValue -InputObject $detections -Name 'DetectedValues')) {
                    Set-ObjectMemberValue -InputObject $detections -Name 'DetectedValues' -Value @([pscustomobject]@{ value = '[REDACTED]' })
                }
            }
        }
    }
    Set-ObjectMemberValue -InputObject $Event -Name 'auditRecord' -Value $audit
    return $Event
}

if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) { throw 'Microsoft.Graph.Authentication is required.' }
Connect-MgGraph -Scopes 'SecurityAlert.Read.All','SecurityEvents.Read.All','CustomTags.Read.All' -NoWelcome
$graphContext = Get-MgContext
$script:GraphHeaders = @{ ConsistencyLevel = 'eventual' }

$alerts = if ($FullPull) { [ordered]@{} } else { Read-JsonlMap $alertStorePath }
$existingEvents = if ($FullPull) { [ordered]@{} } else { Read-JsonlMap $eventStorePath }
$protectedEvents = [ordered]@{}
if ($CaptureSensitiveEvents -and -not $FullPull) {
    $retentionCutoff = (Get-Date).ToUniversalTime().AddDays(-$SensitiveRetentionDays)
    foreach ($entry in (Read-JsonlMap $protectedEventStorePath).GetEnumerator()) {
        $capturedUtc = Get-ObjectMemberValue -InputObject $entry.Value -Name 'capturedUtc'
        if ($capturedUtc) { try { if (([datetime]$capturedUtc).ToUniversalTime() -lt $retentionCutoff) { continue } } catch { continue } }
        $protectedEvents[$entry.Key] = $entry.Value
    }
}
$state = if (-not $FullPull -and (Test-Path $statePath)) { try { Get-Content $statePath -Raw | ConvertFrom-Json } catch { $null } } else { $null }
$stateWatermark = Get-ObjectMemberValue -InputObject $state -Name 'lastAlertWatermark'
$stateAlertCount = Get-ObjectMemberValue -InputObject $state -Name 'alertCount'
$hasUsableWatermark = -not $FullPull -and $stateWatermark -and $stateAlertCount -and [int]$stateAlertCount -gt 0
$initialCutoff = (Get-Date).ToUniversalTime().AddDays(-[Math]::Abs($LookbackDays))
$filterParts = [Collections.Generic.List[string]]::new()
$filterParts.Add("detectionSource eq 'microsoftDataLossPrevention'")
if ($hasUsableWatermark) {
    $since = ([datetime]$stateWatermark).AddHours(-[Math]::Abs($WatermarkBufferHours))
    $filterParts.Add("lastUpdateDateTime ge $($since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
}
$filter = $filterParts -join ' and '
$candidates = @(Get-GraphPages "https://graph.microsoft.com/beta/security/alerts_v2?`$filter=$filter")
$changed = @(
    if ($hasUsableWatermark) {
        $candidates
    } else {
        $candidates | Where-Object {
            $timestamp = Get-ObjectMemberValue -InputObject $_ -Name 'lastUpdateDateTime'
            if (-not $timestamp) { $timestamp = Get-ObjectMemberValue -InputObject $_ -Name 'lastActivityDateTime' }
            if (-not $timestamp) { return $false }
            try { ([datetime]$timestamp).ToUniversalTime() -ge $initialCutoff } catch { $false }
        }
    }
)
if (-not $hasUsableWatermark) {
    Write-Host "Initial DLP alert pull: retained $($changed.Count) of $($candidates.Count) alert(s) within the last $LookbackDays day(s)."
}
Write-Host "Retrieved $($changed.Count) changed DLP alert(s)."
foreach ($alert in $changed) {
    $alertId = Get-ObjectMemberValue -InputObject $alert -Name 'id'
    if ($alertId) { $alerts[[string]$alertId] = $alert }
}

$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($key in $existingEvents.Keys) { [void]$seen.Add([string]$key) }
$newEvents = [Collections.Generic.List[object]]::new()
foreach ($alert in $changed) {
    if ($newEvents.Count -ge $MaxEvents) { break }
    $detectorId = Get-ObjectMemberValue -InputObject $alert -Name 'detectorId'
    $firstActivity = Get-ObjectMemberValue -InputObject $alert -Name 'firstActivityDateTime'
    $lastActivity = Get-ObjectMemberValue -InputObject $alert -Name 'lastActivityDateTime'
    if (-not $detectorId -or -not $firstActivity -or -not $lastActivity) {
        Write-Warning "Skipping an alert without detectorId or activity timestamps."
        continue
    }
    $start = ([datetime]$firstActivity).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $end = ([datetime]$lastActivity).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $eventFilter = "alertCorrelationId eq '$detectorId' and startDateTime ge $start and endDateTime le $end"
    try {
        $alertEvents = @(Get-GraphPages "https://graph.microsoft.com/beta/security/dlpAlertEvent?`$filter=$eventFilter")
    } catch {
        Write-Warning "DLP alert-event query failed for detectorId=$detectorId`: $($_.Exception.Message)"
        continue
    }
    foreach ($event in $alertEvents) {
        if ($newEvents.Count -ge $MaxEvents) { break }
        $eventId = Get-ObjectMemberValue -InputObject $event -Name 'id'
        if ($eventId -and $seen.Add([string]$eventId)) {
            Set-ObjectMemberValue -InputObject $event -Name '_dlpResponseStudio' -Value ([pscustomobject]@{
                alertId = [string]$alertId
                incidentId = [string](Get-ObjectMemberValue -InputObject $alert -Name 'incidentId')
                correlatedUtc = (Get-Date).ToUniversalTime().ToString('o')
                correlation = 'detector-and-alert-activity-window-v2'
            })
            if ($CaptureSensitiveEvents) {
                $protected = Protect-SensitiveEvent -Event $event
                if ($protected) { $protectedEvents[[string]$eventId] = $protected }
            }
            $newEvents.Add((Protect-EventAtRest $event))
        }
    }
}

Write-JsonlMapAtomic -Path $alertStorePath -Map $alerts
if ($FullPull) {
    $rebuilt = [ordered]@{}
    foreach ($event in $newEvents) {
        $eventId = Get-ObjectMemberValue -InputObject $event -Name 'id'
        if ($eventId) { $rebuilt[[string]$eventId] = $event }
    }
    Write-JsonlMapAtomic -Path $eventStorePath -Map $rebuilt
} else { Add-JsonlItems -Path $eventStorePath -Items $newEvents.ToArray() }
if ($CaptureSensitiveEvents) {
    New-Item -ItemType Directory -Path $protectedRoot -Force | Out-Null
    Write-JsonlMapAtomic -Path $protectedEventStorePath -Map $protectedEvents
    Set-ProtectedStoreAcl -Path $protectedRoot
    Set-ProtectedStoreAcl -Path $protectedEventStorePath
}

$watermark = ($alerts.Values | ForEach-Object {
    Get-ObjectMemberValue -InputObject $_ -Name 'lastUpdateDateTime'
} | Where-Object { $_ } | Sort-Object | Select-Object -Last 1)
@{ schemaVersion = 1; updatedUtc = (Get-Date).ToUniversalTime().ToString('o'); lastAlertWatermark = $watermark; alertCount = $alerts.Count; candidateAlertCount = $candidates.Count; changedAlertCount = $changed.Count; newEventCount = $newEvents.Count; eventCount = $existingEvents.Count + $newEvents.Count; tenantId = (Get-ObjectMemberValue -InputObject $graphContext -Name 'TenantId'); account = (Get-ObjectMemberValue -InputObject $graphContext -Name 'Account'); detectedValuesRetained = [bool]$RetainDetectedValues; protectedSensitiveCapture = [bool]$CaptureSensitiveEvents; protectedSensitiveEventCount = $protectedEvents.Count; sensitiveRetentionDays = if ($CaptureSensitiveEvents) { $SensitiveRetentionDays } else { $null } } |
    ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding utf8
Write-Host "DLP sync complete: $($alerts.Count) alert(s), $($newEvents.Count) new event(s)."
if ($CaptureSensitiveEvents) { Write-Host "Protected SIT evidence: $($protectedEvents.Count) DPAPI-encrypted event(s), retention=$SensitiveRetentionDays day(s)." }
