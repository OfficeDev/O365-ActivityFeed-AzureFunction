<#
.SYNOPSIS
Executes safe declarative DLP response flows. Dry-run is the default.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputPath,
    [Parameter(Mandatory)][string]$OutputPath,
    [string]$FlowsPath = (Join-Path $PSScriptRoot '..\config\response-flows.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $FlowsPath)) { $FlowsPath = Join-Path $PSScriptRoot '..\config\response-flows.default.json' }
$request = Get-Content $InputPath -Raw | ConvertFrom-Json -Depth 30
$doc = Get-Content $FlowsPath -Raw | ConvertFrom-Json -Depth 30
$flow = @($doc.flows | Where-Object id -eq $request.flowId | Select-Object -First 1)
if ($flow.Count -eq 0 -or $flow[0].enabled -eq $false) { throw 'Flow not found or disabled.' }
$flow = $flow[0]
$dryRun = $request.mode -ne 'apply'
$actions = [Collections.Generic.List[object]]::new()

function Get-DelimitedTargets {
    param([string]$Value)
    return @($Value -split '[,;\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique -First 200)
}

function ConvertTo-SafeTeamsHtml {
    param([string]$Text)
    $encoded = [Net.WebUtility]::HtmlEncode($Text)
    return '<p>{0}</p>' -f ($encoded -replace '(\r\n|\n|\r)', '<br>')
}

function Get-SitTriageComment {
    param([string]$IncidentId)
    if (-not $request.PSObject.Properties['sitTriage']) { return $null }
    $property = $request.sitTriage.PSObject.Properties[$IncidentId]
    if (-not $property -or -not $property.Value -or [string]::IsNullOrWhiteSpace([string]$property.Value.securityComment)) { return $null }
    $triage = $property.Value
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in @(
        'Detection Assurance AI triage — human review required'
        "Priority: $([string]$triage.priority)"
        "Disposition: $([string]$triage.disposition)"
        "Credential validity: $([string]$triage.validityStatus)"
        "Security assessment: $([string]$triage.securityComment)"
    )) { $lines.Add($line) }
    $patterns = @($triage.falsePositivePatterns)
    if ($patterns.Count -gt 0) {
        $lines.Add('False-positive patterns supporting Purview remediation:')
        foreach ($pattern in @($patterns | Select-Object -First 5)) {
            $lines.Add(("- {0} [{1}; {2}; {3}; occurrences={4}]" -f [string]$pattern.patternFamily, [string]$pattern.triggeringSitRule, [string]$pattern.workload, [string]$pattern.location, [int]$pattern.occurrenceCount))
            $lines.Add(("  Why: {0}" -f [string]$pattern.reasonFalsePositive))
            $lines.Add(("  Purview change: {0}" -f [string]$pattern.suppressionStrategy))
            $lines.Add(("  Retain detection when: {0}" -f [string]$pattern.falseNegativeGuardrail))
        }
    }
    $lines.Add("Source: profile=$([string]$triage.profileId); assessment=$([string]$triage.assessmentLabel); generated=$([string]$triage.generatedAt)")
    $lines.Add('No detected values or sensitive artifacts are included in this comment.')
    $comment = $lines -join "`n"
    if ($comment.Length -gt 3500) { $comment = $comment.Substring(0, 3500) }
    return [pscustomobject]@{ Text = $comment; Priority = ([string]$triage.priority).ToUpperInvariant() }
}

if (-not $dryRun) {
    $scopes = @($flow.requiredScopes | Where-Object { $_ })
    if ($scopes.Count) { Connect-MgGraph -Scopes $scopes -NoWelcome }
}

foreach ($action in @($flow.actions)) {
    if ($action.type -eq 'incidentPatch') {
        foreach ($incidentId in @($request.incidentIds)) {
            $includeTriage = $action.PSObject.Properties['includeSitTriageComment'] -and $action.includeSitTriageComment -eq $true
            $triageComment = if ($includeTriage) { Get-SitTriageComment -IncidentId ([string]$incidentId) } else { $null }
            $triageTags = @(if ($triageComment) { 'SIT-AI-Triaged', "SIT-Risk-$($triageComment.Priority.Substring(0,1).ToUpperInvariant() + $triageComment.Priority.Substring(1).ToLowerInvariant())" })
            if ($dryRun) {
                $patchDetail = if ($triageTags.Count) { "Would set status=$($action.status) and add configured tags plus: $($triageTags -join ', ')." } else { "Would set status=$($action.status) and add configured tags." }
                $actions.Add([pscustomobject]@{ type = 'incidentPatch'; target = $incidentId; status = 'planned'; detail = $patchDetail })
                if ($triageComment) { $actions.Add([pscustomobject]@{ type = 'incidentComment'; target = $incidentId; status = 'planned'; detail = $triageComment.Text }) }
                elseif ($includeTriage) { $actions.Add([pscustomobject]@{ type = 'incidentComment'; target = $incidentId; status = 'skipped'; detail = 'No completed Detection Assurance triage is available for this incident.' }) }
                continue
            }
            try {
                $incident = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/incidents/$incidentId"
                $tags = @($incident.customTags)
                foreach ($tag in @($action.addTags) + $triageTags) { if ($tags -notcontains $tag) { $tags += $tag } }
                $patch = @{ customTags = $tags }
                if ($action.status) { $patch.status = [string]$action.status }
                Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/security/incidents/$incidentId" -Body ($patch | ConvertTo-Json) -ContentType 'application/json' | Out-Null
                $actions.Add([pscustomobject]@{ type = 'incidentPatch'; target = $incidentId; status = 'done' })
            } catch { $actions.Add([pscustomobject]@{ type = 'incidentPatch'; target = $incidentId; status = 'error'; detail = $_.Exception.Message }) }
            if ($triageComment) {
                try {
                    $commentRequest = @{ '@odata.type' = 'microsoft.graph.security.alertComment'; comment = $triageComment.Text }
                    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/security/incidents/$incidentId/comments" -Body ($commentRequest | ConvertTo-Json) -ContentType 'application/json' | Out-Null
                    $actions.Add([pscustomobject]@{ type = 'incidentComment'; target = $incidentId; status = 'done' })
                } catch { $actions.Add([pscustomobject]@{ type = 'incidentComment'; target = $incidentId; status = 'error'; detail = $_.Exception.Message }) }
            } elseif ($includeTriage) { $actions.Add([pscustomobject]@{ type = 'incidentComment'; target = $incidentId; status = 'skipped'; detail = 'No completed Detection Assurance triage is available for this incident.' }) }
        }
    } elseif ($action.type -eq 'emailAffectedUsers') {
        $targets = @()
        if ($request.parameters.PSObject.Properties['impactedUsers']) { $targets = @([string]$request.parameters.impactedUsers -split '[,;\r\n]+' | Where-Object { $_ }) }
        foreach ($target in $targets) {
            if ($dryRun) { $actions.Add([pscustomobject]@{ type = 'email'; target = $target; status = 'planned' }); continue }
            $subject = if ($request.parameters.subject) { [string]$request.parameters.subject } else { 'Data protection alert — review requested' }
            $message = @{ message = @{ subject = $subject; body = @{ contentType = 'HTML'; content = '<p>Please review the DLP activity associated with your account. Sensitive values are redacted.</p>' }; toRecipients = @(@{ emailAddress = @{ address = $target } }) }; saveToSentItems = $true }
            try { Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/me/sendMail' -Body ($message | ConvertTo-Json -Depth 20) -ContentType 'application/json' | Out-Null; $actions.Add([pscustomobject]@{ type = 'email'; target = $target; status = 'done' }) }
            catch { $actions.Add([pscustomobject]@{ type = 'email'; target = $target; status = 'error'; detail = $_.Exception.Message }) }
        }
        if ($targets.Count -eq 0) { $actions.Add([pscustomobject]@{ type = 'email'; target = ''; status = if ($dryRun) { 'planned' } else { 'skipped' }; detail = 'No impactedUsers parameter supplied.' }) }
    } elseif ($action.type -eq 'teamsNotifyAffectedUsers') {
        $targetValue = ''
        if ($request.parameters.PSObject.Properties['teamsRecipients'] -and -not [string]::IsNullOrWhiteSpace([string]$request.parameters.teamsRecipients)) {
            $targetValue = [string]$request.parameters.teamsRecipients
        } elseif ($request.parameters.PSObject.Properties['impactedUsers']) {
            $targetValue = [string]$request.parameters.impactedUsers
        }
        $targets = @(Get-DelimitedTargets -Value $targetValue)
        $messageText = if ($request.parameters.PSObject.Properties['teamsMessage']) { [string]$request.parameters.teamsMessage } else { 'Please review the data protection activity associated with your account. Sensitive values are not included in this notification.' }
        if ([string]::IsNullOrWhiteSpace($messageText) -or $messageText.Length -gt 4000) {
            $actions.Add([pscustomobject]@{ type = 'teamsNotification'; target = ''; status = 'error'; detail = 'The Teams message must contain 1 to 4,000 characters.' })
            continue
        }
        if ($targets.Count -eq 0) {
            $actions.Add([pscustomobject]@{ type = 'teamsNotification'; target = ''; status = if ($dryRun) { 'planned' } else { 'skipped' }; detail = 'No Teams recipients or impacted users were supplied.' })
            continue
        }
        $validTargets = [Collections.Generic.List[string]]::new()
        foreach ($target in $targets) {
            if ($target -match '^[^\s@]+@[^\s@]+\.[^\s@]+$') { $validTargets.Add($target) }
            else { $actions.Add([pscustomobject]@{ type = 'teamsNotification'; target = $target; status = 'error'; detail = 'Recipient must be a Microsoft Entra user principal name.' }) }
        }
        if ($validTargets.Count -eq 0) { continue }
        if ($dryRun) {
            foreach ($target in $validTargets) { $actions.Add([pscustomobject]@{ type = 'teamsNotification'; target = $target; status = 'planned'; detail = 'Would create or reuse a one-to-one Teams chat and send the reviewed message.' }) }
            continue
        }

        $me = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id'
        $safeHtml = ConvertTo-SafeTeamsHtml -Text $messageText
        foreach ($target in $validTargets) {
            try {
                $encodedTarget = [Uri]::EscapeDataString($target)
                $recipient = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$encodedTarget`?`$select=id,userPrincipalName"
                $chatRequest = @{
                    chatType = 'oneOnOne'
                    members = @(
                        @{ '@odata.type' = '#microsoft.graph.aadUserConversationMember'; roles = @('owner'); 'user@odata.bind' = "https://graph.microsoft.com/v1.0/users('$($me.id)')" }
                        @{ '@odata.type' = '#microsoft.graph.aadUserConversationMember'; roles = @('owner'); 'user@odata.bind' = "https://graph.microsoft.com/v1.0/users('$($recipient.id)')" }
                    )
                }
                $chat = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/chats' -Body ($chatRequest | ConvertTo-Json -Depth 20) -ContentType 'application/json'
                $messageRequest = @{ body = @{ contentType = 'html'; content = $safeHtml } }
                Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/chats/$($chat.id)/messages" -Body ($messageRequest | ConvertTo-Json -Depth 10) -ContentType 'application/json' | Out-Null
                $actions.Add([pscustomobject]@{ type = 'teamsNotification'; target = $target; status = 'done' })
            } catch {
                $actions.Add([pscustomobject]@{ type = 'teamsNotification'; target = $target; status = 'error'; detail = $_.Exception.Message })
            }
        }
    } else { $actions.Add([pscustomobject]@{ type = [string]$action.type; target = ''; status = 'skipped'; detail = 'Unsupported declarative action type.' }) }
}

$result = [ordered]@{ generatedUtc = (Get-Date).ToUniversalTime().ToString('o'); flowId = [string]$flow.id; mode = if ($dryRun) { 'dryrun' } else { 'apply' }; actions = $actions }
New-Item -ItemType Directory -Path (Split-Path $OutputPath -Parent) -Force | Out-Null
$result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutputPath -Encoding utf8
if (@($actions | Where-Object status -eq error).Count) { exit 2 }
