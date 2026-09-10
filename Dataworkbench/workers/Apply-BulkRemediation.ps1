<#
.SYNOPSIS
Applies an explicitly confirmed DLP remediation plan.
.NOTES
This worker is never invoked by plan or dry-run operations. The Node service gates invocation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DetectionDataPath,
    [Parameter(Mandatory)][string]$OutputPath,
    [int]$MaxIncidents = 50,
    [int]$MaxUsers = 200,
    [switch]$UpdateIncidents,
    [switch]$SendEmail,
    [switch]$SendTeams,
    [ValidateLength(1, 4000)][string]$TeamsMessage = 'Please review the data protection activity associated with your account. Sensitive values are not included in this notification.',
    [switch]$ResolveLowRisk
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $DetectionDataPath)) { throw 'Detection plan not found.' }
$detections = @(Get-Content -LiteralPath $DetectionDataPath -Raw | ConvertFrom-Json -Depth 40)
$incidentIds = @($detections | ForEach-Object { $_.incidentId } | Where-Object { $_ } | Select-Object -Unique | Select-Object -First $MaxIncidents)
$users = @($detections | ForEach-Object { $_.user } | Where-Object { $_ } | Select-Object -Unique | Select-Object -First $MaxUsers)
$scopes = [Collections.Generic.List[string]]::new()
if ($UpdateIncidents) { $scopes.Add('SecurityIncident.ReadWrite.All') }
if ($SendEmail) { $scopes.Add('Mail.Send') }
if ($SendTeams) { foreach ($scope in 'Chat.Create','ChatMessage.Send','User.ReadBasic.All') { $scopes.Add($scope) } }
if ($scopes.Count -eq 0) { throw 'No live actions were selected.' }
Connect-MgGraph -Scopes $scopes.ToArray() -NoWelcome
$actions = [Collections.Generic.List[object]]::new()

function Get-SitTriageComment {
    param([object[]]$IncidentDetections)

    $triage = @($IncidentDetections | ForEach-Object { $_.sitTriage } | Where-Object { $_ -and -not [string]::IsNullOrWhiteSpace([string]$_.securityComment) } | Select-Object -First 1)
    if ($triage.Count -eq 0) { return $null }
    $triage = $triage[0]
    $lines = @(
        'Detection Assurance AI triage — human review required'
        "Priority: $([string]$triage.priority)"
        "Disposition: $([string]$triage.disposition)"
        "Credential validity: $([string]$triage.validityStatus)"
        "Security assessment: $([string]$triage.securityComment)"
        "Source: profile=$([string]$triage.profileId); assessment=$([string]$triage.assessmentLabel); generated=$([string]$triage.generatedAt)"
        'No detected values or sensitive artifacts are included in this comment.'
    )
    $comment = $lines -join "`n"
    if ($comment.Length -gt 3500) { $comment = $comment.Substring(0, 3500) }
    return $comment
}

if ($UpdateIncidents) {
    foreach ($incidentId in $incidentIds) {
        $incidentDetections = @($detections | Where-Object { [string]$_.incidentId -eq [string]$incidentId })
        $triageComment = Get-SitTriageComment -IncidentDetections $incidentDetections
        try {
            $incident = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/incidents/$incidentId"
            $tags = @($incident.customTags)
            foreach ($tag in 'DLP-Response-Studio','Bulk-Reviewed') { if ($tags -notcontains $tag) { $tags += $tag } }
            $body = @{ customTags = $tags; status = 'inProgress' }
            if ($ResolveLowRisk -and [string]$incident.severity -eq 'low') {
                $body.status = 'resolved'; $body.classification = 'falsePositive'; $body.resolvingComment = 'Resolved by explicitly approved DLP bulk remediation.'
            }
            Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/security/incidents/$incidentId" -Body ($body | ConvertTo-Json -Depth 10) -ContentType 'application/json' | Out-Null
            $actions.Add([pscustomobject]@{ type = 'incidentPatch'; target = [string]$incidentId; status = 'done' })
        } catch { $actions.Add([pscustomobject]@{ type = 'incidentPatch'; target = [string]$incidentId; status = 'error'; detail = $_.Exception.Message }) }
        if ($triageComment) {
            try {
                $commentRequest = @{ '@odata.type' = 'microsoft.graph.security.alertComment'; comment = $triageComment }
                Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/security/incidents/$incidentId/comments" -Body ($commentRequest | ConvertTo-Json) -ContentType 'application/json' | Out-Null
                $actions.Add([pscustomobject]@{ type = 'incidentComment'; target = [string]$incidentId; status = 'done' })
            } catch { $actions.Add([pscustomobject]@{ type = 'incidentComment'; target = [string]$incidentId; status = 'error'; detail = $_.Exception.Message }) }
        } else {
            $actions.Add([pscustomobject]@{ type = 'incidentComment'; target = [string]$incidentId; status = 'skipped'; detail = 'No completed Detection Assurance security comment is available for this incident.' })
        }
    }
}

if ($SendEmail) {
    foreach ($upn in $users) {
        $count = @($detections | Where-Object { $_.user -eq $upn }).Count
        $message = @{ message = @{ subject = 'Data protection alert — review requested'; body = @{ contentType = 'HTML'; content = "<p>Hello,</p><p>The data protection team identified <strong>$count</strong> DLP detection(s) associated with your recent activity.</p><p>Sensitive values have been redacted. Please review the affected content and follow your organisation's approved handling process.</p>" }; toRecipients = @(@{ emailAddress = @{ address = $upn } }) }; saveToSentItems = $true }
        try {
            Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/me/sendMail' -Body ($message | ConvertTo-Json -Depth 20) -ContentType 'application/json' | Out-Null
            $actions.Add([pscustomobject]@{ type = 'email'; target = [string]$upn; status = 'done' })
        } catch { $actions.Add([pscustomobject]@{ type = 'email'; target = [string]$upn; status = 'error'; detail = $_.Exception.Message }) }
    }
}

if ($SendTeams) {
    $me = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id'
    $safeMessage = '<p>{0}</p>' -f (([Net.WebUtility]::HtmlEncode($TeamsMessage)) -replace '(\r\n|\n|\r)', '<br>')
    foreach ($upn in $users) {
        if ($upn -notmatch '^[^\s@]+@[^\s@]+\.[^\s@]+$') {
            $actions.Add([pscustomobject]@{ type = 'teamsNotification'; target = [string]$upn; status = 'error'; detail = 'Recipient must be a Microsoft Entra user principal name.' })
            continue
        }
        try {
            $encodedTarget = [Uri]::EscapeDataString([string]$upn)
            $recipient = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$encodedTarget`?`$select=id,userPrincipalName"
            $chatRequest = @{
                chatType = 'oneOnOne'
                members = @(
                    @{ '@odata.type' = '#microsoft.graph.aadUserConversationMember'; roles = @('owner'); 'user@odata.bind' = "https://graph.microsoft.com/v1.0/users('$($me.id)')" }
                    @{ '@odata.type' = '#microsoft.graph.aadUserConversationMember'; roles = @('owner'); 'user@odata.bind' = "https://graph.microsoft.com/v1.0/users('$($recipient.id)')" }
                )
            }
            $chat = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/chats' -Body ($chatRequest | ConvertTo-Json -Depth 20) -ContentType 'application/json'
            $messageRequest = @{ body = @{ contentType = 'html'; content = $safeMessage } }
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/chats/$($chat.id)/messages" -Body ($messageRequest | ConvertTo-Json -Depth 10) -ContentType 'application/json' | Out-Null
            $actions.Add([pscustomobject]@{ type = 'teamsNotification'; target = [string]$upn; status = 'done' })
        } catch { $actions.Add([pscustomobject]@{ type = 'teamsNotification'; target = [string]$upn; status = 'error'; detail = $_.Exception.Message }) }
    }
}

$result = [ordered]@{ generatedUtc = (Get-Date).ToUniversalTime().ToString('o'); incidents = $incidentIds.Count; users = $users.Count; actions = $actions; succeeded = @($actions | Where-Object status -eq done).Count; failed = @($actions | Where-Object status -eq error).Count }
New-Item -ItemType Directory -Path (Split-Path $OutputPath -Parent) -Force | Out-Null
$result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutputPath -Encoding utf8
if ($result.failed -gt 0) { exit 2 }
