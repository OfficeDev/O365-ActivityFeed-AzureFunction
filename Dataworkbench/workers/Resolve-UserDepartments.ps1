<#
.SYNOPSIS
Resolves Microsoft Entra user departments through Microsoft Graph and updates the local directory cache.
.DESCRIPTION
Uses the operator's delegated User.Read.All permission. The operation is read-only in Graph and writes only
to the local JSON cache supplied by OutputPath.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$UpnsPath,
    [Parameter(Mandatory)][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $UpnsPath)) { throw "UPN input not found: $UpnsPath" }
$upns = @(Get-Content -LiteralPath $UpnsPath -Raw | ConvertFrom-Json | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
if ($upns.Count -eq 0) { throw 'No UPNs supplied.' }

Write-Output "[DepartmentEnrichment] Connecting to Microsoft Graph for $($upns.Count) user(s)."
if (-not (Get-MgContext)) {
    Connect-MgGraph -Scopes 'User.Read.All' -NoWelcome
}

$directory = @{}
if (Test-Path -LiteralPath $OutputPath) {
    try {
        $existing = Get-Content -LiteralPath $OutputPath -Raw | ConvertFrom-Json
        foreach ($property in $existing.PSObject.Properties) {
            $directory[$property.Name.ToLowerInvariant()] = @{
                department  = $property.Value.department
                displayName = $property.Value.displayName
                mail        = $property.Value.mail
                resolvedUtc = $property.Value.resolvedUtc
            }
        }
    } catch {
        Write-Output '[DepartmentEnrichment] WARNING: Existing cache could not be parsed; rebuilding it.'
    }
}

$resolved = 0
$failed = 0
foreach ($upn in $upns) {
    $key = $upn.Trim().ToLowerInvariant()
    try {
        $encodedUpn = [Uri]::EscapeDataString($key)
        $user = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$encodedUpn`?`$select=displayName,department,mail" -OutputType PSObject
        $directory[$key] = @{
            department  = if ($user.department) { [string]$user.department } else { $null }
            displayName = if ($user.displayName) { [string]$user.displayName } else { $null }
            mail        = if ($user.mail) { [string]$user.mail } else { $null }
            resolvedUtc = (Get-Date).ToUniversalTime().ToString('o')
        }
        $resolved++
    } catch {
        if (-not $directory.ContainsKey($key)) {
            $directory[$key] = @{ department = $null; displayName = $null; mail = $null; resolvedUtc = (Get-Date).ToUniversalTime().ToString('o') }
        }
        $failed++
        Write-Output ('[DepartmentEnrichment] WARNING - lookup failed for {0} - {1}' -f $key, $_.Exception.Message)
    }
}

$output = [ordered]@{}
foreach ($key in ($directory.Keys | Sort-Object)) { $output[$key] = $directory[$key] }
New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null
$output | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding utf8
Write-Output "[DepartmentEnrichment] Resolved $resolved; failed $failed; cache contains $($output.Count) user(s)."
