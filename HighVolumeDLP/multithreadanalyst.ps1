<#
USAGE / SETUP GUIDE

Prerequisites:
- PowerShell 7+ (recommended), Windows PowerShell 5.1 not supported.
- Module: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
- Permissions: App/user must have Mail.ReadWrite(+Shared) scope for target mailbox.
- Set Azure OpenAI key: $env:AZURE_OPENAI_API_KEY = "<your-key>"
- Outbound network access to Azure OpenAI endpoint.

Parameters:
 -DlpMailbox <string>          DLP reporting mailbox (Graph user).
 -MaxMatchesThreshold <int>    Pagination early-stop threshold for matched items.
 -OpenAIEndpoint <string>      Azure OpenAI chat completions endpoint.
 -SkipDelete                   Do NOT delete analyzed mailbox messages.
 -Help                         Show usage text and exit.

Examples:
PS> $env:AZURE_OPENAI_API_KEY = '****'
PS> .\investigatecreds.ps1 -DlpMailbox 'dlpmbx01@contoso.onmicrosoft.com' -MaxMatchesThreshold 10000
PS> .\investigatecreds.ps1 -SkipDelete
PS> .\investigatecreds.ps1 -Help

Behavior:
- If no API key present, AI analysis is skipped (collection still runs).
- Use -SkipDelete to retain source messages for reprocessing.
- Output files: dlp_items_*.log, dlp_firstpass_*.csv, dlp_triage_*.md
#>
param(
    [string]$DlpMailbox = "",
    [int]$MaxMatchesThreshold = 1000,
    [string]$OpenAIEndpoint = "",
    [switch]$SkipDelete,
    [switch]$sentinellogic,
    [switch]$Help
)

function Show-Usage {
@'
investigatecreds.ps1 usage:
Parameters:
 -DlpMailbox <string>
 -MaxMatchesThreshold <int>
 -OpenAIEndpoint <string>
 -SkipDelete
 -Help

Setup:
 1. Install-Module Microsoft.Graph -Scope CurrentUser
 2. Connect-MgGraph -Scopes "Mail.ReadWrite","Mail.ReadWrite.Shared","email"
 3. $env:AZURE_OPENAI_API_KEY = "<key>"
 4. Run script with desired parameters.

If API key missing -> AI analysis skipped.
'@
}

if ($Help) { Show-Usage; return }

# Initialize variables
$data = @()
$resource = "https://graph.microsoft.com"
$dlpreportmbx = $DlpMailbox
$MaxMatchesThreshold = $MaxMatchesThreshold # Stop pagination if exceeded

# Azure OpenAI configuration (prefer: $env:AZURE_OPENAI_API_KEY)
$openAIEndpoint = $OpenAIEndpoint

#$env:AZURE_OPENAI_API_KEY = "REPLACE-WITH-YOUR-KEY"
# Prefer environment variable over hardcoded API key
if ($env:AZURE_OPENAI_API_KEY) { $apiKey = $env:AZURE_OPENAI_API_KEY }


# Authenticate using Managed Identity and get access token for Graph API
if (-not ($token)) {
    Connect-MgGraph -Scopes "Mail.ReadWrite","Mail.ReadWrite.Shared","email" -NoWelcome
}
 $mgrequest = Invoke-MgGraphRequest -Method GET  -Uri "https://graph.microsoft.com/v1.0/users/$dlpreportmbx/" -OutputType HttpResponseMessage

$token = $mgRequest.RequestMessage.Headers.Authorization.Parameter

$headerParams = @{
    'Authorization'    = "Bearer $token"
    'ConsistencyLevel' = 'eventual'   # required for $search
}

# New aggregation logic
$pattern = 'Report Id:.*'            # Adjust if you need to stop at newline: 'Location:[^\r\n<]*'
# Capture either a Message-ID in <> or a document/text after "Matched item:", with optional Title on next line
$allMatches = New-Object System.Collections.Generic.List[string]
# New: track retrieved message IDs for deletion after success
$retrievedMessageIds = New-Object System.Collections.Generic.List[string]

# Pagination stop control when too many matches
$ReachedMatchThreshold = $false

# Get all messages (pagination aware)
$graphcall = "https://graph.microsoft.com/v1.0/users/$dlpreportmbx/mailFolders/inbox/messages?$filter=contains(body/content,'Policy Name') and contains(body/content,'Credentials')&$top=1000&select=id,body"
while ($graphcall) {
    $content = Invoke-RestMethod -Headers $headerParams -Uri $graphcall -Method GET
    foreach ($msg in $content.value) {
        # New: remember the message id so we can delete after successful run
        if ($msg.id) { [void]$retrievedMessageIds.Add($msg.id) }
        $body = $msg.body?.content
        if ([string]::IsNullOrEmpty($body)) { continue }
        $matches = [regex]::Matches($body, $pattern)
        foreach ($m in $matches) {
            $val = $m.Value
            $maxLen = 15000
            if ($val.Length -gt $maxLen) {
                $val = $val.Substring(0, $maxLen)
                Write-Output "Match truncated to $maxLen chars"
            }
            $allMatches.Add($val)
            Write-Output "Matches found: " $allMatches.Count
        }
    }

    # New: stop pagination if threshold exceeded
    if (-not $ReachedMatchThreshold -and ($allMatches.Count -gt $MaxMatchesThreshold)) {
        $ReachedMatchThreshold = $true
        Write-Output ("Match threshold reached ({0} > {1}); stopping pagination." -f $allMatches.Count, $MaxMatchesThreshold)
    }

    # New: only fetch @odata.nextLink if threshold not reached
    if (-not $ReachedMatchThreshold) {
        $graphcall = $content.'@odata.nextLink'
    } else {
        $graphcall = $null
    }
}

$time=Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$epochNow = [int][double]((Get-Date -Date $time -UFormat %s))

# DLP analysis instruction for AI model
# Changed to expandable here-string so $time is inserted.
$dlpInstruction = @"
You are Matilda, a very skilled data security analyst. Your task is to assess whether the input data contains actual usable credentials and classify the risk level. You must also detect repeated exposures across items and consolidate them intelligently. Provide full details around the credentials type and decode them in case of a token. If it is high to medium ambiguity classify it as low. 

Input
- The input payload will be delimited by the lines:
  ===BEGIN INPUT===
  ...data...
  ===END INPUT===
  
Task
- The input contains one or more labeled items like: itemN: Matched item: ...
- Analyse each item independently, but use context from other items to detect repeated credential exposures since they indicate test credentials or bulk sharing which is less risky.
- Output a single RFC 4180 CSV with exactly this header:
author,message_id_or_document,risk,credentials,credentialtype,explanation,repeat,Dlptune,Workload,Recipients,subject_document

IMPORTANT JWT EXPIRATION RULE (authoritative - DO NOT IGNORE)
- Current epoch (epochNow) = $epochNow ; current time = $time (UTC).
- A JWT is expired if numeric exp < $epochNow (e.g., if exp=1725888555 and $epochNow>1725888555).
- If exp equals $epochNow then expired=false.
- Example: If exp ISO 2025-09-09T14:29:15Z is earlier than current time $time -> expired=true.
- If server-side metadata line [JWT_META ... expired=TRUE] is present you MUST set expired=true (same for FALSE). Trust server annotation over your own inference.

Population rules
- author: Extract only the UPN/e-mail from nearby "Person sharing item:", "Author:", "Sender:". Else "unknown" or the closest available identifier.
- message_id_or_document: "Matched Item:" Prefer Message-ID in <...> or document/file/URL identifier at Matched item:, NEVER use Report Id: else "unknown".
- risk: One of high, med, low 
- credentials: Only the credential material found (e.g., token, key, username/password). Mask long secrets: show first 4 and last 4 characters. Do not include entire private keys or full tokens.
- credentialtype: Identify the type of credential (e.g., AWS Access Key, Azure SAS Token, JWT, OAuth Bearer Token, Private Key, Password, Connection String). If uncertain, use "unknown".
- explanation: <= 500 chars. Short rationale why you made this decision, common simple creds, test creds other details relevant to your decision. If a JWT is present, Base64URL-decode header and payload and summarize: alg, kid, iss, aud, sub, exp (ISO 8601), scopes/roles/permissions, tenant hints, and why risky. Do not include the signature or print the full token, follow the important JWT expiration rule above.
- repeat: If the same credential material appears in multiple items, downgrade risk to low unless overridden by context. Set the value to true if repeated multiple times, else false.
- Dlptune: Keywords or patterns surrounding the matches that can be used for future DLP tuning. If none, use "none".
- Workload: You will find it after Service: e.g. Exchange, SharePoint, OneDrive, Teams,Endpoint unknown
- Recipients: For Exchange items, extract recipients from "To:", "Cc:", "Bcc:". For Teams Recipient(s): For other workloads, use "unknown".
- subject_document: Look for Title: or Subject: or URL: or file name in the vicinity of the match. If none, use "unknown".


Required tags in explanation
- item=itemN (use the exact provided label, e.g., item3)
- expired=true|false (only if a JWT is analyzed). Follow the important JWT expiration rule above.

Repeat Detection and Risk Downgrade Logic
- If the same credential material (e.g., token, key, password) appears in multiple items, classify the risk as low unless:
- The credential is actively used in a live system (e.g., verified via context or metadata).
- The credential is embedded in a high-sensitivity context (e.g., production secrets, financial data).
- Track credential fingerprints (e.g., token prefixes, masked values) across all items in the input payload.
- If a credential appears more than once, downgrade risk to low unless overridden by context. Ensure that the repeat column is set to true for these cases.
- If a credential appears only once, proceed with standard risk classification.

Detection guidance
- Based on the credential material and the context as well as pattern repeat classify the risk as High, Medium or Low.

Output constraints
- Produce exactly one CSV row per analyzed labeled item. Ensure that you get all the items in the input.
- Return ONLY CSV with a single header row: author,message_id_or_document,risk,credentials,credentialtype,explanation,repeat,dlptune,Workload,Recipients,subject_document
- Quote fields containing commas, quotes, or newlines using double quotes per RFC 4180. Do not forget this for your own comment in the explanation field.
- If required fields are unavailable, use "unknown".
- Do not include commentary, markdown, code fences, or extra text.
"@

# Helper: AI analysis and retry (now thread-safe)
function Analyze-Data {
    param(
        [string]$result,
        [string]$instruction,
        [string]$apiKey,
        [string]$openAIEndpoint,
        [int]$MaxTokens = 10200
    )
    if (-not $apiKey -or $apiKey -like "*REPLACE*") {
        Write-Warning "API key not set; skipping AI analysis."
        return $null
    }
    $messages = @(
        @{ role = "system"; content = $instruction },
        @{ role = "user";   content = @"
Analyze the following input payload (delimited by ===BEGIN INPUT=== / ===END INPUT===). Return only the required CSV.

===BEGIN INPUT===
$result
===END INPUT===
"@ }
    )
    $body = @{
        messages    = $messages
        max_tokens  = $MaxTokens
        temperature = 0
    } | ConvertTo-Json -Depth 10
    $headers = @{
        "Content-Type" = "application/json"
        "api-key"      = $apiKey
    }

    $maxRetries = 3
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        try {
            $resp = Invoke-RestMethod -Method POST -Uri $openAIEndpoint -Headers $headers -Body $body
            return $resp.choices[0].message.content
        } catch {
            $statusCode = $null
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $statusCode = [int]$_.Exception.Response.StatusCode.value__
            }
            if ($statusCode -eq 429 -and $attempt -lt $maxRetries) {
                Write-Warning "Rate limited (HTTP 429) on attempt $attempt. Sleeping 30 seconds before retry..."
                Start-Sleep -Seconds 30
                continue
            }
            Write-Warning "AI analysis failed (attempt $attempt): $_"
            if ($attempt -ge $maxRetries) {
                return $null
            }
        }
    }
}

# --- DLP analysis pipeline using $dlpInstruction ---

# Guard: ensure we have matches to analyze
if (-not $allMatches -or $allMatches.Count -eq 0) {
    Write-Output "No matches found; skipping AI analysis."
    return
}
# Visibility: how much data we have
Write-Output ("Total matches to analyze: {0}" -f $allMatches.Count)

# Helper: split labeled items into chunks by character budget
function Split-ByMaxChars {
    param(
        [Parameter(Mandatory)]
        [object]$Lines,
        [int]$MaxChars = 50000
    )
    # Accept either a single string (split by newline) or an array of lines
    if ($Lines -is [string]) {
        $Lines = $Lines -split "(`r`n|`n)"
    }
    $chunks = New-Object System.Collections.Generic.List[object]
    $current = New-Object System.Collections.Generic.List[string]
    $len = 0
    foreach ($line in $Lines) {
        $lineLen = [text.encoding]::UTF8.GetByteCount($line)
        if (($len + $lineLen) -gt $MaxChars -and $current.Count -gt 0) {
            $chunks.Add($current.ToArray())
            $current = New-Object System.Collections.Generic.List[string]
            $len = 0
        }
        $current.Add($line)
        $len += $lineLen + 1
    }
    if ($current.Count -gt 0) { $chunks.Add($current.ToArray()) }
    return $chunks
}

# Helper: merge multiple RFC 4180 CSV strings (keep first header only)
function Merge-CsvStrings {
    param([string[]]$CsvStrings)
    $header = $null
    $rows = New-Object System.Collections.Generic.List[string]
    foreach ($csv in $CsvStrings) {
        if (-not $csv) { continue }
        $lines = $csv -split "(`r`n|`n)"
        if (-not $lines -or $lines.Count -eq 0) { continue }
        if (-not $header) { $header = $lines[0] }
        if ($lines.Count -gt 1) {
            $tail = [string[]]$lines[1..($lines.Count - 1)]
            # Skip empty/whitespace-only lines to remove empty rows
            $cleanTail = New-Object System.Collections.Generic.List[string]
            foreach ($line in $tail) {
                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    $cleanTail.Add($line)
                }
            }
            if ($cleanTail.Count -gt 0) { $rows.AddRange($cleanTail.ToArray()) }
        }
    }
    if (-not $header) { return $null }
    # Ensure final merged rows contain no empty lines
    if ($rows.Count -gt 0) {
        $filtered = New-Object System.Collections.Generic.List[string]
        foreach ($r in $rows) {
            if (-not [string]::IsNullOrWhiteSpace($r)) {
                $filtered.Add($r)
            }
        }
        $rows = $filtered
    }
    return ($header + "`r`n" + ($rows -join "`r`n"))
}

# New: batch delete helper (20 deletes per Graph $batch)
function Remove-MessagesBatch {
    param(
        [Parameter(Mandatory)][string]$User,
        [Parameter(Mandatory)][string[]]$Ids,
        [int]$BatchSize = 20
    )
    if (-not $Ids -or $Ids.Count -eq 0) { return }
    $batchEndpoint = "https://graph.microsoft.com/v1.0/`$batch"
    for ($i = 0; $i -lt $Ids.Count; $i += $BatchSize) {
        $end = [math]::Min($i + $BatchSize - 1, $Ids.Count - 1)
        $slice = $Ids[$i..$end]
        $reqs = @()
        $rid = 1
        foreach ($mid in $slice) {
            $reqs += @{
                id     = "$rid"
                method = "DELETE"
                url    = "users/$User/messages/$mid"
            }
            $rid++
        }
        $body = @{ requests = $reqs } | ConvertTo-Json -Depth 5
        try {
            Invoke-RestMethod -Method POST -Uri $batchEndpoint -Headers $headerParams -Body $body -ContentType "application/json" | Out-Null
        } catch {
            Write-Warning "Batch delete failed for items $i..$($end): $_"
        }
        Start-Sleep -Milliseconds 200
    }
}

# Label each match as itemN for the model
$labeledItems = for ($i = 0; $i -lt $allMatches.Count; $i++) {
    "item$($i+1): $($allMatches[$i])"
}

try {
    $previewMaxChars = 150
    $tsItemLog = Get-Date -Format 'yyyyMMdd_HHmmss'
    $itemLogPath = Join-Path -Path (Get-Location) -ChildPath "dlp_items_$tsItemLog.log"
    $logLines = New-Object System.Collections.Generic.List[string]

    for ($i = 0; $i -lt $allMatches.Count; $i++) {
        $raw = [string]$allMatches[$i]
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        $preview = $raw
        if ($preview.Length -gt $previewMaxChars) {
            $preview = $preview.Substring(0, $previewMaxChars)
        }
        $preview = $preview -replace "(`r`n|`n|`r)", " "
        $logLines.Add(("item{0}: {1}" -f ($i + 1), $preview))
    }

    ("# Items preview log ({0}) - total={1}" -f $tsItemLog, $logLines.Count) | Out-File -FilePath $itemLogPath -Encoding utf8
    if ($logLines.Count -gt 0) {
        $logLines | Out-File -FilePath $itemLogPath -Encoding utf8 -Append
    }
    Write-Output ("Item log: {0}" -f $itemLogPath)
} catch {
    Write-Warning ("Failed to write item preview log: {0}" -f $_)
}

# Estimate size to understand whether chunking is needed
$joinedPreview = ($labeledItems -join "`n`n")
$inputBytes = [Text.Encoding]::UTF8.GetByteCount($joinedPreview)
$estTokens = [math]::Ceiling($inputBytes / 4)  # rough heuristic
Write-Output ("Estimated tokens for AI first pass: ~{0}" -f $estTokens)

# Chunk inputs and run first pass (with multi-threading)
$chunks = Split-ByMaxChars -Lines $labeledItems -MaxChars 150000
Write-Output ("Chunking plan: {0} chunk(s) created (MaxChars=150000)" -f $chunks.Count)

# Create runspace pool with 4 threads (change from to desired number depending on your quota)
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, 4)
$RunspacePool.Open()

# Script block for threaded analysis
$AnalysisScriptBlock = {
    param($ChunkData, $Instruction, $ApiKey, $Endpoint, $ChunkIndex)
    
    # Re-define Analyze-Data function within the thread context
    function Analyze-Data {
        param(
            [string]$result,
            [string]$instruction,
            [string]$apiKey,
            [string]$openAIEndpoint,
            [int]$MaxTokens = 1200
        )
        if (-not $apiKey -or $apiKey -like "*REPLACE*") {
            return $null
        }
        $messages = @(
            @{ role = "system"; content = $instruction },
            @{ role = "user";   content = @"
Analyze the following input payload (delimited by ===BEGIN INPUT=== / ===END INPUT===). Return only the required CSV.

===BEGIN INPUT===
$result
===END INPUT===
"@ }
        )
        $body = @{
            messages    = $messages
            max_tokens  = $MaxTokens
            temperature = 0
        } | ConvertTo-Json -Depth 10
        $headers = @{
            "Content-Type" = "application/json"
            "api-key"      = $apiKey
        }

        $maxRetries = 3
        for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
            try {
                $resp = Invoke-RestMethod -Method POST -Uri $openAIEndpoint -Headers $headers -Body $body
                return $resp.choices[0].message.content
            } catch {
                $statusCode = $null
                if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                    $statusCode = [int]$_.Exception.Response.StatusCode.value__
                }
                if ($statusCode -eq 429 -and $attempt -lt $maxRetries) {
                    Start-Sleep -Seconds 30
                    continue
                }
                if ($attempt -ge $maxRetries) {
                    return $null
                }
            }
        }
    }
    
    $dataBlock = ($ChunkData -join "`n`n")
    $csvPart = Analyze-Data -result $dataBlock -instruction $Instruction -apiKey $ApiKey -openAIEndpoint $Endpoint -MaxTokens 16384
    
    return @{
        ChunkIndex = $ChunkIndex
        CsvPart = $csvPart
    }
}

# Create jobs for each chunk
$Jobs = @()
$chunkIdx = 0
foreach ($chunk in $chunks) {
    $chunkIdx++
    $PowerShell = [powershell]::Create()
    $PowerShell.RunspacePool = $RunspacePool
    [void]$PowerShell.AddScript($AnalysisScriptBlock)
    [void]$PowerShell.AddArgument($chunk)
    [void]$PowerShell.AddArgument($dlpInstruction)
    [void]$PowerShell.AddArgument($apiKey)
    [void]$PowerShell.AddArgument($openAIEndpoint)
    [void]$PowerShell.AddArgument($chunkIdx)
    
    $Jobs += @{
        PowerShell = $PowerShell
        Handle = $PowerShell.BeginInvoke()
        ChunkIndex = $chunkIdx
    }
}

Write-Output "Processing $($Jobs.Count) chunks using 4 threads..."

# Collect results
$firstPassParts = New-Object System.Collections.Generic.List[string]
$completedCount = 0

foreach ($job in $Jobs) {
    try {
        $result = $job.PowerShell.EndInvoke($job.Handle)
        $completedCount++
        Write-Output "Chunk $($result.ChunkIndex) analyzed ($completedCount/$($Jobs.Count) complete)."
        
        if ($result.CsvPart) {
            $firstPassParts.Add($result.CsvPart)
        } else {
            Write-Warning "First pass analysis failed for chunk $($result.ChunkIndex)."
        }
    } catch {
        Write-Warning "Thread error for chunk $($job.ChunkIndex): $_"
    } finally {
        $job.PowerShell.Dispose()
    }
}

# Clean up runspace pool
$RunspacePool.Close()
$RunspacePool.Dispose()

# Merge first-pass CSV parts
$firstPassCsv = Merge-CsvStrings -CsvStrings $firstPassParts
if (-not $firstPassCsv) {
    Write-Warning "No CSV produced in first pass; aborting."
    return
}

# Optional: write outputs to timestamped files (first pass only)
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$firstPath = Join-Path -Path (Get-Location) -ChildPath "dlp_firstpass_$ts.csv"
$firstPassCsv | Out-File -FilePath $firstPath -Encoding utf8
Write-Output "First pass CSV: $firstPath"

# --- Updated: Markdown triage summary (use first pass CSV) ---
try {
    $rows = @()
    try { $rows = $firstPassCsv | ConvertFrom-Csv } catch {}
    if (-not $rows -or $rows.Count -eq 0) {
        Write-Warning "No rows to summarize; skipping Markdown triage."
        return
    }

    $high = ($rows | Where-Object { $_.risk -eq 'high' })
    $med  = ($rows | Where-Object { $_.risk -eq 'med' })
    $low  = ($rows | Where-Object { $_.risk -eq 'low' })

    $highCount = $high.Count
    $medCount  = $med.Count
    $lowCount  = $low.Count

    $authorHigh = $high | Group-Object author | Sort-Object Count -Descending
    $topAuthors = @()
    if ($authorHigh) { $topAuthors = $authorHigh | Select-Object -First 5 }

    $topHighRows = @()
    if ($high) { $topHighRows = $high | Select-Object author,message_id_or_document,credentials,explanation,repeat -First 10 }

    $providers = [ordered]@{
        'AWS'               = 'AKIA|ASIA|aws(?!-static)'
        'Azure SAS'         = '(\bsv=|\bsig=|\bsrt=|\bsp=)'
        'Azure Storage'     = 'AccountKey=|BlobEndpoint=|QueueEndpoint='
        'Cosmos DB'         = 'AccountEndpoint=|AccountKey='
        'GitHub token'      = 'ghp_'
        'GitLab token'      = 'glpat-'
        'JWT/OAuth'         = '\bJWT\b|\bOAuth\b|\bBearer\b|eyJ[A-Za-z0-9_-]{10,}\.'
        'Private key'       = 'BEGIN [A-Z ]+PRIVATE KEY'
        'Connection string' = 'Password=|Pwd=|User ID=|Server='
    }
    $joinedText = ($rows | ForEach-Object { "$($_.credentials) $($_.explanation)" }) -join " "
    $assetCounts = @{
    }
    foreach ($k in $providers.Keys) {
        try {
            $m = [regex]::Matches($joinedText, $providers[$k])
            if ($m.Count -gt 0) { $assetCounts[$k] = $m.Count }
        } catch {}
    }
    $assetsList = if ($assetCounts.Count -gt 0) {
        ($assetCounts.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "- $($_.Key): $($_.Value)" }) -join "`r`n"
    } else {
        "- none detected"
    }

    $topAuthorsMd = if ($topAuthors.Count -gt 0) {
        ($topAuthors | ForEach-Object { "- $($_.Name): $($_.Count)" }) -join "`r`n"
    } else { "- none" }

    $topHighMd = if ($topHighRows.Count -gt 0) {
        ($topHighRows | ForEach-Object { "- $($_.author) | $($_.message_id_or_document) | $($_.credentials) | $($_.explanation)" }) -join "`r`n"
    } else { "- none" }

    $md = @"
# DLP triage ($ts)

## Overview
- Total rows: $($rows.Count)
- Risk: high=$highCount, med=$medCount, low=$lowCount

## Where to begin
- Tackle high-risk items from top authors first.
- Prioritize tokens/keys and unexpired JWTs; revoke/rotate immediately.

### Top authors (high-risk)
$topAuthorsMd

### Top 10 high-risk items
$topHighMd

## Critical assets
$assetsList

## Next steps
- Revoke exposed tokens/keys; rotate secrets.
- Remove/expire messages or files containing credentials.
- Add DLP exceptions for known false positives.
- Educate senders on secure sharing practices.
"@

    $mdPath = Join-Path -Path (Get-Location) -ChildPath "dlp_triage_$ts.md"
    $md | Out-File -FilePath $mdPath -Encoding utf8
    Write-Output "Triage Markdown: $mdPath"
} catch {
    Write-Warning "Failed to create Markdown triage summary: $_"
}

# --- Helpers to ensure Graph token still valid before post-analysis operations ---
function Get-JwtExpiryEpoch {
    param([string]$Jwt)
    if (-not $Jwt) { return $null }
    $parts = $Jwt.Split('.')
    if ($parts.Count -lt 2) { return $null }
    $payload = $parts[1].Replace('-','+').Replace('_','/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
    }
    try {
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        return ( ($json | ConvertFrom-Json).exp )
    } catch { return $null }
}

function Ensure-ValidGraphToken {
    param([ref]$HeaderRef)
    try {
        $auth = $HeaderRef.Value['Authorization']
        if (-not $auth -or $auth -notmatch '^Bearer\s+') { return }
        $currentToken = $auth -replace '^Bearer\s+',''
        $exp = Get-JwtExpiryEpoch -Jwt $currentToken
        if (-not $exp) { return }  # cannot parse -> skip
        $nowEpoch = [int][double]((Get-Date -AsUTC -UFormat %s))
        if ($nowEpoch -ge ($exp - 120)) {
            Write-Verbose "Access token expired or within 120s of expiry; refreshing Graph token."
            Connect-MgGraph -Scopes "Mail.ReadWrite","Mail.ReadWrite.Shared","email" -NoWelcome | Out-Null
            $newResp  = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/me" -OutputType HttpResponseMessage
            $newToken = $newResp.RequestMessage.Headers.Authorization.Parameter
            if ($newToken) {
                $HeaderRef.Value['Authorization'] = "Bearer $newToken"
            }
        }
    } catch {
        Write-Verbose "Token refresh check failed: $_"
    }
}

# New: On successful completion, delete all retrieved messages
try {
    # Ensure token still valid before any Graph deletions (long analysis may have caused expiry)
    Ensure-ValidGraphToken -HeaderRef ([ref]$headerParams)

    $analysisOk = (Test-Path $firstPath) -and ($firstPassCsv -and $firstPassCsv.Trim().Length -gt 0)
    if ($analysisOk -and $retrievedMessageIds.Count -gt 0 -and -not $SkipDelete) {
        Write-Output ("Deleting {0} messages retrieved by this run..." -f $retrievedMessageIds.Count)
        Remove-MessagesBatch -User $dlpreportmbx -Ids $retrievedMessageIds
        Write-Output "Deletion complete."
    } else {
        Write-Output "Skipping deletion (analysis missing, no messages, or -SkipDelete supplied)."
    }
} catch {
    Write-Warning "Deletion step failed: $_"
}
