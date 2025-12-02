param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,
    [string]$DcrId = "",
    [string]$DceEndpoint = "",
    [string]$StreamName = "Custom-Credleak_CL",
    [int]$BatchSize = 500,
    [int]$MaxPostBytes = 1048576,
    [string]$AccessToken,                    # CHANGED: removed misleading default "true"
    [string]$TimeField = "TimeGenerated",
    [switch]$ShowErrorBody,
    [switch]$DryRun,
    [switch]$ShowFirstPayload,               # dump first batch JSON for debugging
    [switch]$RepeatAsString,                  # treat repeat field as raw string instead of boolean
    [switch]$Diagnose400,                     # emit detailed diagnostics on HTTP 400
    [string]$resource = "https://monitor.azure.com/"         
)

function Invoke-WithRetry {
    param(
        [scriptblock]$Action,
        [int]$MaxAttempts = 5
    )
    for ($i=1; $i -le $MaxAttempts; $i++) {
        try {
            return & $Action
        } catch {
            $status = $_.Exception.Response.StatusCode.value__ 2>$null
            # Do not retry client schema errors (400) – they are not transient
            if ($status -in 408,429,500,502,503,504 -and $i -lt $MaxAttempts) {
                Start-Sleep -Seconds ([math]::Min([math]::Pow(2,$i),30))
                continue
            }
            throw
        }
    }
}

function Get-AccessToken {
    param([string]$CachedToken)

    if ($CachedToken) { return $CachedToken }

    # 1. If user supplied token
    if ($AccessToken) { return $AccessToken }

    # 2. Managed Identity (IMDS)
    try {
        $imdsUri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://monitor.azure.com/"
        $mi = Invoke-RestMethod -Method GET -Uri $imdsUri -Headers @{Metadata="true"} -TimeoutSec 3
        if ($mi.access_token) { return $mi.access_token }
    } catch { }

    # 3. Az.Accounts (Connect-AzAccount) if available
    try {
        if (Get-Module -ListAvailable -Name Az.Accounts | Where-Object { $_ }) {
            # Requires prior Connect-AzAccount
            $azTok = (Get-AzAccessToken -ResourceUrl $resource -AsSecureString).Token | ConvertFrom-SecureString -AsPlainText
            if ($azTok) { return $azTok }
        }
    } catch { }

    # 4. Azure CLI fallback
    try {
        $cli = az account get-access-token --resource https://monitor.azure.com/ --output json 2>$null | ConvertFrom-Json
        if ($cli.accessToken) { return $cli.accessToken }
    } catch { }

    throw "Failed to acquire AAD access token. If the token is expired or no session is present, run: Connect-AzAccount -AuthScope https://monitor.azure.com/"
}

function Send-LogBatch {
    param(
        [object[]]$Records,
        [string]$DcrId,
        [string]$DceEndpoint,
        [string]$StreamName,
        [ref]$TokenRef
    )
    if (-not $Records -or $Records.Count -eq 0) { return 0 }

    $json = $Records | ConvertTo-Json -Depth 6

    if (-not $TokenRef.Value) {
        $TokenRef.Value = Get-AccessToken
    }
    $token = $TokenRef.Value   # FIX: capture correct token
    $uri = "https://$DceEndpoint/dataCollectionRules/$DcrId/streams/$($StreamName)?api-version=2023-01-01"
    $headers = @{
        "Authorization" = "Bearer $token"   # FIX: was using undefined $Token
        "Content-Type"  = "application/json; charset=utf-8"
        "x-ms-client-request-id" = [guid]::NewGuid().ToString()
    }
    $did401Retry = $false      # NEW: track single retry on 401
    Invoke-WithRetry -Action {
        try {
            Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $json -ContentType "application/json"
        } catch {
            $status = $_.Exception.Response.StatusCode.value__ 2>$null
            # NEW: handle 401 with one automatic token refresh + replay
            if ($status -eq 401 -and -not $did401Retry) {
                Write-Warning "401 Unauthorized. Refreshing access token and retrying once."
                $TokenRef.Value = Get-AccessToken
                $token = $TokenRef.Value
                $headers["Authorization"] = "Bearer $token"
                $did401Retry = $true
                try {
                    Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $json -ContentType "application/json"
                    return
                } catch {
                    $status = $_.Exception.Response.StatusCode.value__ 2>$null
                    # fall through to normal error handling below
                }
            }
            if ($status -eq 401 -and $did401Retry) {
                Write-Error "Persistent 401 Unauthorized. Re-authenticate: Connect-AzAccount -AuthScope https://monitor.azure.com/"
            }
            $errBody = $null
            if ($_.Exception.Response) {
                try {
                    $respStream = $_.Exception.Response.GetResponseStream()
                    if ($respStream) {
                        $reader = New-Object System.IO.StreamReader($respStream)
                        $errBody = $reader.ReadToEnd()
                    }
                } catch { }
            }
            if ($ShowErrorBody -and $errBody) {
                Write-Warning ("Service error body: {0}" -f $errBody)
            }
            if ($errBody) {
                try {
                    $parsed = $errBody | ConvertFrom-Json
                    $msg = $parsed.error.message 2>$null
                    $code = $parsed.error.code 2>$null
                    if ($msg -or $code) {
                        Write-Warning ("Detailed error Code={0} Message={1}" -f $code,$msg)
                        if ($msg -match 'Column.*type' -or $msg -match 'schema') {
                            Write-Warning "Hint: Check DCR stream field names & data types (boolean vs string, etc.)."
                        }
                        if ($msg -match 'TimeGenerated' -and -not $TimeField) {
                            Write-Warning "Hint: DCR expects a time field; supply -TimeField or map in DCR."
                        }
                    }
                } catch { }
            }
            if ($status -eq 401) {
                $TokenRef.Value = Get-AccessToken
                throw
            }
            if ($status -eq 400 -and $Diagnose400) {
                Write-Warning "HTTP 400 diagnostics start =================================="
                Write-Warning ("DCR={0} Stream={1} RecordsInBatch={2} PayloadBytes={3}" -f $DcrId,$StreamName,$Records.Count,$payloadSize)
                $first = $Records | Select-Object -First 1
                if ($first) {
                    Write-Warning "First record field types:"
                    foreach ($p in $first.PSObject.Properties) {
                        $t = if ($p.Value -ne $null) { $p.Value.GetType().Name } else { "null" }
                        Write-Warning ("  {0} : {1} | SampleValue={2}" -f $p.Name,$t,($p.Value -is [string] -and $p.Value.Length -gt 60 ? ($p.Value.Substring(0,57)+'...') : $p.Value))
                    }
                }
                if (-not ($json.TrimStart().StartsWith('['))) {
                    Write-Warning "Body is not a JSON array. Logs Ingestion requires an array of objects."
                }
                if ($json -match '"repeat"\s*:\s*"(true|false)"' -and -not $RepeatAsString) {
                    Write-Warning 'repeat appears as quoted string while schema may expect boolean. Use -RepeatAsString if DCR column is string, else ensure unquoted true/false.'
                }
                if ($TimeField -and $json -notmatch ('"'+[regex]::Escape($TimeField)+'"\s*:')) {
                    Write-Warning ("Time field {0} missing from payload objects." -f $TimeField)
                }
                if ($errBody) {
                    Write-Warning "Service provided body already captured above."
                } else {
                    Write-Warning "No service error body returned (could be networking or formatting before service parse)."
                }
                Write-Warning "Sample JSON (truncated to 1000 chars):"
                Write-Warning ($json.Substring(0,[Math]::Min(1000,$json.Length)))
                Write-Warning "HTTP 400 diagnostics end ===================================="
            }
            throw
        }
    } | Out-Null
    return $Records.Count
}

# Validate stream name (avoid hidden whitespace mismatches)
if ($StreamName -match '^\s' -or $StreamName -match '\s$') {
    throw "StreamName has leading or trailing whitespace. Fix: '$StreamName'"
}

if (-not (Test-Path -Path $CsvPath -PathType Leaf)) {
    throw "CSV path not found: $CsvPath"
}

$rows = Import-Csv -Path $CsvPath
if (-not $rows) {
    Write-Host "No rows found in CSV."
    return
}

# Transform rows with explicit ISO 8601 UTC timestamp in configurable TimeField
$mapped = foreach ($r in $rows) {
    $h = [ordered]@{
        author                  = $r.author
        message_id_or_document  = $r.message_id_or_document
        risk                    = $r.risk
        credentials             = $r.credentials
        credentialtype          = $r.credentialtype
        explanation             = $r.explanation
        # CHANGED: repeat handling toggle for schema mismatch scenarios
        repeat                  = if ($RepeatAsString) { ($r.repeat -as [string]) } else { ($r.repeat -as [string]) -in @('true','1','yes') }
        dlptune                 = $r.dlptune
        Workload                = $r.Workload
        Recipients              = $r.Recipients
        subject_document        = $r.subject_document
    }
    # Add time field (string ISO 8601) if a name supplied
    if ($TimeField) {
        $h[$TimeField] = (Get-Date).ToUniversalTime().ToString("o")
    }
    [pscustomobject]$h
}

if ($DryRun) {
    Write-Host "DryRun: would ingest $($mapped.Count) records to stream $StreamName (DCR $DcrId) TimeField=$TimeField"
    $preview = $mapped | Select-Object -First ([math]::Min(5,$mapped.Count))
    $preview | ConvertTo-Json -Depth 4
    return
}

$total        = $mapped.Count
$batches      = [System.Collections.Generic.List[object[]]]::new()
$currentBatch = @()
foreach ($item in $mapped) {
    $currentBatch += $item
    if ($currentBatch.Count -ge $BatchSize) {
        $batches.Add($currentBatch)
        $currentBatch = @()
    }
}
if ($currentBatch.Count -gt 0) { $batches.Add($currentBatch) }

$success = 0
$failed  = 0
$batchIndex = 0
$tokenRef = [ref]$null

foreach ($b in $batches) {
    $batchIndex++
    try {
        $ingested = Send-LogBatch -Records $b -DcrId $DcrId -DceEndpoint $DceEndpoint -StreamName $StreamName -TokenRef $tokenRef
        $success += $ingested
        Write-Host ("Batch {0}/{1} OK - {2} records (size={3} bytes)" -f $batchIndex,$batches.Count,$ingested,([Text.Encoding]::UTF8.GetBytes(($b | ConvertTo-Json -Depth 4)).Length))
    } catch {
        $failed += $b.Count
        Write-Warning ("Batch {0}/{1} FAILED ({2} records): {3}" -f $batchIndex,$batches.Count,$b.Count,$_.Exception.Message)
    }
}

Write-Host ("Ingestion complete. Total={0} Succeeded={1} Failed={2} Stream={3}" -f $total,$success,$failed,$StreamName)
if ($failed -gt 0) { exit 1 }
