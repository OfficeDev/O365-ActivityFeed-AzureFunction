# Input bindings are passed in via param block.
param($QueueItem, $TriggerMetadata)

#Initiate Arrays used by the function
$records = @()
$exupload = @()
$spoupload = @()
$endpointupload = @()
$powerbiupload = @()
$allWS = @()

$tolocal = @()

#Workspaces, mapping of country code to workspace, update county code, key and ID reference for multiple workspaces
#$maineu = @{"Countries" = "US,ES,IT";"Workspacekey" = $env:workspaceKey; "Workspace" = $env:workspaceId}
#$Germany = @{"Countries" = "DE,GB,SE";"Workspacekey" = $env:workspaceKeyEU; "Workspace" = $env:workspaceIdEU}
#$LT = @{"Countries" = "LT";"Workspacekey" = $env:workspaceKeyEU; "Workspace" = $env:workspaceIdEU}

#List of Workspaces, update based on workspaces added
#$workspaces = @{"MainEU" = $maineu; "Germany" = $Germany; "LT" = $LT}

#All Content Workspace, used for the central team
$AllContent = @{"Countries" = "ALLContent"; "Workspacekey" = $env:workspaceKey; "Workspace" = $env:workspaceId }

# Specify the name of the record type that you'll be creating
$LogType = $env:customLogName

#Define Azure Monitor variables
$dcrImmutableId = $env:DcrImmutableId
$dceUri = $env:DceUri
$uamiClientId = $env:UamiClientId
$sensitiveDataHandling = $env:SensitiveDataHandling

#Retry logic primarily for AF429 where there is more than 60k requests per minute, much code reused from https://stackoverflow.com/questions/45470999/powershell-try-catch-and-retry
function Test-Command {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [scriptblock]$ScriptBlock,
  
        [Parameter(Position = 1, Mandatory = $false)]
        [int]$Maximum = 5,
  
        [Parameter(Position = 2, Mandatory = $false)]
        [int]$Delay = 100
    )
    Begin {
        $cnt = 0
    }
    Process {
        do {
            $cnt++
            try {
                $ScriptBlock.Invoke()
                return
            }
            catch {
                $fault = $_.Exception.InnerException.Message | convertfrom-json
                Write-Error $_.Exception.InnerException.Message -ErrorAction Continue
                if ($fault.error.code -eq "AF429") { Start-Sleep -Milliseconds $Delay }
                else { $cnt = $Maximum }
            }
        } while ($cnt -lt $Maximum)
        throw 'Execution failed.'
    }
}

#Function to split data into specified batch sizes (so we do not exceed the maximum body size) and send to Azure Monitor.
function Send-DataToAzureMonitor {
    param ($Data, $BatchSize, $TableName, $JsonDepth, $Maximum = 5)
    $skip = 0
    $cnt = 0
    do {
        $cnt++
        try {
            do {
                $batchedData = $Data | Select-Object -Skip $skip -First $BatchSize
                $logIngestionClient.Upload($dcrImmutableId, $TableName, ($batchedData | ConvertTo-Json -Depth $JsonDepth -AsArray))
                $skip += $BatchSize
            } until (
                $skip -ge $Data.Count
            )
            return
        }
        catch {
            if ($_.Exception.InnerException.Message -like "*ErrorCode: ContentLengthLimitExceeded*") { 
                if ($BatchSize -le 1) {
                    Write-Error "Single event is too large to submit to Azure Monitor. Try reducing size or breaking up into smaller events." -ErrorAction Continue
                    $cnt = $Maximum
                }
                else {
                    $BatchSize = [math]::Round($BatchSize / 2)
                    if ($BatchSize -lt 1) { $BatchSize = 1 }
                    Write-Host ("Data too large, reducing batch size to: $BatchSize")
                }
            }
            else { $cnt = $Maximum }
        }
    } while ($cnt -lt $Maximum)
    throw 'Failed to write data to Azure Monitor.'
}

#Function to hash or remove the sensitive data detected.
function Set-DetectedValues {
    param($Data, $Method)
    foreach ($policy in $Data.PolicyDetails) {
        foreach ($rule in $policy.Rules) {
            foreach ($sit in $rule.ConditionsMatched.SensitiveInformation) {
                foreach ($detection in $sit.SensitiveInformationDetections) {
                    foreach ($value in $detection.DetectedValues) {
                        if ($Method -eq 'Hash') {
                            $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
                            $nameHash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($value.Name))
                            $nameHashString = [System.BitConverter]::ToString($nameHash)
                            $nameHash = $nameHashString.Replace('-', '')
                            $valueHash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($value.Value))
                            $valueHashString = [System.BitConverter]::ToString($valueHash)
                            $valueHash = $valueHashString.Replace('-', '')
                            $value.Name = $nameHash.toLower()
                            $value.Value = $valueHash.toLower()
                        }
                        else {
                            $value.Name = 'Removed'
                            $value.Value = 'Removed'
                        }
                    }
                }
            }
        }
    }
}

function Set-DetectedValuesEndpoint {
    param($Data, $Method)
    foreach ($SensitiveInfoTypeData in $Data.EndpointMetaData.SensitiveInfoTypeData) {
        foreach ($SensitiveInformationDetectionsInfo in $SensitiveInfoTypeData.SensitiveInformationDetectionsInfo) {
            foreach ($value in $SensitiveInformationDetectionsInfo.DetectedValues) {
                if ($Method -eq 'Hash') {
                    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
                    $nameHash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($value.Name))
                    $nameHashString = [System.BitConverter]::ToString($nameHash)
                    $nameHash = $nameHashString.Replace('-', '')
                    $valueHash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($value.Value))
                    $valueHashString = [System.BitConverter]::ToString($valueHash)
                    $valueHash = $valueHashString.Replace('-', '')
                    $value.Name = $nameHash.toLower()
                    $value.Value = $valueHash.toLower()
                }
                else {
                    $value.Name = 'Removed'
                    $value.Value = 'Removed'
                }
            }
        }     
    }
}

$clientID = "$env:clientID"
$clientSecret = "$env:clientSecret"
$loginURL = "https://login.microsoftonline.com"
$tenantGUID = "$env:TenantGuid"
$resource = "https://manage.office.com"

# Get an Oauth 2 access token based on client id, secret and tenant domain
$body = @{grant_type = "client_credentials"; resource = $resource; client_id = $ClientID; client_secret = $ClientSecret }

#oauthtoken in the header
$oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantGUID/oauth2/token?api-version=1.0 -Body $body 
$headerParams = @{'Authorization' = "$($oauth.token_type) $($oauth.access_token)" }

#$message = $queueitem | convertfrom-json
$content = $queueitem

if ($queueitem.count -eq 1) { $content = $queueitem | convertfrom-json }

foreach ( $url in $content) {
    $uri = $url + "?PublisherIdentifier=" + $TenantGUID
    $record = Test-Command {  
        Invoke-RestMethod -UseBasicParsing -Headers $headerParams -Uri $uri
    } -Delay 10000
    $records += $record
}

$records.count

#Here starts the enrichment functionality and routing function.

#Make the GRAPH Call to get additional information, require different audience tag.
$resourceG = "https://graph.microsoft.com"
$bodyG = @{grant_type = "client_credentials"; resource = $resourceG; client_id = $ClientID; client_secret = $ClientSecret }
$oauthG = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantGUID/oauth2/token?api-version=1.0 -Body $bodyG 
$headerParamsG = @{'Authorization' = "$($oauthG.token_type) $($oauthG.access_token)" }

Foreach ($user in $records) {
    #Exchange and Teams upload data process
    $user.workload
    if (($user.workload -eq "Exchange" -and $user.operation -ne "MipLabel") -or ($user.Workload -eq "MicrosoftTeams")) {
        #Remove/hash sensitive info if specified.
        if ($sensitiveDataHandling -eq 'Keep') {}
        else { Set-DetectedValues -Data $user -Method $sensitiveDataHandling }
        
        #Determine if the email is from external or internal if from external associate with first recipient on the to line
        if (($env:domains).split(",") -Contains ($user.ExchangeMetaData.from.Split('@'))[1]) { $exuser = $user.ExchangeMetaData.from }

        if ([string]::IsNullOrEmpty($exuser)) {
            $tolocal = $user.ExchangeMetaData.to | select-string -pattern ($env:domains).split(",") -simplematch
            if ($null -ne $tolocal) { $exuser = $tolocal[0] } 
            else { Write-Warning "Could not find any matching internal domains within the To or From fields. Make sure the internal domains list is up to date." }            
        }

        #Avoiding enrichment for system messages that may have slipped through
        $systemMail = "no-reply@sharepointonline.com,noreply@email.teams.microsoft.com"
        if (($systemMail).split(",") -notcontains $exuser) {
        
            #Add the additional attributes needed to enrich the event stored in Log Analytics for Exchange
            # $queryString = "https://graph.microsoft.com/v1.0/users/" + $exuser + "?" + "$" + "select=usageLocation,Manager,department,state" 
            $queryString = "https://graph.microsoft.com/v1.0/users?" + '$select=department,usageLocation,UserPrincipalName,jobTitle&$filter' + "=proxyAddresses/any(x:startswith(x,'SMTP:$exuser'))"       
            if ($exuser) { $info = Invoke-RestMethod -Headers $headerParamsG -Uri $queryString -Method GET -SkipHttpErrorCheck }
            $info = $info.value

            #Add usage location from GRAPH Call
            $user | Add-Member -MemberType NoteProperty -Name "usageLocation" -Value $info.usageLocation
            if ($info) { 
                $user | Add-Member -MemberType NoteProperty -Name "department" -Value $info.department
                $user | Add-Member -MemberType NoteProperty -Name "jobTitle" -Value $info.jobTitle
            }

            #$querymanager = "https://graph.microsoft.com/v1.0/users/" + $exuser + "/manager"
            $querymanager = "https://graph.microsoft.com/v1.0/users/" + $info.userPrincipalName + "/manager"
            $manager = Invoke-RestMethod -Headers $headerParamsG -Uri $querymanager -SkipHttpErrorCheck
            if ($manager) { $user | Add-Member -MemberType NoteProperty -Name "manager" -Value $manager.mail }
          
            Clear-Variable -name info                                                                                                         
        }

        $exupload += $user 
    }

    #SharePoint and OneDrive upload data process
    if (($user.Workload -eq "OneDrive") -or ($user.Workload -eq "SharePoint")) {
        #Remove/hash sensitive info if specified.
        if ($sensitiveDataHandling -eq 'Keep') {}
        else { Set-DetectedValues -Data $user -Method $sensitiveDataHandling }

        #Add the additional attributes needed to enrich the event stored in Log Analytics for SharePoint
        $queryString = $user.SharePointMetaData.From + "?$" + "select=usageLocation,Manager,department,state,jobTitle"
        $info = Invoke-RestMethod -Headers $headerParamsG -Uri "https://graph.microsoft.com/v1.0/users/$queryString" -Method GET -SkipHttpErrorCheck
        $user | Add-Member -MemberType NoteProperty -Name "usageLocation" -Value $info.usageLocation
        if ($info) { 
            $user | Add-Member -MemberType NoteProperty -Name "department" -Value $info.department
            $user | Add-Member -MemberType NoteProperty -Name "jobTitle" -Value $info.jobTitle
        }

        $querymanager = "https://graph.microsoft.com/v1.0/users/" + $user.SharePointMetaData.From + "/manager" 
        $manager = Invoke-RestMethod -Headers $headerParamsG -Uri $querymanager -SkipHttpErrorCheck
        if ($manager) { $user | Add-Member -MemberType NoteProperty -Name "manager" -Value $manager.mail }

        $spoupload += $user
        Clear-Variable -name info
    }
                            
    #EndpointDLP upload
    if ($user.Workload -eq "Endpoint") {
        #Remove/hash sensitive info if specified.
        if ($sensitiveDataHandling -eq 'Keep') {}
        else { Set-DetectedValuesEndpoint -Data $user -Method $sensitiveDataHandling }
        
        #Add the additional attributes needed to enrich the event stored
        $queryString = $user.UserKey + "?$" + "select=usageLocation,Manager,department,state,jobTitle"
        $info = Invoke-RestMethod -Headers $headerParamsG -Uri "https://graph.microsoft.com/v1.0/users/$queryString" -Method GET -SkipHttpErrorCheck
        $user | Add-Member -MemberType NoteProperty -Name "usageLocation" -Value $info.usageLocation
        if ($info) { 
            $user | Add-Member -MemberType NoteProperty -Name "department" -Value $info.department
            $user | Add-Member -MemberType NoteProperty -Name "jobTitle" -Value $info.jobTitle
        }

        $querymanager = "https://graph.microsoft.com/v1.0/users/" + $user.UserKey + "/manager" 
        $manager = Invoke-RestMethod -Headers $headerParamsG -Uri $querymanager -SkipHttpErrorCheck
        if ($manager) { $user | Add-Member -MemberType NoteProperty -Name "manager" -Value $manager.mail }

        if ($user.objectId) {
            $document = Split-Path $user.objectId -leaf
            $user | Add-Member -MemberType NoteProperty -Name "DocumentName" -Value $document
        }

        $endpointupload += $user
        Clear-Variable -name info
    }
    
    #PowerBI upload
    if ($user.Workload -eq "PowerBI") {
        #Remove/hash sensitive info if specified.
        if ($sensitiveDataHandling -eq 'Keep') {}
        else { Set-DetectedValues -Data $user -Method $sensitiveDataHandling }

        #Add the additional attributes needed to enrich the event stored
        $queryString = $user.UserId + "?$" + "select=usageLocation,Manager,department,state,jobTitle"
        $info = Invoke-RestMethod -Headers $headerParamsG -Uri "https://graph.microsoft.com/v1.0/users/$queryString" -Method GET -SkipHttpErrorCheck
        $user | Add-Member -MemberType NoteProperty -Name "usageLocation" -Value $info.usageLocation
        if ($info) { 
            $user | Add-Member -MemberType NoteProperty -Name "department" -Value $info.department
            $user | Add-Member -MemberType NoteProperty -Name "jobTitle" -Value $info.jobTitle
        }

        $querymanager = "https://graph.microsoft.com/v1.0/users/" + $user.UserId + "/manager" 
        $manager = Invoke-RestMethod -Headers $headerParamsG -Uri $querymanager -SkipHttpErrorCheck
        if ($manager) { $user | Add-Member -MemberType NoteProperty -Name "manager" -Value $manager.mail }

        if ($user.objectId) {
            $document = Split-Path $user.objectId -leaf
            $user | Add-Member -MemberType NoteProperty -Name "DocumentName" -Value $document
        }

        $powerbiupload += $user
        Clear-Variable -name info
    }
}

#Add required .Net assemblies to handle the Azure Monitor ingestion.
Add-Type -Path .\StoreDLPEvents\lib\Azure.Monitor.Ingestion.dll
Add-Type -Path .\StoreDLPEvents\lib\Azure.Identity.dll

#Create Azure.Identity credential via User Assigned Managed Identity.
$credential = New-Object Azure.Identity.ManagedIdentityCredential($uamiClientId)

#Create LogsIngestionClient to handle sending data to Azure Monitor.
$logIngestionClient = New-Object Azure.Monitor.Ingestion.LogsIngestionClient($dceURI, $credential)

#Determine which Sentinel Workspace to route the information,
$uploadWS = @{}

if ($workspace) {
    foreach ($workspace in $workspaces.GetEnumerator()) {
        $uploadWS[$workspace.name] = @()

        #Exchange and Teams
        $uploadWS[$workspace.name] += $exupload | where-object { $workspace.Value.Countries.split(",") -Contains $_.usageLocation }                                                          

        #SharePoint and OneDrive
        $uploadWS[$workspace.name] += $spoupload | where-object { $workspace.Value.Countries.split(",") -Contains $_.usageLocation }       
                                
        #EndPoint
        $uploadWS[$workspace.name] += $endpointupload | where-object { $workspace.Value.Countries.split(",") -Contains $_.usageLocation }
        
        #PowerBi
        $uploadWS[$workspace.name] += $powerbiupload | where-object { $workspace.Value.Countries.split(",") -Contains $_.usageLocation } 
    }                  

    #Upload to Workspaces

    foreach ($workspace in $workspaces.GetEnumerator()) {
        $activeWS = $workspace.name
        if ($uploadWS.$activeWS) {
            #Add required TimeGenerated field and create alias for Id field since that name is not allowed by Azure Monitor.
            $allWS | Add-Member -NotePropertyName 'TimeGenerated' -NotePropertyValue (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ' -AsUTC)
            $uploadWS.$activeWS | Add-Member -MemberType AliasProperty -Name Identifier -Value Id

            #Send received data to Azure Monitor.
            Send-DataToAzureMonitor -Data $uploadWS.$activeWS -BatchSize 50 -TableName ("Custom-$LogType" + "_CL") -JsonDepth 100
        }

    }
}

#Uploading everything to a unified Workspace
$allWS += $exupload
$allWS += $spoupload
$allWS += $endpointupload
#$allWS += $powerbiupload
if ($allWS) {
    #Add required TimeGenerated field and create alias for Id field since that name is not allowed by Azure Monitor.
    $allWS | Add-Member -NotePropertyName 'TimeGenerated' -NotePropertyValue (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ' -AsUTC)
    $allWS | Add-Member -MemberType AliasProperty -Name Identifier -Value Id

    #Send received data to Azure Monitor.
    Send-DataToAzureMonitor -Data $allWS -BatchSize 50 -TableName ("Custom-$LogType" + "_CL") -JsonDepth 100
}






