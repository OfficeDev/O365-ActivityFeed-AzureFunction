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

#Function to hash or remove the sensitive data detected.
function Set-DetectedValues {
    param($Data, $Method)
    foreach ($policy in $Data.PolicyDetails) {
        foreach ($rule in $policy.Rules) {
            $rule.ConditionsMatched | Add-Member @{
                TotalCount = [int] ($rule.ConditionsMatched.SensitiveInformation | Measure-Object -Property Count -Sum).Sum
            } -PassThru | Out-Null
            foreach ($sit in $rule.ConditionsMatched.SensitiveInformation) {
                $index = ($rule.ConditionsMatched.SensitiveInformation).IndexOf($sit)
                $sitId = (New-Guid).Guid
                $sit | Add-Member -Force -NotePropertyMembers @{
                    Identifier                   = $Data.Id
                    PolicyId                     = $policy.PolicyId
                    RuleId                       = $rule.RuleId
                    SensitiveType                = $sit.SensitiveType
                    SensitiveInformationTypeName = $sit.SensitiveInformationTypeName
                    DetectionResultsTruncated    = $sit.SensitiveInformationDetections.ResultsTruncated
                    SITCount                     = $sit.Count
                    ClassificationAttributes     = $sit.SensitiveInformationDetailedClassificationAttributes
                    SensitiveInfoId              = $sitId
                } -PassThru | Out-Null
                $sit.PSObject.Properties.Remove('Count')
                $sit.PSObject.Properties.Remove('SensitiveInformationDetailedClassificationAttributes')
                $sitAdd =  $sit.PsObject.Copy()
                $sitAdd.PSObject.Properties.Remove('SensitiveInformationDetections')
                $sits.Add($sitAdd) | Out-Null
                foreach ($detection in $sit.SensitiveInformationDetections) {
                    if ($Method -ne 'Keep') {
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
                            elseif ($Method -eq 'Remove') {
                                $value.Name = 'Removed'
                                $value.Value = 'Removed'
                            }
                            $value | Add-Member -Force -NotePropertyMembers @{
                                Identifier      = $Data.Id
                                SensitiveInfoId = $sitId
                                Name            = $value.Name
                                Value           = $value.Value                         
                            } -PassThru | Out-Null
                            $detections.Add($value) | Out-Null                        
                        }
                    }
                }
                if ($index -eq (($rule.ConditionsMatched.SensitiveInformation).Count -1))
                {
                    $rule.ConditionsMatched.PSObject.Properties.Remove('SensitiveInformation')
                }
            }
        }
    }
}

function Set-DetectedValuesEndpoint {
    param($Data, $Method)
    $Data.EndpointMetaData | Add-Member @{
        SensitiveInfoTypeTotalCount = [int] ($Data.EndpointMetaData.SensitiveInfoTypeData | Measure-Object -Property Count -Sum).Sum
    } -PassThru | Out-Null
    foreach ($sit in $Data.EndpointMetaData.SensitiveInfoTypeData) {
        $sit | Add-Member -Force -NotePropertyMembers @{
            Identifier                   = $Data.Id
            SITCount                     = $sit.Count
            SensitiveInfoTypeId          = $sit.SensitiveInfoTypeId
            SensitiveInformationTypeName = $sit.SensitiveInfoTypeName
            ClassificationAttributes     = $sit.SensitiveInformationDetailedClassificationAttributes
        } -PassThru | Out-Null
        $sit.PSObject.Properties.Remove('Count')
        $sit.PSObject.Properties.Remove('SensitiveInformationDetailedClassificationAttributes')
        $sits.Add($sit) | Out-Null
        foreach ($detection in $sit.SensitiveInformationDetectionsInfo) {
            if ($Method -ne 'Keep') {
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
                    elseif ($Method -eq 'Remove') {
                        $value.Name = 'Removed'
                        $value.Value = 'Removed'
                    }
                    $value | Add-Member -Force -NotePropertyMembers @{
                        Identifier            = $Data.Id                 
                    } -PassThru | Out-Null
                    $detections.Add($value) | Out-Null
                }
            }
        }     
    }
    $Data.EndpointMetaData.PSObject.Properties.Remove('SensitiveInfoTypeData')
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

#Initialize arrays to hold sensitive info type and detected values data.
$sits = New-Object System.Collections.ArrayList
$detections = New-Object System.Collections.ArrayList

Foreach ($user in $records) {
    #Exchange and Teams upload data process
    $user.workload
    if (($user.workload -eq "Exchange" -and $user.operation -ne "MipLabel") -or ($user.Workload -eq "MicrosoftTeams")) {
        #Remove/hash sensitive info if specified.
        Set-DetectedValues -Data $user -Method $sensitiveDataHandling
        
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
        Set-DetectedValues -Data $user -Method $sensitiveDataHandling

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
        Set-DetectedValuesEndpoint -Data $user -Method $sensitiveDataHandling
        
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
        Set-DetectedValues -Data $user -Method $sensitiveDataHandling

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
            Send-DataToAzureMonitorBatched -Data $uploadWS.$activeWS -BatchSize 50 -TableName ("Custom-$LogType" + "_CL") -JsonDepth 100 -UamiClientId $uamiClientId -DceURI $dceUri -DcrImmutableId $dcrImmutableId -SortBySize $true -EventIdPropertyName 'Identifier'
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
    $timeGenerated = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ' -AsUTC)
    $allWS | Add-Member -NotePropertyName 'TimeGenerated' -NotePropertyValue $timeGenerated
    $allWS | Add-Member -MemberType AliasProperty -Name Identifier -Value Id
    $sits | Add-Member -NotePropertyName 'TimeGenerated' -NotePropertyValue $timeGenerated
    $detections | Add-Member -NotePropertyName 'TimeGenerated' -NotePropertyValue $timeGenerated

    #Send received data to Azure Monitor.
    Send-DataToAzureMonitorBatched -Data $allWS -BatchSize 10000 -TableName ("Custom-$LogType" + "_CL") -JsonDepth 100 -UamiClientId $uamiClientId -DceURI $dceUri -DcrImmutableId $dcrImmutableId -SortBySize $true -EventIdPropertyName 'Identifier'
    Send-DataToAzureMonitorBatched -Data $sits -BatchSize 10000 -TableName ("Custom-$LogType" + "SIT_CL") -JsonDepth 100 -UamiClientId $uamiClientId -DceURI $dceUri -DcrImmutableId $dcrImmutableId -SortBySize $true -EventIdPropertyName 'Identifier'
    Send-DataToAzureMonitorBatched -Data $detections -BatchSize 10000 -TableName ("Custom-$LogType" + "Detections_CL") -JsonDepth 100 -UamiClientId $uamiClientId -DceURI $dceUri -DcrImmutableId $dcrImmutableId -SortBySize $true -EventIdPropertyName 'Identifier'
}