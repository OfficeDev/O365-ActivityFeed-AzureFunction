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

#Functions to hash or remove the sensitive data detected.
function Get-Hash ($Value) {
    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
    $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
    $hashString = [System.BitConverter]::ToString($hash)
    $hash = $hashString.Replace('-', '')
    return $hash.ToLower()
}
function Set-DetectedValues {
    param($Data, $Method = 'Hash')
    foreach ($policy in $Data.PolicyDetails) {
        foreach ($rule in $policy.Rules) {
            $rule.ConditionsMatched | Add-Member @{
                TotalCount = [int] ($rule.ConditionsMatched.SensitiveInformation | Measure-Object -Property Count -Sum).Sum
            } -PassThru | Out-Null
            foreach ($sit in $rule.ConditionsMatched.SensitiveInformation) {
                $index = ($rule.ConditionsMatched.SensitiveInformation).IndexOf($sit)
                $sitId = (New-Guid).Guid
                $sit | Add-Member -NotePropertyMembers @{
                    Identifier                = $Data.Id
                    PolicyId                  = $policy.PolicyId
                    RuleId                    = $rule.RuleId
                    DetectionResultsTruncated = $sit.SensitiveInformationDetections.ResultsTruncated
                    SITCount                  = $sit.Count
                    ClassificationAttributes  = $sit.SensitiveInformationDetailedClassificationAttributes
                    SensitiveInfoId           = $sitId
                } -PassThru | Out-Null
                $sit.PSObject.Properties.Remove('Count')
                $sit.PSObject.Properties.Remove('SensitiveInformationDetailedClassificationAttributes')
                $sitAdd = $sit.PsObject.Copy()
                $sitAdd.PSObject.Properties.Remove('SensitiveInformationDetections')
                $sits.Add($sitAdd) | Out-Null
                if ($Method -ne 'Remove') {
                    foreach ($detection in $sit.SensitiveInformationDetections) {
                        foreach ($value in $detection.DetectedValues) {
                            foreach ($detection in $sit.SensitiveInformationDetections) {
                                if ($Method -eq 'Hash') {
                                    $value.Name = Get-Hash -Value $value.Name
                                    $value.Value = Get-Hash -Value $value.Value
                                }
                                $value | Add-Member -NotePropertyMembers @{
                                    Identifier      = $Data.Id
                                    SensitiveInfoId = $sitId            
                                } -PassThru | Out-Null
                                $detections.Add($value) | Out-Null
                            }                       
                        }
                    }
                }
                if ($index -eq (($rule.ConditionsMatched.SensitiveInformation).Count - 1)) {
                    $rule.ConditionsMatched.PSObject.Properties.Remove('SensitiveInformation')
                }
            }
        }
    }
}

function Set-DetectedValuesEndpoint {
    param($Data, $Method = 'Hash')
    $Data.EndpointMetaData | Add-Member @{
        SensitiveInfoTypeTotalCount = [int] ($Data.EndpointMetaData.SensitiveInfoTypeData | Measure-Object -Property Count -Sum).Sum
    } -PassThru | Out-Null
    foreach ($sit in $Data.EndpointMetaData.SensitiveInfoTypeData) {
        $sitId = (New-Guid).Guid
        $sit | Add-Member -NotePropertyMembers @{
            Identifier                   = $Data.Id
            SITCount                     = $sit.Count
            SensitiveType                = $sit.SensitiveInfoTypeId
            SensitiveInformationTypeName = $sit.SensitiveInfoTypeName
            ClassificationAttributes     = $sit.SensitiveInformationDetailedClassificationAttributes
            SensitiveInfoId              = $sitId
        } -PassThru | Out-Null
        $sit.PSObject.Properties.Remove('Count')
        $sit.PSObject.Properties.Remove('SensitiveInformationDetailedClassificationAttributes')
        $sit.PSObject.Properties.Remove('SensitiveInfoTypeId')
        $sits.Add($sit) | Out-Null
        if ($Method -ne 'Remove') {
            foreach ($detection in $sit.SensitiveInformationDetectionsInfo) {
                foreach ($value in $detection.DetectedValues) {
                    if ($Method -eq 'Hash') {
                        $value.Name = Get-Hash -Value $value.Name
                        $value.Value = Get-Hash -Value $value.Value
                    }
                    $value | Add-Member -NotePropertyMembers @{
                        Identifier      = $Data.Id
                        SensitiveInfoId = $sitId            
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
$token = $oauth.access_token | ConvertTo-SecureString -AsPlainText

#$message = $queueitem | convertfrom-json
$content = $queueitem

if ($queueitem.count -eq 1) { $content = $queueitem | convertfrom-json }

foreach ( $url in $content) {
    $uri = $url + "?PublisherIdentifier=" + $TenantGUID
    $record = Test-Command {  
        Invoke-RestMethod -UseBasicParsing -Authentication Bearer -Token $token -Uri $uri
    } -Delay 10000
    $records += $record
}

$records.count

#Here starts the enrichment functionality and routing function.

#Make the GRAPH Call to get additional information, require different audience tag.
$resourceG = "https://graph.microsoft.com"
$bodyG = @{grant_type = "client_credentials"; resource = $resourceG; client_id = $ClientID; client_secret = $ClientSecret }
$oauthG = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantGUID/oauth2/token?api-version=1.0 -Body $bodyG 
$tokenG = $oauthG.access_token | ConvertTo-SecureString -AsPlainText

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
            if ($exuser) { $info = Invoke-RestMethod -Authentication Bearer -Token $tokenG -Uri $queryString -Method GET -SkipHttpErrorCheck }
            $info = $info.value

            #Add usage location from GRAPH Call
            $user | Add-Member -MemberType NoteProperty -Name "usageLocation" -Value $info.usageLocation
            if ($info) { 
                $user | Add-Member -MemberType NoteProperty -Name "department" -Value $info.department
                $user | Add-Member -MemberType NoteProperty -Name "jobTitle" -Value $info.jobTitle
            }

            #$querymanager = "https://graph.microsoft.com/v1.0/users/" + $exuser + "/manager"
            $querymanager = "https://graph.microsoft.com/v1.0/users/" + $info.userPrincipalName + "/manager"
            $manager = Invoke-RestMethod -Authentication Bearer -Token $tokenG -Uri $querymanager -SkipHttpErrorCheck
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
        $info = Invoke-RestMethod -Authentication Bearer -Token $tokenG -Uri "https://graph.microsoft.com/v1.0/users/$queryString" -Method GET -SkipHttpErrorCheck
        $user | Add-Member -MemberType NoteProperty -Name "usageLocation" -Value $info.usageLocation
        if ($info) { 
            $user | Add-Member -MemberType NoteProperty -Name "department" -Value $info.department
            $user | Add-Member -MemberType NoteProperty -Name "jobTitle" -Value $info.jobTitle
        }

        $querymanager = "https://graph.microsoft.com/v1.0/users/" + $user.SharePointMetaData.From + "/manager" 
        $manager = Invoke-RestMethod -Authentication Bearer -Token $tokenG -Uri $querymanager -SkipHttpErrorCheck
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
        $info = Invoke-RestMethod -Authentication Bearer -Token $tokenG -Uri "https://graph.microsoft.com/v1.0/users/$queryString" -Method GET -SkipHttpErrorCheck
        $user | Add-Member -MemberType NoteProperty -Name "usageLocation" -Value $info.usageLocation
        if ($info) { 
            $user | Add-Member -MemberType NoteProperty -Name "department" -Value $info.department
            $user | Add-Member -MemberType NoteProperty -Name "jobTitle" -Value $info.jobTitle
        }

        $querymanager = "https://graph.microsoft.com/v1.0/users/" + $user.UserKey + "/manager" 
        $manager = Invoke-RestMethod -Authentication Bearer -Token $tokenG -Uri $querymanager -SkipHttpErrorCheck
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
        $info = Invoke-RestMethod -Authentication Bearer -Token $tokenG -Uri "https://graph.microsoft.com/v1.0/users/$queryString" -Method GET -SkipHttpErrorCheck
        $user | Add-Member -MemberType NoteProperty -Name "usageLocation" -Value $info.usageLocation
        if ($info) { 
            $user | Add-Member -MemberType NoteProperty -Name "department" -Value $info.department
            $user | Add-Member -MemberType NoteProperty -Name "jobTitle" -Value $info.jobTitle
        }

        $querymanager = "https://graph.microsoft.com/v1.0/users/" + $user.UserId + "/manager" 
        $manager = Invoke-RestMethod -Authentication Bearer -Token $tokenG -Uri $querymanager -SkipHttpErrorCheck
        if ($manager) { $user | Add-Member -MemberType NoteProperty -Name "manager" -Value $manager.mail }

        if ($user.objectId) {
            $document = Split-Path $user.objectId -leaf
            $user | Add-Member -MemberType NoteProperty -Name "DocumentName" -Value $document
        }

        $powerbiupload += $user
        Clear-Variable -name info
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
    if ($detections.Count -gt 0) {
        Write-Host "Sending detection info:"
        Send-DataToAzureMonitorBatched -Data $detections -BatchSize 10000 -TableName ("Custom-$LogType" + "Detections_CL") -JsonDepth 100 -UamiClientId $uamiClientId -DceURI $dceUri -DcrImmutableId $dcrImmutableId -SortBySize $true -EventIdPropertyName 'Identifier'
    }
    
    Write-Host "Sending SIT info:"
    Send-DataToAzureMonitorBatched -Data $sits -BatchSize 10000 -TableName ("Custom-$LogType" + "SIT_CL") -JsonDepth 100 -UamiClientId $uamiClientId -DceURI $dceUri -DcrImmutableId $dcrImmutableId -SortBySize $true -EventIdPropertyName 'Identifier'
    
    Write-Host "Sending core event info:"
    Send-DataToAzureMonitorBatched -Data $allWS -BatchSize 10000 -TableName ("Custom-$LogType" + "_CL") -JsonDepth 100 -UamiClientId $uamiClientId -DceURI $dceUri -DcrImmutableId $dcrImmutableId -SortBySize $true -EventIdPropertyName 'Identifier'
}