# Input bindings are passed in via param block.
param($QueueItem, $TriggerMetadata)

#Initiate Arrays used by the function
$records = @()
$exupload = @()
$spoupload = @()
$allWS = @()

$tolocal = @()

#Workspaces, mapping of country code to workspace, update county code, key and ID reference for multiple workspaces
#$maineu = @{"Countries" = "GB,ES,IT";"Workspacekey" = $env:workspaceKey; "Workspace" = $env:workspaceId}
#$Germany = @{"Countries" = "DE";"Workspacekey" = $env:workspaceKeyEU; "Workspace" = $env:workspaceIdEU}
#$LT = @{"Countries" = "LT";"Workspacekey" = $env:workspaceKeyEU; "Workspace" = $env:workspaceIdEU}

#List of Workspaces, update based on workspaces added
#$workspaces = @{"MainEU" = $maineu; "Germany" = $Germany; "LT" = $LT}

#All Content Workspace, used for the central team
$AllContent = @{"Countries" = "ALLContent";"Workspacekey" = $env:workspaceKey; "Workspace" = $env:workspaceId}


# Specify the name of the record type that you'll be creating
$LogType = $env:customLogName

# Specify the table used for Endpoint
$logTypeEndpoint = "endpointdlp"

#SharePoint Site US
$SPUS = $env:SPUS

#Retry logic primarily for AF429 where there is more than 60k requests per minute, much code reused from https://stackoverflow.com/questions/45470999/powershell-try-catch-and-retry
function Test-Command {
      [CmdletBinding()]
      Param(
          [Parameter(Position=0, Mandatory=$true)]
          [scriptblock]$ScriptBlock,
  
          [Parameter(Position=1, Mandatory=$false)]
          [int]$Maximum = 5,
  
          [Parameter(Position=2, Mandatory=$false)]
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
              } catch {
                  $fault = $_.Exception.InnerException.Message | convertfrom-json
                       Write-Error $_.Exception.InnerException.Message -ErrorAction Continue
                          if ($fault.error.code -eq "AF429") {Start-Sleep -Milliseconds $Delay}
                             else  {$cnt = $Maximum}
              }
          } while ($cnt -lt $Maximum)
          throw 'Execution failed.'
      }
  }

# You can use an optional field to specify the timestamp from the data. If the time field is not specified, Azure Monitor assumes the time is the message ingestion time
$TimeStampField = (Get-Date)

# Create the function to create the authorization signature
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
#        "x-ms-AzureResourceId" = $resourceId;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}


$clientID = "$env:clientID"
$clientSecret = "$env:clientSecret"
$loginURL = "https://login.microsoftonline.com"
$tenantdomain = "$env:tenantdomain"
$tenantGUID = "$env:TenantGuid"
$resource = "https://manage.office.com"


    # Get an Oauth 2 access token based on client id, secret and tenant domain
    $body = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}

    #oauthtoken in the header
    $oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body 
    $headerParams  = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}

#$message = $queueitem | convertfrom-json
$content = $queueitem


if ($queueitem.count -eq 1) {$content = $queueitem | convertfrom-json}

    foreach ( $url in $content)     
                          {
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
$bodyG = @{grant_type="client_credentials";resource=$resourceG;client_id=$ClientID;client_secret=$ClientSecret}
$oauthG = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $bodyG 
$headerParamsG  = @{'Authorization'="$($oauthG.token_type) $($oauthG.access_token)"}


Foreach ($user in $records) {
#Capture detection entries that are too long for LA to store
if (($user.PolicyDetails.rules.ConditionsMatched.SensitiveInformation.SensitiveInformationDetections.ResultsTruncated -eq "true") -or ($user.PolicyDetails.rules.ConditionsMatched.SensitiveInformation.SensitiveInformationDetections.Count -gt 150)) {
$detectedrows = $user.PolicyDetails.rules.ConditionsMatched.SensitiveInformation.SensitiveInformationDetections.DetectedValues.count
do      {
    $increment = [math]::truncate($detectedrows/2 )
    $detected = $user.PolicyDetails.rules.ConditionsMatched.SensitiveInformation.SensitiveInformationDetections.DetectedValues[0..$increment]
    $detectedcount = $detected.value | Measure-object -Character
    $detectedrows = [math]::truncate($increment*1.5)
        } until ($detectedcount.Characters -le "10240" )
            $user.PolicyDetails.rules.ConditionsMatched.SensitiveInformation.SensitiveInformationDetections.DetectedValues = $detected
                                                                                                                                  }

#Exchange and Teams upload data process
$user.workload
if (($user.workload -eq "Exchange" -and $user.operation -ne "MipLabel") -or ($user.Workload -eq "MicrosoftTeams")) {

 #Determine if the email is from external or internal if from external associate with first recipient on the to line
    if (($env:domains).split(",") -Contains ($user.ExchangeMetaData.from.Split('@'))[1]) {$exuser = $user.ExchangeMetaData.from}

    if ([string]::IsNullOrEmpty($exuser)) 
        {
          $tolocal = $user.ExchangeMetaData.to | select-string -pattern ($env:domains).split(",") -simplematch
          $exuser = $tolocal[0]
        }

#Avoiding enrichment for system messages that may have slipped through
    $systemMail = "no-reply@sharepointonline.com,noreply@email.teams.microsoft.com"
    if (($systemMail).split(",") -notcontains $exuser) {
        
        #Add the additional attributes needed to enrich the event stored in Log Analytics for Exchange
        $queryString = "https://graph.microsoft.com/v1.0/users/" + $exuser + "?" + "$" + "select=usageLocation,Manager,department,state"        
        $info = Invoke-RestMethod -Headers $headerParamsG -Uri $queryString -Method GET -SkipHttpErrorCheck

        #Add usage location from GRAPH Call
        $user | Add-Member -MemberType NoteProperty -Name "usageLocation" -Value $info.usageLocation
         if ($info) {$user | Add-Member -MemberType NoteProperty -Name "department" -Value $info.department}

        $querymanager = "https://graph.microsoft.com/v1.0/users/" + $exuser + "/manager"
        $manager = Invoke-RestMethod -Headers $headerParamsG -Uri $querymanager -SkipHttpErrorCheck
        if ($manager) {$user | Add-Member -MemberType NoteProperty -Name "manager" -Value $manager.mail}
        
    if ($user.workload -eq "Exchange") {

            #Add link to the location of the original content !!!! Remember to add per Geo depending on Geo
            $original = $user.ExchangeMetaData.MessageID -replace ("\<", "_") -replace ("\>", "_")
            $spousLocation = $SPUS + $user.PolicyDetails.rules.RuleName + "/" + $original + ".eml"
            $spoSELocation = $SPUS + $user.PolicyDetails.rules.RuleName +  "/" + $original + ".eml"
                
                #Determine SPO Geo to point to this is pointing to the US sample, only Exchange provide full content
                if (($user.usageLocation -eq "US") -and ($user.workload -eq "Exchange"))  {$user | Add-Member -MemberType NoteProperty -Name "originalContent" -Value $spousLocation}
                if (($user.usageLocation -ne "US") -and ($user.workload -eq "Exchange"))  {$user | Add-Member -MemberType NoteProperty -Name "originalContent" -Value $spousLocation}
   
                                                            }   
      Clear-Variable -name info                                                                                                         
                                                         }

$exupload += $user 
                                    }

#SharePoint and OneDrive upload data process
if (($user.Workload -eq "OneDrive") -or ($user.Workload -eq "SharePoint")) {

    #Add the additional attributes needed to enrich the event stored in Log Analytics for SharePoint
    $queryString = $user.SharePointMetaData.From + "?$" + "select=usageLocation,Manager,department,state"
    $info = Invoke-RestMethod -Headers $headerParamsG -Uri "https://graph.microsoft.com/v1.0/users/$queryString" -Method GET -SkipHttpErrorCheck
    $user | Add-Member -MemberType NoteProperty -Name "usageLocation" -Value $info.usageLocation
     if ($info) {$user | Add-Member -MemberType NoteProperty -Name "department" -Value $info.department}

        $querymanager = "https://graph.microsoft.com/v1.0/users/" + $user.SharePointMetaData.From + "/manager" 
        $manager = Invoke-RestMethod -Headers $headerParamsG -Uri $querymanager -SkipHttpErrorCheck
        if ($manager) {$user | Add-Member -MemberType NoteProperty -Name "manager" -Value $manager.mail}

$spoupload += $user
Clear-Variable -name info
                                                                            }
                            
#EndpointDLP upload
if (($user.Workload -eq "EndPoint") -and (($user.PolicyMatchInfo)))   {

    #Add the additional attributes needed to enrich the event stored
    $queryString = $user.UserKey + "?$" + "select=usageLocation,Manager,department,state"
    $info = Invoke-RestMethod -Headers $headerParamsG -Uri "https://graph.microsoft.com/v1.0/users/$queryString" -Method GET -SkipHttpErrorCheck
    $user | Add-Member -MemberType NoteProperty -Name "usageLocation" -Value $info.usageLocation
     if ($info) {$user | Add-Member -MemberType NoteProperty -Name "department" -Value $info.department}
     if ($user.objectId) {
         $document = Split-Path $user.objectId -leaf
         $user | Add-Member -MemberType NoteProperty -Name "DocumentName" -Value $document
                         }

$endpointupload += $user
Clear-Variable -name info
                                          }                            
                             }    



#Determine which Sentinel Workspace to route the information,
$uploadWS = @{}

if ($workspace) 
{
foreach ($workspace in $workspaces.GetEnumerator()) {
$uploadWS[$workspace.name] = @()

#Exchange and Teams
$uploadWS[$workspace.name] += $exupload | where-object  {$workspace.Value.Countries.split(",") -Contains $_.usageLocation}                                                          

#SharePoint and OneDrive
$uploadWS[$workspace.name] += $spoupload | where-object  {$workspace.Value.Countries.split(",") -Contains $_.usageLocation}       
                                
#EndPoint
$uploadWS[$workspace.name] += $endpointupload | where-object  {$workspace.Value.Countries.split(",") -Contains $_.usageLocation}    

                                                        }                  

#Upload to Workspaces

foreach ($workspace in $workspaces.GetEnumerator()) {
$activeWS = $workspace.name
if ($uploadWS.$activeWS) {
$json = $uploadWS.$activeWS |convertTo-Json -depth 100
Post-LogAnalyticsData -customerId $workspace.value.workspace -sharedKey $workspace.value.workspacekey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType
                        }

                                                    }
}                       
#Uploading everything to a unified Workspace
$allWS += $exupload
$allWS += $spoupload
$allWS += $endpointupload
$alljson = $allWS |convertTo-Json -depth 100
Post-LogAnalyticsData -customerId $AllContent.workspace -sharedKey $AllContent.workspacekey -body ([System.Text.Encoding]::UTF8.GetBytes($alljson)) -logType $logType
