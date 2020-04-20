# Input bindings are passed in via param block.
param($QueueItem, $TriggerMetadata)

# Replace with your Log Analytics Workspace ID
$CustomerId = $env:workspaceId

# Replace with your Log Analytics Primary Key
$SharedKey = $env:workspaceKey

# Specify the name of the record type that you'll be creating
$LogType = $env:customLogName

#SharePoint Site US
$SPUS = $env:SPUS


# You can use an optional field to specify the timestamp from the data. If the time field is not specified, Azure Monitor assumes the time is the message ingestion time
$TimeStampField = (Get-Date)

#Initiate Arrays used by the function
$records = @()
$exupload = @()
$spoupload = @()
$usWorkspace = @()

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
                            $record = Invoke-RestMethod -UseBasicParsing -Headers $headerParams -Uri $uri
   
   if (-not ($record)) {throw 'Failed to fetch the content blob'}
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
#Exchange and Teams upload data process
#!!!!Note!!! the code handles internal recipients sending outbound, need amendment to handle external users sending to recipients in the organization. 

$user.workload
if (($user.workload -eq "Exchange") -or ($user.Workload -eq "MicrosoftTeams")) {

$domain = $user.ExchangeMetaData.From.Split('@')

   if (($env:domains).split(",") -Contains $domain[1])   {
        
        #Add the additional attributes needed to enrich the event stored in Log Analytics for Exchange
        $queryString = "https://graph.microsoft.com/v1.0/users/" + $user.ExchangeMetaData.From + "?" + "$" + "select=usageLocation,Manager,department,state"       
        $info = Invoke-RestMethod -Headers $headerParamsG -Uri $queryString -Method GET

        #Add usage location from GRAPH Call
        $user | Add-Member -MemberType NoteProperty -Name "usageLocation" -Value $info.usageLocation

        #Add link to the location of the original content !!!! Remember to add per Geo depending on Geo
        $original = $user.ExchangeMetaData.MessageID -replace ("\<", "_") -replace ("\>", "_")
        $spousLocation = $SPUS + $original + ".eml"
        $spoSELocation = $SPUS + $original + ".eml"
        
        #Determine SPO Geo to point to this is pointing to the US sample, only Exchange provide full content
        if (($user.usageLocation -eq "US") -and ($user.workload -eq "Exchange"))  {$user | Add-Member -MemberType NoteProperty -Name "originalContent" -Value $spousLocation}
        if (($user.usageLocation -eq "SE") -and ($user.workload -eq "Exchange"))  {$user | Add-Member -MemberType NoteProperty -Name "originalContent" -Value $spoSELocation}
        Clear-Variable -name info    
                                                         }
$exupload += $user 

                                    }

#SharePoint and OneDrive upload data process
if (($user.Workload -eq "OneDrive") -or ($user.Workload -eq "SharePoint")) {

    #Add the additional attributes needed to enrich the event stored in Log Analytics for SharePoint
    $queryString = $user.SharePointMetaData.From + "?$" + "select=usageLocation,Manager,department,state"
    $info = Invoke-RestMethod -Headers $headerParamsG -Uri "https://graph.microsoft.com/v1.0/users/$queryString" -Method GET
    $user | Add-Member -MemberType NoteProperty -Name "usageLocation" -Value $info.usageLocation

$spoupload += $user
Clear-Variable -name info
                                                                            }
                             }    


#Determine which Sentinel Workspace to route the information, remember to define the variable for each workspace as an array.
foreach ($entry in $exupload)   {
        if ($entry.usageLocation -eq "US") { $usWorkspace += $entry  }
        if ($entry.usageLocation -eq "")   { $usWorkspace += $entry  } 
                                }
foreach ($entry in $spoupload)  {
        if ($entry.usageLocation -eq "US") { $usWorkspace += $entry  }    
        if ($entry.usageLocation -eq "")   { $usWorkspace += $entry  } 
                                }

#Upload US Workspace, to add addtional workspaces add the WorkspaceID and Workspacekey and make a new post based on those parameters
$jsonus = $usWorkspace | convertTo-Json -depth 20
Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($jsonus)) -logType $logType
