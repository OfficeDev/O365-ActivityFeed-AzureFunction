# Input bindings are passed in via param block.
param([string] $Timer)

#Workspaces, mapping of country code to workspace, update county code, key and ID reference for multiple workspaces
#$maineu = @{"Countries" = "US,ES,IT";"Workspacekey" = $env:workspaceKey; "Workspace" = $env:workspaceId}
#$Germany = @{"Countries" = "DE,GB,SE";"Workspacekey" = $env:workspaceKeyEU; "Workspace" = $env:workspaceIdEU}
#$LT = @{"Countries" = "LT";"Workspacekey" = $env:workspaceKeyEU; "Workspace" = $env:workspaceIdEU}
$AllContent = @{"Countries" = "ALLContent";"Workspacekey" = $env:workspaceKey; "Workspace" = $env:workspaceId}

#List of Workspaces, update based on workspaces added
$workspaces = @{"Main" = $AllContent}


# Specify the name of the record type that you'll be creating
$LogType = "DLPSensitivity"

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


#This is the Exchange extraction portion of the code

$expass = $env:expass
$exuser = $env:exuser
$password = ConvertTo-SecureString $expass -AsPlainText -Force
$credentials=New-Object -TypeName System.Management.Automation.PSCredential ($exuser, $password)

if ($credentials) {
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri  https://ps.compliance.protection.outlook.com/powershell-liveid?BasicAuthToOAuthConversion=true -Credential $Credentials -Authentication Basic -AllowRedirection
                   }
    if (-not ($session)) {throw 'Failed to connect to Exchange Online PowerShell'}

if ($session) {Import-PSSession $session -CommandName Get-DlpSensitiveInformationType,Get-Label -AllowClobber -DisableNameChecking}

                $mapping = Get-DlpSensitiveInformationType | select Id,name,Publisher | ConvertTo-Json
                $labelmap = Get-Label | select ImmutableId,DisplayName | ConvertTo-Json

#Upload to Workspaces
foreach ($workspace in $workspaces.GetEnumerator()) {
                     Post-LogAnalyticsData -customerId $workspace.value.workspace -sharedKey $workspace.value.workspacekey -body ([System.Text.Encoding]::UTF8.GetBytes($mapping)) -logType $logType  
                     Post-LogAnalyticsData -customerId $workspace.value.workspace -sharedKey $workspace.value.workspacekey -body ([System.Text.Encoding]::UTF8.GetBytes($labelmap)) -logType "miplabel"  
                                                      }
#Update stored time and remove session
remove-PSSession $session    