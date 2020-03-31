# Input bindings are passed in via param block.
param([string] $Timer)

#Number of events written per batch to log analytics
$messageSize = 10000

# Replace with your Log Analytics Workspace ID
$CustomerId = $env:workspaceId

# Replace with your Log Analytics Primary Key
$SharedKey = $env:workspaceKey

# Specify the name of the record type that you'll be creating
$LogType = $env:customLogName

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
$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/PowerShell-LiveId?BasicAuthToOAuthConversion=true -Credential $Credentials -Authentication Basic -AllowRedirection
                   }

if ($session) {Import-PSSession $session -CommandName Get-MessageTrace  -AllowClobber -DisableNameChecking}

#This sets the start and stop time, $tracker is read from the last time the function was run. (It will fail on the first run.)
$tracker = "D:\home\timetracker.log" # change to location of choise this is the root.
$startTime = Get-date -format "yyyy-MM-ddTHH:mm:ss.fffZ"

#After first run remark the configured date 
#$storedTime = Get-content $Tracker
$storedTime = "2020-03-01T11:20:35.464Z"

#Run the message trace
$messagetrace = Get-MessageTrace -EndDate $startTime  -startdate $storedTime

#Store the information in loganalytics
$messagetrace.count
$runs = $messagetrace.Count/$messageSize

 if (($runs -gt 0) -and ($runs -le "1") ) {$runs=1}
 $runs
 $writeSize = $messageSize
 $i = 0
        while ($runs -ge 1) { 
    
                    $pagedrecord = $messagetrace[$i..$writeSize] 
                    $pagedjson = $pagedrecord | convertTo-Json
                    Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($pagedjson)) -logType $logType                          
                                    
           $runs -= 1
           $i+= $messageSize +1
           $writeSize += $messageSize + 1 
                        
           Clear-Variable pagedrecord
           Clear-Variable pagedjson
                                   
                                    }   

#Update stored time and remove session
$storedTime = $startTime
out-file -FilePath $Tracker -NoNewline -InputObject (get-date $storedTime).AddMilliseconds(1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") 
remove-PSSession $session                          

