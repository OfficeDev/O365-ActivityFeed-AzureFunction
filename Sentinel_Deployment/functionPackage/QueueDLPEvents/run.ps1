# Input bindings are passed in via param block.
param($Timer)

#Enumerators and object to wrap the objects
$pageArray = @()
$msgarray = @()

#Sign in Parameters
$clientID = "$env:clientID"
$clientSecret = "$env:clientSecret"
$loginURL = "https://login.microsoftonline.com"
$tenantGUID = "$env:TenantGuid"
$resource = "https://manage.office.com"

#Workloads and end time default is on start
$workloads = $env:contentTypes.split(",")
$endTime = Get-date -format "yyyy-MM-ddTHH:mm:ss.fffZ"

Foreach ($workload in $workloads) {
    #Storage Account Settings
    if ($workload -eq "dlp.all") { $storageQueue = "$env:storageQueue" }

    #Load the Storage Queue
    $storeAuthContext = New-AzStorageContext -ConnectionString $env:AzureWebJobsStorage
    $myQueue = Get-AzStorageQueue -Name $storageQueue -Context $storeAuthContext
    $messageSize = 10
    if (-not ($myQueue)) { throw 'Failed to connect to Storage Queue' }

    $Tracker = "D:\home\$workload.log" # change to location of choice this is the root.
    if ((Test-Path -Path $Tracker) -eq $true) {
        $storedTime = Get-content $Tracker
    }
    else {
        Write-Error "Time tracker log file not found, creating new file and using 1 minute lookback. If this is the very first run, this error can be ignored." -ErrorAction Continue
        $date = (Get-date).AddMinutes(-1).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        out-file d:\home\$workload.log -InputObject $date
        $storedTime = Get-content $Tracker
    }

    try {
        $adjustTime = New-TimeSpan -start $storedTime -End $endTime    
    }
    catch {
        throw "Unable to calculate start time. Ensure valid timestamp is in [workload].log file."
    }
    
    #If events are longer apart than 24 hours
    If ($adjustTime.TotalHours -gt 24) {
        $hours = $adjustTime.TotalHours - 23.9
        $storedTime = (get-date $storedTime).AddHours($hours)
    }

    # Get an Oauth 2 access token based on client id, secret and tenant domain
    $body = @{grant_type = "client_credentials"; resource = $resource; client_id = $ClientID; client_secret = $ClientSecret }

    #oauthtoken in the header
    $oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantGUID/oauth2/token?api-version=1.0 -Body $body 
    $token = $oauth.access_token | ConvertTo-SecureString -AsPlainText

    #Make the request
    try { $rawRef = Invoke-WebRequest -Authentication Bearer -Token $token -Uri "https://manage.office.com/api/v1.0/$tenantGUID/activity/feed/subscriptions/content?contenttype=$workload&startTime=$Storedtime&endTime=$endTime&PublisherIdentifier=$tenantGUID" -UseBasicParsing -RetryIntervalSec 2 -MaximumRetryCount 5 }
    catch { throw ("Error calling Office 365 Management API. " + $_.Exception) }
    
    if (-not ($rawRef)) { throw 'Failed to retrieve the content Blob Url' }
    
    #If more than one page is returned capture and return in pageArray
    if ($rawRef.Headers.NextPageUri) {
        $pageTracker = $true
        $pagedReq = $rawRef.Headers.NextPageUri
        while ($pageTracker -ne $false) {   
            $pageuri = "$pagedReq&PublisherIdentifier=$tenantGUID"
            try { $CurrentPage = Invoke-WebRequest -Authentication Bearer -Token $token -Uri $pageuri -UseBasicParsing -RetryIntervalSec 2 -MaximumRetryCount 5 }
            catch { throw ("Error calling Office 365 Management API. " + $_.Exception) }
            $pageArray += $CurrentPage
            if ($CurrentPage.Headers.NextPageUri) {
                $pageTracker = $true    
            }
            Else {
                $pageTracker = $false
            }
            $pagedReq = $CurrentPage.Headers.NextPageUri
        }
    } 

    $pageArray += $rawref

    if ($pagearray.RawContentLength -gt 3) {
        foreach ($page in $pageArray) {
            $request = $page.content | convertfrom-json
            $request
            # Setting up the paging of the Message queue adding +1 to avoid misconfiguration
            $runs = $request.Count / ($messageSize + 1)
            if (($runs -gt 0) -and ($runs -le "1") ) { $runs = 1 }
            $writeSize = $messageSize
            $i = 0            
            while ($runs -ge 1) { 
    
                if ($request.count -eq "1") { $rawmessage += $request.contenturi }
                Else { $rawmessage = $request[$i..$writeSize].contenturi }

                foreach ($msg in $rawmessage) { 
                    $msgarray += @($msg) 
                }    
                $message = $msgarray | convertto-json                
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($message)
                $messageBase64  =[Convert]::ToBase64String($bytes)
                $myQueue.QueueClient.SendMessage($messageBase64)
               
                $runs -= 1
                $i += $messageSize + 1
                $writeSize += $messageSize + 1      
               
                Clear-Variable msgarray
                Clear-Variable message
                Clear-Variable rawMessage
            }                                          
        }
        #Updating timers on success, registering the date from the latest entry returned from the API and adding 1 millisecond to avoid overlap
        $time = $pagearray[0].Content | convertfrom-json
        
        try {
            $Lastentry = (get-date ($time[$Time.contentcreated.Count - 1].contentCreated)).AddMilliseconds(1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")    
        }
        catch {
            throw "Unable to get date from last entry."
        }
        
        if ($Lastentry -ge $storedTime) { out-file -FilePath $Tracker -NoNewline -InputObject $Lastentry } 

    } 

    Clear-Variable pagearray
    Clear-Variable rawref -ErrorAction Ignore
    Clear-Variable page -ErrorAction Ignore
}