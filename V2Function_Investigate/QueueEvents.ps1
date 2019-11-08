# Input bindings are passed in via param block.
param($Timer)

#Enumerators and object to wrap the objects
    $pageArray = @()
    $output= @()
    $msgarray = @()


#Sign in Parameters
$clientID = "YOUR CLIENT ID”
$clientSecret = "YOUR CLIENT SECRET"
$loginURL = "https://login.windows.net"
$tenantdomain = "YOUR TENANT"
$tenantGUID = "YOUR TENANT GUID"
$resource = "https://manage.office.com"

#Workloads and end time default is on start
$workloads = @("Audit.AzureActiveDirectory","Audit.SharePoint","Audit.Exchange","Audit.General","DLP.All")
$endTime = Get-date -format "yyyy-MM-ddTHH:mm:ss.fffZ"


#Storage Account Settings, this is needed to access the storage queue
$storageAccountName = "STORAGE ACCOUNTNAME"
$storageAccountKey = "STORAGE ACCOUNT KEY"
$storageQueue = 'STORAGE QUEUE NAME'

#Load the Storage Queue
$storeAuthContext = New-AzStorageContext $StorageAccountName -StorageAccountKey $StorageAccountKey
$myQueue = Get-AzStorageQueue -Name $storageQueue -Context $storeAuthContext
$messageSize = 10


Foreach ($workload in $workloads) {

$Tracker = "D:\home\$workload.log" # change to location of choise this is the root.
$StoredTime = Get-content $Tracker 
#$StoredTime = "2019-11-04T11:20:35.464Z"

    # Get an Oauth 2 access token based on client id, secret and tenant domain
    $body = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}

    #oauthtoken in the header
    $oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body 
    $headerParams  = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}

    #Make the request
    $rawRef = Invoke-WebRequest -Headers $headerParams -Uri "https://manage.office.com/api/v1.0/$tenantGUID/activity/feed/subscriptions/content?contenttype=$workload&startTime=$Storedtime&endTime=$endTime&&PublisherIdentifier=$TenantGUID" -UseBasicParsing
  
 
    #If more than one page is returned capture and return in pageArray

    if ($rawRef.Headers.NextPageUri) {

     
        $pageTracker = $true

        $pagedReq = $rawRef.Headers.NextPageUri



            while ($pageTracker -ne $false)

            

             {   
                    $pageuri = $pagedReq + "?PublisherIdentifier=" + $TenantGUID  
        	        $CurrentPage = Invoke-WebRequest -Headers $headerParams -Uri $pageuri -UseBasicParsing

                    $pageArray += $CurrentPage


                 if ($CurrentPage.Headers.NextPageUri)

                                {

                                $pageTracker = $true    

                                }

                                Else

                                        {

                                        $pageTracker = $false

                                        }

                                        $pagedReq = $CurrentPage.Headers.NextPageUri

                }

                                 } 

    $pageArray += $rawref

if ($pagearray.RawContentLength -gt 3) {

        foreach ($page in $pageArray)

        {

            $request = $page.content | convertfrom-json

 $runs = $request.Count/($messageSize +1)
 $writeSize = $messageSize
 $i = 0
              
        while ($runs -ge 1) { 
    
                        $rawmessage = $request[$i..$writeSize].contenturi 
                                       
                                foreach ($msg in $rawmessage){ 
                                                             $msgarray += @($msg) 
                                                             $message = $msgarray | convertto-json
                                                             }                     
                        
                        $queueMessage = New-Object -TypeName Microsoft.Azure.Storage.Queue.CloudQueueMessage -ArgumentList "$message"
                        $myqueue.CloudQueue.AddMessage($queuemessage)
               
                $runs -= 1
                $i+= $messageSize +1
                $writeSize += $messageSize + 1 
           
               
                Clear-Variable msgarray
                Clear-Variable message
                Clear-Variable rawMessage
                                    }   
         
         if ($runs -gt 0) {
                        
                        $rawMessage = $request[$i..$writeSize].contenturi 
                                foreach ($msg in $rawMessage){  
                                                                $msgarray += @($msg)
                                                                $message = $msgarray | convertto-json                                                        
                                                            }                                                           
                       
                        $runs -=1                                   
                       
                        $queueMessage = New-Object -TypeName Microsoft.WindowsAzure.Storage.Queue.CloudQueueMessage -ArgumentList "$message"
                        $myqueue.CloudQueue.AddMessage($queuemessage)

                        }

Clear-Variable rawMessage
Clear-Variable message
Clear-Variable msgarray 
                                  }
     $time = $pagearray[0].Content | convertfrom-json
     $Lastentry = $time[$Time.contentcreated.Count -1].contentCreated 
     if ($Lastentry -ge $storedTime) {out-file -FilePath $Tracker -NoNewline -InputObject (get-date $lastentry).Addseconds(1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")} 

         } 

Clear-Variable pagearray
Clear-Variable rawref -ErrorAction Ignore
Clear-Variable page -ErrorAction Ignore

        }
