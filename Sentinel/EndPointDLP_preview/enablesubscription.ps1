param($Enablement)

#Enable the Activity API Subscriptions
$clientID = "$env:clientID"
$clientSecret = "$env:clientSecret"
$loginURL = "https://login.microsoftonline.com"
$tenantdomain = "$env:tenantdomain"
$tenantGUID = "$env:TenantGuid"
$resource = "https://manage.office.com"
$date = Get-date -format "yyyy-MM-ddTHH:mm:ss.fffZ"

#Adding the yaml files used as templates for the analytic rules, added to d:\home to match the analytics synch scripts
$officedlp1 =@{"URL" = "https://raw.githubusercontent.com/OfficeDev/O365-ActivityFeed-AzureFunction/master/Sentinel/EndPointDLP_preview/Analytics/endpointruletemplate.yaml"; "file" = "endpointruletemplate.yaml"}
$officedlp = @{"URL"= "https://raw.githubusercontent.com/OfficeDev/O365-ActivityFeed-AzureFunction/master/Sentinel/AnalyticsRule/ruletemplate.yaml"; "file" = "ruletemplate.yaml"} 
$Dlpdepend = $($officedlp,$officedlp1)

foreach ($template in $Dlpdepend) {
$webclient = New-Object System.Net.WebClient
$filepath = "d:\home\" + $template.file.ToString()
$filepath
$template.url.ToString()
$webclient.DownloadFile($template.url.ToString(),$filepath)
                                 }


# Get an Oauth 2 access token based on client id, secret and tenant domain
$body = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}
$oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body
#Let's put the oauth token in the header
$headerParams  = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}
#Start Subscriptions
Invoke-RestMethod -Method Post -Headers $headerParams -Uri "https://manage.office.com/api/v1.0/$tenantGUID/activity/feed/subscriptions/start?contentType=DLP.All"
Invoke-RestMethod -Method Post -Headers $headerParams -Uri "https://manage.office.com/api/v1.0/$tenantGUID/activity/feed/subscriptions/start?contentType=audit.general"
#List the active subscriptions
Invoke-RestMethod -Headers $headerParams -Uri "https://manage.office.com/api/v1.0/$tenantGUID/activity/feed/subscriptions/list"

#Sets up the Message Queue
$storeAuthContext = New-AzStorageContext -ConnectionString $env:AzureWebJobsStorage
New-AzStorageQueue -Name $env:storageQueue -context $storeAuthContext
New-AzStorageQueue -Name $env:endpointstorageQueue -context $storeAuthContext

$distantdate = "2005-08-18T15:32:04.000Z"

#Generates the time stamp for the ingestion
out-file d:\home\dlp.All.log -InputObject $date
out-file d:\home\audit.general.log -InputObject $date
out-file d:\home\lastofficepolicy.log -InputObject $distantdate -NoNewline
out-file d:\home\lastendpointpolicy.log -InputObject $distantdate -NoNewline

