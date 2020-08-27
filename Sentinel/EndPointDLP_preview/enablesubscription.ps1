param($Enablement)

#Enable the Activity API Subscriptions
$clientID = "$env:clientID"
$clientSecret = "$env:clientSecret"
$loginURL = "https://login.microsoftonline.com"
$tenantdomain = "$env:tenantdomain"
$tenantGUID = "$env:TenantGuid"
$resource = "https://manage.office.com"
$date = Get-date -format "yyyy-MM-ddTHH:mm:ss.fffZ"
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


#Generates the time stamp for the ingestion
out-file d:\home\dlp.All.log -InputObject $date
out-file d:\home\audit.general.log -InputObject $date
out-file d:\home\oldendpoint.log -InputObject $date
