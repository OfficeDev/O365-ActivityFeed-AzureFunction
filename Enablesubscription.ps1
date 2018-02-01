#Sign in Parameters
$ClientID = "YOUR CLIENT ID A HEX”
$ClientSecret = "YOUR CLIENT SECRET
$loginURL = "https://login.windows.net"
$tenantdomain = "YOURDOMAIN.onmicrosoft.com"
$TenantGUID = "YOUR TenantGUID HEX"
$resource = "https://manage.office.com"

#Provide the Azure Function address and change the authid to your TenantGUID
$webhookadr = "YOUR WEBHOOK ADDRESS HERE”
$authid = "YOUR TENANT GUID UNLESS YOU HAVE A DEV GUID"
$webhookparam = @{address=$webhookadr;authid=$authid;expiration=""}
$webhook = @{ 'Webhook' = $webhookparam}
$webhookbody = $webhook |ConvertTo-Json

# Get an Oauth 2 access token based on client id, secret and tenant domain
$body = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}
$oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body

#Let's put the oauth token in the header, where it belongs
$headerParams  = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}


#Let's make sure the subscriptions are startedh
Invoke-RestMethod -Method Post -Headers $headerParams -Body $webhookbody -Uri "https://manage.office.com/api/v1.0/$tenantGUID/activity/feed/subscriptions/start?contentType=Audit.AzureActiveDirectory" -ContentType "application/json; charset=utf-8"
Invoke-RestMethod -Method Post -Headers $headerParams -Body $webhookbody -Uri "https://manage.office.com/api/v1.0/$tenantGUID/activity/feed/subscriptions/start?contentType=Audit.Exchange" -ContentType "application/json; charset=utf-8"
Invoke-RestMethod -Method Post -Headers $headerParams -Body $webhookbody -Uri "https://manage.office.com/api/v1.0/$tenantGUID/activity/feed/subscriptions/start?contentType=Audit.SharePoint" -ContentType "application/json; charset=utf-8"
Invoke-RestMethod -Method Post -Headers $headerParams -Body $webhookbody -Uri "https://manage.office.com/api/v1.0/$tenantGUID/activity/feed/subscriptions/start?contentType=Audit.General" -ContentType "application/json; charset=utf-8"
Invoke-RestMethod -Method Post -Headers $headerParams -Body $webhookbody -Uri "https://manage.office.com/api/v1.0/$tenantGUID/activity/feed/subscriptions/start?contentType=DLP.All" -ContentType "application/json; charset=utf-8"
