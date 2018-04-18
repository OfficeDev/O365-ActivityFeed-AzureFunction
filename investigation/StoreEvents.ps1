#Input from the Message queue on trigger
$rawRequest = Get-Content $triggerInput

#Sign in Parameters
$clientID = "YOUR CLIENT ID”
$clientSecret = "YOUR CLIENT SECRET"
$loginURL = "https://login.windows.net"
$tenantdomain = "YOUR TENANT"
$tenantGUID = "YOUR TENANT GUID"
$resource = "https://manage.office.com"

    # Get an Oauth 2 access token based on client id, secret and tenant domain
    $body = @{grant_type="client_credentials";resource=$resource;client_id=$clientID;client_secret=$clientSecret}

    #oauthtoken in the header
    $oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body 
    $headerParams  = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}
 
$request = $rawRequest | ConvertFrom-Json

    foreach ( $content in $request)     
       {
        $uri = $content + "?PublisherIdentifier=" + $tenantGUID  
        Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $uri -PassThru -OutFile $outputdocument
       }
