# Input bindings are passed in via param block.
param($QueueItem, $TriggerMetadata)   

#Sign in Parameters
$clientID = "YOUR CLIENT ID”
$clientSecret = "YOUR CLIENT SECRET"
$loginURL = "https://login.windows.net"
$tenantdomain = "YOUR TENANT"
$tenantGUID = "YOUR TENANT GUID"
$resource = "https://manage.office.com"
   
   
    # Get an Oauth 2 access token based on client id, secret and tenant domain
    $body = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}

    #oauthtoken in the header
    $oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body 
    $headerParams  = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}

$queueitem.count

    if ($queueitem.count -eq "1") 
    
                                {
                                $item = $queueitem | convertfrom-json
                                $uri = $item + "?PublisherIdentifier=" + $TenantGUID  
                                $records = Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $uri
                                Push-OutputBinding -Name outputDocument -value $records.content -clobber
                                }

elseif ($queueitem.count -gt "1") {
    
    foreach ( $content in $queueitem)     
                          {
                            $uri = $content + "?PublisherIdentifier=" + $TenantGUID  
                            $records = Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $uri
                            Push-OutputBinding -Name outputDocument -value $records.content -clobber
                          }
                                  }
