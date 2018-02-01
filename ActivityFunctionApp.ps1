#Enumerators and object to wrap the incoming request
    $pageArray = @()
    $rawreq = @()
    $rawreq = New-Object -TypeName psobject
    $rawreq | Add-Member -name Content -value Content -membertype noteproperty

#Retrieve the content URI
    $requestbody = Get-Content $req -Raw | ConvertFrom-Json
    $rawreq.content  = $requestbody | convertto-json
   
#Activity Feed webhook Body to process
    $contenttype = $requestBody.contenttype
    #$tenantguid = $requestBody.tenantid
    $clientIdIn = $requestBody.clientid
    $contentId = $requestBody.contentid
    $contentUri = $requestBody.contentUri
    $contentCreated = $requestBody.contentCreated
    $contentExpiration = $requestBody.contentExpiration

#Sign in Parameters
$ClientID = "YOUR CLIENT ID A HEX”
$ClientSecret = "YOUR CLIENT SECRET
$loginURL = "https://login.windows.net"
$tenantdomain = "YOURDOMAIN.onmicrosoft.com"
$TenantGUID = "YOUR TenantGUID HEX"
$resource = "https://manage.office.com"


#Verify that it is the correct ID and import to Cosmos DB
if ($clientIdIn -eq $ClientId ) 
    {
    
    # Get an Oauth 2 access token based on client id, secret and tenant domain
    $body = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}

    #oauthtoken in the header
    $oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body 
    $headerParams  = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}
      
    #If more than one page is returned capture and return in pageArray
    if ($REQ_HEADERS_NextPageUri) {
     
        $pageTracker = $true
        $pagedReq = $REQ_HEADERS_NextPageUri

            while ($pageTracker -ne $false)
            
             {   
        	$CurrentPage = Invoke-WebRequest -Headers $headerParams -Uri $pagedReq -UseBasicParsing
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
    
    
    $pageArray += $rawreq

    foreach ($page in $pageArray)
   
    {

    $request = $page.content | ConvertFrom-Json
                                       

    foreach ( $content in $request)     
        {
        $uri = $content.contentUri + "?PublisherIdentifier=" + $TenantGUID  
        Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $uri -PassThru -OutFile $outputdocument
        }
 
    }

    }
 
Out-File -Encoding Ascii -FilePath $res -inputObject "200 OK"  
