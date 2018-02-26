# This script will require the Web Application and permissions setup in Azure Active Directory
# This code should run within a scheduled Azure Function. The Tracker file defines from where to start

#You can use this to initialize the tracker file
#$Tracker = "D:\home\tracker.log" # change to location of choise
#$timerange= "{0:s}" -f (get-date).AddDays(-7) + "Z"
#out-file -FilePath $Tracker -NoNewline -InputObject $object.signinDateTime




$ClientID       = "YOUR CLIENT ID"             # Should be a ~35 character string insert your info here
$ClientSecret   = "YOUR CLIENT SECRET"         # Should be a ~44 character string insert your info here
$loginURL       = "https://login.microsoftonline.com/"
$tenantdomain   = "contoso.onmicrosoft.com"    #Provide your yourdomain.onmicrosoft.com 
$output         = $outputEventHubMessage  #This is the variable to define for the out put, this sample is an Event hub
$Tracker = "D:\home\tracker.log" # change to location of choise this is the root.

$Timerange = Get-content $Tracker

# Get an Oauth 2 access token based on client i, secret and tenant domain
$body       = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}

$oauth      = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body

if ($oauth.access_token -ne $null) {
$headerParams = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}

$url = "https://graph.windows.net/$tenantdomain/activities/signinEvents?api-version=beta&`$filter=signinDateTime ge $timerange"


Do{
   
    $myReport = (Invoke-RestMethod -Method Get -UseBasicParsing -Headers $headerParams -Uri $url )
        
    $url = ($myReport.value).'@odata.nextLink'
    
    #Sorting the array so that the most recent object is last
    $Report = $myreport.value | Sort-Object signinDateTimeInMillis, Index
    foreach ( $object in $Report) { 
    
                         $object | ConvertTo-Json | Out-File $output
                         out-file -FilePath $Tracker -NoNewline -InputObject $object.signinDateTime
    
                                 }
     
} while($url -ne $null)


} else {

    Write-Host "ERROR: No Access Token"
}