# Input bindings are passed in via param block.
param($Timer)

#Sign in Parameters
$clientID = "$env:clientID"
$clientSecret = "$env:clientSecret"
$loginURL = "https://login.microsoftonline.com"
$tenantdomain = "$env:tenantdomain"
$tenantGUID = "$env:TenantGuid"
$resource = "https://graph.microsoft.com"

# Get an Oauth 2 access token based on client id, secret and tenant domain
$body = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}
$oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body

#Let's put the oauth token in the header, where it belongs
$headerParams  = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}

#Code to sign-in to Sentinel
$context = Get-AzContext
$profileR = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($profileR)
$token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
$authHeader = @{
  'Content-Type' = 'application/json'
  'Authorization' = 'Bearer ' + $token.AccessToken 
               }

Set-AzContext $context.Subscription.name
$instance = Get-AzResource -Name $env:SentinelWorkspace -ResourceType Microsoft.OperationalInsights/workspaces
$WorkspaceID = (Get-AzOperationalInsightsWorkspace -Name $instance.Name -ResourceGroupName $Instance.ResourceGroupName).CustomerID

#Get the Watchlist so that we don't store duplicates
$q2 = '(_GetWatchlist("SensitivityLabels") | project SearchKey)'
$watchlist = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $q2

#Fetch the labels and prepare for export
$labels = Invoke-RestMethod -Headers $headerParams -Uri "https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels" -Method Get -ContentType "application/json"
$sLabels = $labels.value | select id,name,@{N='parent';E={$_.parent.name}}  

# Watchlist update 
$path = $instance.ResourceId                           
$csv = $sLabels

foreach ($item in $csv) {
if ($item.id -notin $watchlist.results.SearchKey) {
 $etag = New-Guid
               $a= @{
                'etag'= $etag.guid
                'properties'= @{itemsKeyValue = @()}
                    }           
                $a.properties.itemsKeyValue = $item  
                $update = $a | convertto-json    
            $urlupdate = "https://management.azure.com$path/providers/Microsoft.SecurityInsights/watchlists/SensitivityLabels/watchlistitems/$($etag)?api-version=2023-04-01-preview"
            Invoke-RestMethod -Method "Put" -Uri $urlupdate -Headers $authHeader -body $update
                                            }
                        }