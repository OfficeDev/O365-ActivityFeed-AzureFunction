param([string]$csvfile,[string]$Watchlist,[string]$Workspace,[string]$errlog)

if ($csvfile -eq "") {$csvfile = Read-Host "Provide path to csv import" -asString}
if ($errlog -eq "") {$errlog = Read-Host "Provide path to csv import" -asString}
if ($Watchlist -eq "")  {$Watchlist = Read-Host "Provide Watchlist" -asString}
if ($Worksapce -eq "")  {$Workspace = Read-Host "Provide Watchlist" -asString}

$csv = Import-Csv $csvfile

Connect-AzAccount
$context = Get-AzContext
$profileR = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($profileR)
$token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
$authHeader = @{
  'Content-Type' = 'application/json'
  'Authorization' = 'Bearer ' + $token.AccessToken 
               }
$workspace.value
$instance = Get-AzResource -Name $Workspace -ResourceType Microsoft.OperationalInsights/workspaces


#Retreiving the current watchlist
$path = $instance.ResourceId
$wlists = "https://management.azure.com$path/providers/Microsoft.SecurityInsights/watchlists?api-version=2021-09-01-preview"
$watchlists = Invoke-RestMethod -Method "Get" -Uri $wlists -Headers $authHeader
$watchlistname = $watchlists.value.properties | where watchlistAlias -like $Watchlist   
$listwitems = "https://management.azure.com$path/providers/Microsoft.SecurityInsights/watchlists/$($watchlistname.displayName)/watchlistitems?api-version=2021-09-01-preview"
$witems = Invoke-RestMethod -Method "Get" -Uri $listwitems -Headers $authHeader
     if (-not ($witems)) {throw 'Failed to connect to Sentinel Workspace'}

# Looping through the policies and create Analytic Rules in Sentinel
$errcnt = $error.count 
$errors = @()
foreach ($item in $csv) {

   $matchexisting = $witems.value | where-object  {$_.properties.itemsKeyValue.userPrincipalName -contains $item.userPrincipalName } | select-object

         if ($matchexisting) {
           $etag = $matchexisting[0].name

            $a= @{
                'etag'= $etag
                'properties'= @{itemsKeyValue = @()}
                }
                $a.properties.itemsKeyValue = $item  
            $update = $a | convertto-json    

            $urlupdate = "https://management.azure.com$path/providers/Microsoft.SecurityInsights/watchlists/UserAccounts/watchlistitems/$($matchexisting[0].name)?api-version=2021-03-01-preview"
            Invoke-RestMethod -Method "Put" -Uri $urlupdate -Headers $authHeader -body $update
                              }

         if (-not $matchexisting) {
               $etag = New-Guid
               $a= @{
                'etag'= $etag
                'properties'= @{itemsKeyValue = @()}
                }
                
                $a.properties.itemsKeyValue = $item  
                $update = $a | convertto-json    

            $urlupdate = "https://management.azure.com$path/providers/Microsoft.SecurityInsights/watchlists/UserAccounts/watchlistitems/$($etag)?api-version=2021-03-01-preview"
            Invoke-RestMethod -Method "Put" -Uri $urlupdate -Headers $authHeader -body $update

                                    }
                                    if ($error.count -gt $errcnt) {$errors += $item.userPrincipalName.ToString(), $error[$errcnt-1].ToString()}
Clear-Variable matchexisting   
Clear-Variable etag    
Clear-Variable a     
Clear-Variable update                                
                            }

if ($errors) {$errors | Out-File -FilePath $errlog} 
