# Input bindings are passed in via param block.
param($Timer)

#Path to the template file
$filepath = "d:\home\"

#Sentinel variables for workspaces update for each workspace to include
#$workspaceId0 = $env:SentinelWorkspaceUS
#$workspaceId1 = $env:SentinelWorkspaceEU
$workspaceId2 = $env:SentinelWorkspace
$maineu = @{"GlobalWorkspace" = $workspaceId2}

#Path for logging of rule progress
$EXOruleprocesslog = $filepath + "EXORuleprocess.log"
$EXOprocessedrules = get-content $EXOruleprocesslog


foreach ($workspace in $maineu.GetEnumerator()) {

$context = Get-AzContext
$profileR = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($profileR)
$token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
$authHeader = @{
  'Content-Type' = 'application/json'
  'Authorization' = 'Bearer ' + $token.AccessToken 
               }
$workspace.value
Set-AzContext $context.Subscription.name
$instance = Get-AzResource -Name $workspace.value -ResourceType Microsoft.OperationalInsights/workspaces

$WorkspaceID = (Get-AzOperationalInsightsWorkspace -Name $instance.Name -ResourceGroupName $Instance.ResourceGroupName).CustomerID

# Get the DLP Policies in store
$q = 'PurviewDLP_CL
| where TimeGenerated > ago(90d)
| extend Name = tostring(PolicyDetails[0].PolicyName)
| where Name != ""
| summarize by Name,Workload'
$response = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $q

#Get the Watchlist so that we don't store duplicates
$q2 = '(_GetWatchlist("Policy") | project SearchKey)'
$watchlist = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $q2

$policies = $response.results | where {($_.Workload -contains "Exchange") -or ($_.Workload -contains "MicrosoftTeams")}
$policies = $policies | Select-Object -Unique Name  

$processedPolicies = @()

#Retreiving the Sentinel Analytic rules
$path = $instance.ResourceId
$urllist = "https://management.azure.com$($path)/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-04-01-preview"
$rules = Invoke-RestMethod -Method "Get" -Uri $urllist -Headers $authHeader

#Fetch Template
$template0 =  $rules.value | where-object  {$_.properties.displayname -eq "Template_email_teams"} | select-object

     if (-not ($rules)) {throw 'Failed to connect to Sentinel Workspace'}
     if (-not ($template0)) {throw 'Failed to retreive template'}
# Looping through the policies and create Analytic Rules in Sentinel
foreach ($policy in $policies) {
    $alreadyprocessed = $path + "," + $policy.Name 
    $alreadyprocessed
    if ($EXOprocessedrules -notcontains $alreadyprocessed)   {

   $matchexisting = $rules.value | where-object  {$_.properties.displayname -eq $policy.Name} | select-object
    
    # Deep copy of template
     $template = $template0 | ConvertTo-Json -Depth 20 | ConvertFrom-Json
     $date = Get-Date
         
         if ($matchexisting) {
            $template.properties.query = $template.properties.query -replace 'Policy != "" //Do Not Remove',  "Policy == '$($policy.name)'"
            $pattern = '\| where not\(Policy has_any \(policywatchlist\)\) //Do not remove'
            $template.properties.query = $template.properties.query -replace $pattern, "//This rule was updated by code $date"
            $template.properties.displayname = $matchexisting.properties.displayname
            $template.properties.enabled = $true
            $template.name =  $matchexisting.name
            $template.etag = $matchexisting.etag
            $template.properties.displayname = $policy.name
            $template.properties.lastModifiedUtc = ""
            $template.id = ""
                $update = $template | convertto-json -depth 20
                $update = $update -replace '"lastModifiedUtc": ""',''
                $update = $update -replace '"id": "",', ""   
                    $updateRule = $matchexisting.name
                    $urlupdate = "https://management.azure.com$path/providers/Microsoft.SecurityInsights/alertRules/$updateRule" + '?api-version=2023-04-01-preview'
                    $rule = Invoke-RestMethod -Method "Put" -Uri $urlupdate -Headers $authHeader -body $update
                              }

         if (-not $matchexisting) {
            $etag = New-Guid
            $template.properties.query = $template.properties.query -replace 'Policy != "" //Do Not Remove',  "Policy == '$($policy.name)'"
            $pattern = '\| where not\(Policy has_any \(_GetWatchlist\(\"Policy\"\)\)\) //Do not remove'
            $template.properties.query = $template.properties.query -replace $pattern, "//This rule was created by code $date"
            $template.properties.displayname = $policy.name
            $template.properties.enabled = $true
            $template.etag =  $etag.guid
            $template.name =  $etag.guid
            $template.properties.lastModifiedUtc = ""
            $template.id = ""
                $update = $template | convertto-json -depth 20
                $update = $update -replace '"lastModifiedUtc": ""',''
                $update = $update -replace '"id": "",', ""   
                    $urlupdate = "https://management.azure.com$path/providers/Microsoft.SecurityInsights/alertRules/$($etag.guid)" + '?api-version=2023-04-01-preview'
                    $rule = Invoke-RestMethod -Method "Put" -Uri $urlupdate -Headers $authHeader -body $update
                                  }
            
          #Keep track of already processed rules by placing in array for if sentence
          $processedPolicies += $policy.Name
        
          #Keep track of workspaces and rules processed
          $track = $path + "," + $policy.Name
          $track
          $track | Out-File -Append -FilePath $EXOruleprocesslog


Clear-Variable matchexisting

                                }
                                    } 
Clear-Variable processedPolicies   
$rule.count                                  
                            }                            

# Watchlist update                            
$csv = $response.Results 

foreach ($item in $csv) {
if ($item.Name -notin $watchlist.results.SearchKey) {
 $etag = New-Guid
               $a= @{
                'etag'= $etag.guid
                'properties'= @{itemsKeyValue = @()}
                    }           
                $a.properties.itemsKeyValue = $item  
                $update = $a | convertto-json    
            $urlupdate = "https://management.azure.com$path/providers/Microsoft.SecurityInsights/watchlists/Policy/watchlistitems/$($etag)?api-version=2023-04-01-preview"
            Invoke-RestMethod -Method "Put" -Uri $urlupdate -Headers $authHeader -body $update
                                            }
                        }