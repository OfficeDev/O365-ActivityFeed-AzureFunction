# Input bindings are passed in via param block.
param($Timer)

#Path to the template file
$filepath = "d:\home\"

#Define workloads array to be processed
$workloads = Get-Content .\SyncDLPAnalyticsRules\workloads.json  | ConvertFrom-Json

#Sentinel variables for workspaces update for each workspace to include
#$workspaceId0 = $env:SentinelWorkspaceUS
#$workspaceId1 = $env:SentinelWorkspaceEU
$workspaceId2 = $env:SentinelWorkspace
$main = @{"GlobalWorkspace" = $workspaceId2 }

foreach ($workload in $workloads) {
  $workloadAlias = $workload.Alias
  $ruleProcessLog = $filepath + $workloadAlias + 'Ruleprocess.log'
  if ((Test-Path -Path ($ruleProcessLog)) -eq $true) {
    $processedRules = get-content $ruleProcessLog
  }
  else {
    out-file $ruleProcessLog
    $processedRules = get-content $ruleProcessLog
  }

  foreach ($workspace in $main.GetEnumerator()) {
    $context = Get-AzContext
    $profileR = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($profileR)
    $token = ($profileClient.AcquireAccessToken($context.Subscription.TenantId)).AccessToken | ConvertTo-SecureString -AsPlainText
    $headers = @{
      'Content-Type'  = 'application/json'
    }
    $workspace.value
    Set-AzContext $context.Subscription.name
    $instance = Get-AzResource -Name $workspace.value -ResourceType Microsoft.OperationalInsights/workspaces
    $WorkspaceID = (Get-AzOperationalInsightsWorkspace -Name $instance.Name -ResourceGroupName $Instance.ResourceGroupName).CustomerID
      
    $workloadNames = '"' + ([string]$workload.Names).Replace(' ', '", "') + '"'
    # Get the DLP Policies in store
 
    $q = "PurviewDLP_CL
        | where TimeGenerated > ago(14d)
        | where Workload in ($workloadNames)
        | mv-expand PolicyDetails
        | extend Name = tostring(PolicyDetails.PolicyName)
        | where Name != ''
        | summarize by Name
        | project Name, Workload = '$workloadAlias'"

    $response = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $q
      
    #Get the Watchlist so that we don't store duplicates
    $q2 = "(_GetWatchlist('Policy') | where Workload == '$workloadAlias' | project SearchKey, Workload)"
    $watchlist = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $q2
      
    $policies = $response.results | Select-Object Name
      
    $processedPolicies = @()
      
    #Retreiving the Sentinel Analytic rules
    $path = $instance.ResourceId
    $urllist = "https://management.azure.com$($path)/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-04-01-preview"
    $rules = Invoke-RestMethod -Method "Get" -Uri $urllist -Headers $headers -Authentication Bearer -Token $token
      
    #Fetch Template
    $template0 = $rules.value | where-object { $_.properties.displayname -eq ("Microsoft DLP Incident Creation Template ($workloadAlias)") } | select-object
    $date = Get-Date
      
    if (-not ($rules)) { throw 'Failed to connect to Sentinel Workspace' }
    if (-not ($template0)) { throw 'Failed to retreive template' }
      
    # Looping through the policies and create Analytic Rules in Sentinel
    foreach ($policy in $policies) {
      $alreadyprocessed = $path + "," + $policy.Name 
      if ($processedRules -notcontains $alreadyprocessed) {
         
        $policyName = "Microsoft DLP - " + $policy.Name + " ($workloadAlias)"
        $matchexisting = $rules.value | where-object { $_.properties.displayname -eq $policyName } | select-object
        $template = $template0 | ConvertTo-Json -Depth 20 | ConvertFrom-Json
          
        if ($matchexisting) {
          $policy.name
          $template.properties.query = $template.properties.query -replace 'PolicyName != "" //Do Not Remove', "PolicyName == '$($policy.name)' and PolicyName has_any (PolicyWatchlist)"
          $pattern = '\| where not\(PolicyName has_any \(PolicyWatchlist\)\) //Do not remove'
          $template.properties.query = $template.properties.query -replace $pattern, "//This rule was updated by code $date"
          $template.properties.displayname = $matchexisting.properties.displayname
          $template.properties.enabled = $true
          $template.name = $matchexisting.name
          $template.etag = $matchexisting.etag
          $template.properties.displayname = $policyName
          $template.properties.lastModifiedUtc = ""
          $template.id = ""
          $update = $template | convertto-json -depth 20
          $update = $update -replace '"lastModifiedUtc": ""', ''
          $update = $update -replace '"id": "",', ""   
          $updateRule = $matchexisting.name
          $urlupdate = "https://management.azure.com$path/providers/Microsoft.SecurityInsights/alertRules/$updateRule" + '?api-version=2023-04-01-preview'
          $rule = Invoke-RestMethod -Method "Put" -Uri $urlupdate -Headers $headers -Authentication Bearer -Token $token -body $update
        }
      
        if (-not $matchexisting) {
          $etag = New-Guid
          $template.properties.query = $template.properties.query -replace 'PolicyName != "" //Do Not Remove', "PolicyName == '$($policy.Name)' and PolicyName has_any (PolicyWatchlist)"
          $pattern = '\| where not\(PolicyName has_any \(PolicyWatchlist\)\) //Do not remove'
          $template.properties.query = $template.properties.query -replace $pattern, "//This rule was created by code $date"
          $template.properties.displayname = $policyName
          $template.properties.enabled = $true
          $template.etag = $etag.guid
          $template.name = $etag.guid
          $template.properties.lastModifiedUtc = ""
          $template.id = ""
          $update = $template | convertto-json -depth 20
          $update = $update -replace '"lastModifiedUtc": ""', ''
          $update = $update -replace '"id": "",', ""   
          $urlupdate = "https://management.azure.com$path/providers/Microsoft.SecurityInsights/alertRules/$($etag.guid)" + '?api-version=2023-04-01-preview'
          $rule = Invoke-RestMethod -Method "Put" -Uri $urlupdate -Headers $headers -Authentication Bearer -Token $token -body $update
        }
                  
        #Keep track of already processed rules by placing in array for if sentence
        $processedPolicies += $policy.Name
      
        #Keep track of workspaces and rules processed
        $track = $path + "," + $policy.Name
        $track
        $track | Out-File -Append -FilePath $ruleProcessLog
      
        Clear-Variable matchexisting
      
      }
    }
    $rule.count
        
    $dlplastchange = $policies.whenChanged | Sort-Object -Descending                          

    # Watchlist update                            
    $csv = $response.Results 

    foreach ($item in $csv) {
      if ($item.Name -notin $watchlist.results.SearchKey -and $item.Workload -notin $watchlist.results.Workload) {
        $etag = New-Guid
        $a = @{
          'etag'       = $etag.guid
          'properties' = @{itemsKeyValue = @() }
        }           
        $a.properties.itemsKeyValue = $item  
        $update = $a | convertto-json    
        $urlupdate = "https://management.azure.com$path/providers/Microsoft.SecurityInsights/watchlists/Policy/watchlistitems/$($etag)?api-version=2023-04-01-preview"
        Invoke-RestMethod -Method "Put" -Uri $urlupdate -Headers $headers -Authentication Bearer -Token $token -body $update
      }
    }
  }
}
