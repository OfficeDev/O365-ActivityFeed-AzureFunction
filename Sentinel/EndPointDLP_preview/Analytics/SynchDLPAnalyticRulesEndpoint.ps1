# Input bindings are passed in via param block.
param($Timer)

#Path to the template file
$filepath = "d:\home\"
$dlpyamlfile = $filepath + "endpointruletemplate.yaml"

#Sentinel variables
$workspace = "$env:SentinelWorkspace"

$context = Get-AzContext
$profileR = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($profileR)
$token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
$authHeader = @{
  'Content-Type' = 'application/json'
  'Authorization' = 'Bearer ' + $token.AccessToken 
               }

$instance = Get-AzResource -Name $workspace -ResourceType Microsoft.OperationalInsights/workspaces

$processedPolicies = @()
$dlpyaml = Get-Content $dlpyamlfile

#Last Policy update
$lastpolicylog = "d:\home\lastendpointpolicy.log"
$lastpolicychange = Get-Content $lastpolicylog

#Exchange Credentials
$expass = $env:expass
$exuser = $env:exuser
$password = ConvertTo-SecureString $expass -AsPlainText -Force
$credentials=New-Object -TypeName System.Management.Automation.PSCredential ($exuser, $password)


#Connecting to SCC PowerShell
if ($credentials) {
$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri  https://ps.compliance.protection.outlook.com/powershell-liveid?BasicAuthToOAuthConversion=true -Credential $Credentials -Authentication Basic -AllowRedirection
                  }

if ($session) {Import-PSSession $session -CommandName Get-DlpComplianceRule  -AllowClobber -DisableNameChecking}

#Retreiving the DLP Policies in place 
$policies = Get-DlpCompliancerule | Where-Object workload -match "endpointdevices"

#Retreiving the Sentinel Analytic rules
$path = $instance.ResourceId
$urllist = "https://management.azure.com$path/providers/Microsoft.SecurityInsights/alertRules?api-version=2020-01-01"
$rules = Invoke-RestMethod -Method "Get" -Uri $urllist -Headers $authHeader

# Looping through the policies and create Analytic Rules in Sentinel
foreach ($policy in $policies) {

if (($processedPolicies -notcontains $policy.ReportSeverityLevel,$policy.ParentPolicyName) -and ((get-date $policy.whenChanged).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") -gt (get-date $lastpolicychange).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")))
                                  {

               #Updating with the severity and name of the Dlp Policy

        $policyName = $policy.ParentPolicyName + "_" + $policy.ReportSeverityLevel
        $updateyaml1 = $dlpyaml -replace "dlppolicyname", $policyName
        $updateyaml2 = $updateyaml1 -replace "dlppolicy", $policy.ParentPolicyName
        $updateyaml3 = $updateyaml2 -replace "ImmutableID", $policy.ImmutableId
        $updateyaml4 = $updateyaml3 -replace "UpdateSeverity", $policy.ReportSeverityLevel  


   $matchexisting = $rules.value | where-object  {$_.properties.displayname -eq $policyName + "_EndPoint"} | select-object

         if ($matchexisting) {
               $finalyaml = $updateyaml4 -replace "ruleGUID", ($matchexisting.etag -replace '"', "")
               $update = $matchexisting.name
               $urlupdate = "https://management.azure.com$path/providers/Microsoft.SecurityInsights/alertRules/$update" + '?api-version=2020-01-01'
               Invoke-RestMethod -Method "Put" -Uri $urlupdate -Headers $authHeader -body $finalyaml
                              }

         if (-not $matchexisting) {
               $etag = New-Guid
               $finalyaml = $updateyaml4 -replace "ruleGUID", $etag
               $update = $matchexisting.id
               $urlupdate = "https://management.azure.com$path/providers/Microsoft.SecurityInsights/alertRules/$etag" + '?api-version=2020-01-01'
               Invoke-RestMethod -Method "Put" -Uri $urlupdate -Headers $authHeader -body $finalyaml
                                  }  
            
          #Keep track of already processed rules by placing in array for if sentence
          $processedPolicies += $policy.ReportSeverityLevel,$policy.ParentPolicyName

Clear-Variable updateyaml1
Clear-Variable finalyaml

                                  }
$dlplastchange = $policies.whenChanged | Sort-Object -Descending
$dlplastchange[0] | Out-File $lastpolicylog -NoNewline                                  

                          }
Remove-PSSession $session
