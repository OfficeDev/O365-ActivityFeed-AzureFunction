# Input bindings are passed in via param block.
param($Timer)

#Path to the template file
$filepath = "d:\home\"
$dlpyamlfile = $filepath + "ruletemplate.yaml"

#Last Policy update
$lastpolicylog = 'd:\home\lastofficepolicy.log'
$lastpolicychange = get-content $lastpolicylog

#Sentinel variables
$workspacename = "$env:SentinelWorkspace"

$processedPolicies = @()
$dlpyaml = Get-Content $dlpyamlfile

#Use this portion if you want to automate using a Function
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
$policies = Get-DlpComplianceRule

# Looping through the policies and create Analytic Rules in Sentinel
foreach ($policy in $policies) {

if (($processedPolicies -notcontains $policy.ReportSeverityLevel,$policy.ParentPolicyName) -and ((get-date $policy.whenChanged).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") -gt (get-date $lastpolicychange).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")))
                                  {

        #Updating with the severity and name of the Dlp Policy

        $policyName = $policy.ParentPolicyName + "_" + $policy.ReportSeverityLevel
        $updateyaml1 = $dlpyaml -replace "dlppolicyname", $policyName
        $updateyaml2 = $updateyaml1 -replace "dlppolicy", $policy.ParentPolicyName
        $finalyaml = $updateyaml2 -replace "UpdateSeverity", $policy.ReportSeverityLevel

            # Sending the rule to temporary storage
            $file = $filepath + $policy.ParentPolicyName + $policy.ReportSeverityLevel + ".yaml"
            $finalyaml | Out-File $file

             #Updating or adding new Rules to Sentinel
             Get-Item $file  | Import-AzSentinelAlertRule -WorkspaceName $workspacename -Confirm:$false -ErrorAction:silentlycontinue
            
          #Keep track of already processed rules by placing in array for if sentence
          $processedPolicies += $policy.ReportSeverityLevel,$policy.ParentPolicyName
Remove-Item $file
Clear-Variable updateyaml1
Clear-Variable finalyaml

                                }

$dlplastchange = $policies.whenChanged | Sort-Object -Descending
$dlplastchange[0] | Out-File $lastpolicylog -NoNewline                                

                          }
Remove-PSSession $session
