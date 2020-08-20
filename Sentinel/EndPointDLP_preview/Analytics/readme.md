---
page_type: sample
products:
- office-365
- Sentinel
languages:
- powershellcore
extensions:
  contentType: samples
  createdDate: 8/20/2020 3:00:56 PM
description: "This sample can be used to create a function that ingest DLP.All logs to Sentinel."
---


# Creating Sentinel Analytic Rules based on Office DLP Policies
The script will generate new Analytic rules used for alerting in connection to Office DLP policies. If the script is run more than once it will update the existing rules.

### Prerequisites

- The script is relying on AZ.sentinel PS Module from **Wortell** https://github.com/wortell/AZSentinel
- The RBAC permission for the user that running the **export part** of the script is at least a Sentinel **reader** https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#azure-sentinel-reader
- The RBAC permission for the user that running the **import part** of the script is a Sentinel **Contributor** https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#azure-sentinel-contributor

Prerequisite for using the Sentinel module https://github.com/wortell/AZSentinel#prerequisites

* [PowerShell Core](https://github.com/PowerShell/PowerShell)
* Powershell [AZ Module](https://www.powershellgallery.com/packages/Az) - tested with version 3.8.0
* PowerShell [powershell-yaml Module](https://www.powershellgallery.com/packages/powershell-yaml) 0.4.1
- Az.sentinel Module (tested with 0.6.4) with command below

Install-Module AzSentinel -Scope CurrentUser -Force

- **MUST** have ingested both SharePoint and Exchange events to Azure Sentinel or rule creation will fail with error 500.

### Running the Script

1. Update the paramters used in the Script to suit your environment
2. When executing the script you will have to provide Az device login and credentials for Office 365
3. The script extracts all Office DLP rules and associated DLP policies and create Analytic Rules in Azure Sentinel. A policy for PCI as an example, may contain both a High and a Low rule, there will be two separate analytic rules one called PCI_High
and one called PCI_Low. 
        
## Additional Customization

If you need to troubleshoot connections to Azure Sentinel change Get-Item $file | Import-AzSentinelAlertRule -WorkspaceName $workspacename -SubscriptionID $subscriptionID -Confirm:$false -ErrorAction:silentlycontinue
to
Get-Item $file | Import-AzSentinelAlertRule -WorkspaceName $workspacename -SubscriptionID $subscriptionID -verbose

If you need to customize the KQL query either modify the associated template file ruletemplate.yaml or create your own custom template.



## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
