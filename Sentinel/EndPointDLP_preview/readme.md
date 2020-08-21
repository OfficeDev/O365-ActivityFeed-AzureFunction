[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FOfficeDev%2FO365-ActivityFeed-AzureFunction%2Fmaster%2FSentinel%2FEndPointDLP_preview%2Fdeploysentinelfunction.json)

---
page_type: sample
products:
- office-365
- Sentinel
languages:
- powershellcore
extensions:
  contentType: samples
  createdDate: 4/21/2020 3:00:56 PM
description: "This sample can be used to create a function that ingest DLP.All logs and Audit.General Endpoint DLP events to Sentinel. This is early preview code and contains some workarounds to solve current limitations in the system"
---


# Ingesting Office 365 and Endpoint DLP events to Sentinel

By clicking deploy above you will deploy an Azure Function App with the functions needed to run this project. You will have to copy the code manually to the functions or use the script option below for deployment. The reason being that we want you to manage the code distribution yourself. There currently is a bug in the API that may cause duplicates of a single endpoint event during low load conditions.

### Prerequisites

- You need to have an Azure Subscription
- Ability to create an Azure Function App. 
- A Sentinel Workspace and access to the Keys
- Part of the Endpoint DLP preview
- Exchange credentials to get sensitive info types
- You need permissions to make a new App registration. 
- SharePoint Library if you want to utilize the ability to store full email content in SharePoint.

### Installing

* 1. Register a new application in Azure AD https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app
  -Microsoft GRAPH  (Application permissions)
     - Group.Read.All
     - User.Read.All
  - Office 365 Management APIs  (Application permissions)
     - ActivityFeed.Read
     - ActivityFeed.ReadDlp   (Needed for detailed events)
 
 * 2. Collect the identity and secret for the new App created in step 1.  For production. Store the secret in Azure Key vault https://docs.microsoft.com/en-us/azure/app-service/app-service-key-vault-references
      - clientID
      - clientSecret
      - TenantGuid
      - exuser (User account to allow for mapping to sensitive info types)
      
* 3. Get the WorkSpace ID and Workspace Key for your Sentinel Workspace.

* 4. Click on Deploy to Azure Above to start the deployment. Fill in the values for your environment. If you have an Azure Keyvault use the string something like this instead of the actual value @Microsoft.KeyVault(SecretUri=https://Myvault.vault.azure.net/secrets/MySecretKey/bd2a5f8b0f944b528af2b66da20645d4)
SPUS is only used if you are going to deploy ingestion of SharePoint. (https://myTenant.sharepoint.com/sites/DLPDetectionsFinance/Records/)
These values can be changed later on by going to configuration of the Azure Function App.

* 5. **Please Observe, there may be a timing issue causing an error when deploying the logic apps. If it is one of the functions it can be safely ignored.**

* 6. **If you want to deploy the code by script follow these steps**
  * Download the endpointdlpservice.zip from this repo
  * Start to connect to Azure PowerShell Connect-AzAccout
  * Run Publish-AzWebApp -ResourceGroupName REPLACEWITHYOURRG -Name REPLACEWITHYOURAPPNAME -ArchivePath C:\YOURPATH\endpointdlpservice.zip  **Note:The names are case sensitive**
  * Navigate to the Enablement function in your Function App, open the function under functions, open "Code + Test" , click Test/Run, click Run
  * Note if there are any errors generated in this run, you will see it in the logging window. If there is a typo or similar in your configuration files. Go back to the main window for the App and click Configuration to update.

* 7. **If you want to copy the code manually.**
  * Copy the code from  https://github.com/OfficeDev/O365-ActivityFeed-AzureFunction/blob/master/Sentinel/EndPointDLP_preview/enablesubscription.ps1 to EnableSubscription. Run the function once and look for errors in the log. (Popup the window while running)
  * Copy the code from https://github.com/OfficeDev/O365-ActivityFeed-AzureFunction/blob/master/Sentinel/EndPointDLP_preview/QueueDLPEvents.ps1 and place in the Queue events function.
  * Copy the code from  https://github.com/OfficeDev/O365-ActivityFeed-AzureFunction/blob/master/Sentinel/EndPointDLP_preview/StoreEndpointDLPEvents.ps1 to store the EndPoint events
  * Copy the code from https://github.com/OfficeDev/O365-ActivityFeed-AzureFunction/blob/master/Sentinel/StoreEvents.ps1 to the StoreEvents function. 

At this point the function should be ready to run. 

- When you have ingested some Endpoint DLP events you can follow these instructions for setting up Alerts https://github.com/OfficeDev/O365-ActivityFeed-AzureFunction/tree/master/Sentinel/EndPointDLP_preview/AnalyticsRule Note they will fail if you haven't ingested events first.

- When you have ingested some DLP alerts from both SPO and Exchange you can follow these instructions for setting up Alerts https://github.com/OfficeDev/O365-ActivityFeed-AzureFunction/tree/master/Sentinel/AnalyticsRule Note they will fail
if you haven't ingested events first.

- If you want to ingest content to SharePoint please see https://github.com/OfficeDev/O365-ActivityFeed-AzureFunction/tree/master/Sentinel/logicapp, complete the step pasting the code in to ActualID in the current project if you didn't use the automatic code deployment.

- For Reporting please see https://github.com/OfficeDev/O365-ActivityFeed-AzureFunction/tree/master/Sentinel/EndPointDLP_preview/Report

## Multiple workspaces for Multi Geo and Microsoft Graph enrichment
The StoreEvents.ps1 has the basic enrichment functionality. You will find it from row 110 and onward. There is a high likelihood that you want to customize this code to meet your organizations requirements.

Right now it is based on usageLocation and below usageLocation US. You will likely have another attribute that we should use for event routing.

- The GRAPH <mark>queryString</mark> dictates which attributes we bring back from the Azure GRAPH. What you get back can then be used to enrich the data. You can make additional calls to the Security Graph as well.

- As part of the code we are adding the SPO location so that once that component is in place you can easily access the original content through that link. Storing it in SharePoint allow for granular permissions.

- When preparing the Arrays for upload to Log Analytics we simply push the data to the appropriate Workspace based on the usageLocation in this sample.

There is an issue returning the manager with the v1.0 which works with the Beta endpoint. 
To get the manager with v1.0 amend the code with
        $querymanager = "https://graph.microsoft.com/v1.0/users/" + $user.ExchangeMetaData.From + "/manager"
        $manager = Invoke-RestMethod -Headers $headerParamsG -Uri $querymanager
        
## Additional Customization

For production increase the FUNCTIONS_WORKER_PROCESS_COUNT https://docs.microsoft.com/en-us/azure/azure-functions/functions-app-settings
Specifies the maximum number of language worker processes, with a default value of 1. The maximum value allowed is 10. Function invocations are evenly distributed among language worker processes. Language worker processes are spawned every 10 seconds until the count set by FUNCTIONS_WORKER_PROCESS_COUNT is reached. 

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

