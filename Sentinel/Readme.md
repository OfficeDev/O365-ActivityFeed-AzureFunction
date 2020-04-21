[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FOfficeDev%2FO365-ActivityFeed-AzureFunction%2Fmaster%2FSentinel%2FdeploySentinelfunction.json)

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
description: "This sample can be used to create a function that ingest DLP.All logs to Sentinel."
---


# Ingesting Office 365 DLP.ALL events to Sentinel

By clicking deploy above you will deploy an Azure Function App with the functions needed to run this project. To get it to work you will have to copy the code manually to the functions. The reason being that we want you to manage the code distribution yourself.

### Prerequisites

You need to have an Azure Subscription, ability to create an Azure Function App. You need to have at least one Sentinel Workspace.
You need permissions to make a new App registration. SharePoint Library where you can 

### Installing

1. Register a new application in Azure AD https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app
  -Microsoft GRAPH  (Application permissions)
     - Group.Read.All
     - User.Read.All
  - Office 365 Management APIs  (Application permissions)
     - ActivityFeed.Read
     - ActivityFeed.ReadDlp
 
 2. Collect the identity and secret for the new App created in step 1.  For production. Store the secret in Azure Key vault https://docs.microsoft.com/en-us/azure/app-service/app-service-key-vault-references
      - clientID
      - clientSecret
      - TenantGuid
      
3. Get the WorkSpace ID and Workspace Key for your Sentinel Workspace.

4. Click on Deploy to Azure Above to start the deployment. Fill in the values for your environment. If you have an Azure Keyvault use the string something like this instead of the actual value @Microsoft.KeyVault(SecretUri=https://Myvault.vault.azure.net/secrets/MySecretKey/bd2a5f8b0f944b528af2b66da20645d4)
SPUS is only used if you are going to deploy ingestion of SharePoint. (https://myTenant.sharepoint.com/sites/DLPDetectionsFinance/Records/)
These values can be changed later on by going to configuration of the Azure Function App.

5. There may be a timing issue causing an error for the Queue function. That can be safely ignored.

6. Copy the code from https://github.com/OfficeDev/O365-ActivityFeed-AzureFunction/blob/master/Sentinel/enablesubscription.ps1 to EnableSubscription. Run the function once and look for errors in the log. (Popup the window while running)

7. Copy the code from https://github.com/OfficeDev/O365-ActivityFeed-AzureFunction/blob/master/Sentinel/QueueEvents.ps1 and place in the Queue events function.

8. Copy the code from https://github.com/OfficeDev/O365-ActivityFeed-AzureFunction/blob/master/Sentinel/StoreEvents.ps1 to the StoreEvents function. 

At this point the function should be ready to run. 

## Running the tests

Check the logs for errors when the function is running. 

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
