
# Sentinel DLP Connector Deployment
1. Enable the **Office 365 Sentinel Connector** and ensure the **OfficeActivity** table is provisioned.
2. Create an **App Registration** with the following **Application** permissions and **grant admin consent**. Create a **secret** and copy the value along with the **Application (client) ID** and **Tenant ID** which will best used later in the deployment.
    - **Microsoft Graph**
        - Group.Read.All
        - User.Read.All
    - **Office 365 Management APIs**
        - ActivityFeed.ReadDlp
3. Click the button below to deploy the Function App which will start ingesting DLP data into Sentinel.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fanders-alex%2FO365-ActivityFeed-AzureFunction%2FSentinel_Deployment%2FSentinel_Deployment%2Fmain.json)

