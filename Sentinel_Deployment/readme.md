
# Microsoft Purview DLP Sentinel Solution
This a fork of the initial [Sentinel DLP Solution](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/advanced-incident-management-for-office-and-endpoint-dlp-using/ba-p/1811497). It has been updated for easy deployment, modernization of components, and to introduce new capabilities. View [Release Notes](releaseNotes.md).

## New Features
- Fully packaged into a single ARM/Bicep deployment for easy installation and setup.
- Leverages new Data Collection Rule (DCR) custom tables to ingest and store DLP data. This provides fine grained security and unlocks new capabilities such as data transformations.
- Provides option to hash, remove, or retain the detected sensitive information values.
- Includes "PurviewDLP" Azure Monitor Function to normalize the DLP event data across all of the different workload types (Endpoint, Teams/Exchange, and SharePoint/OneDrive).
- Separates DLP data into the below three separate tables to allow for all sensitive information data to be ingested (some events would exceed the max field size when trying to store everything in a single row). This also allows for more flexible queries and restricting access to the sensitive information data if desired.
    - PurviewDLP: Core DLP event information, including violating user, impacted files/messages, etc.
    - PurviewDLPSIT: Contains the sensitive information types that were detected.
    - PurviewDLPDetections: Contains the sensitive information type detected values (evidence).
- For Endpoint DLP events, the severity of the alert/event is not currently included in the API, so by default the severity is derived from DLP policy rule name. The rule name must have a "Low", "Medium", or "High" suffix value with a space as the delimiter. For example, "DLP rule name Medium" or "DLP rule name High".
- Includes 3 built-in Sentinel workbooks to provide advanced incident management and reporting:
    - Microsoft DLP Incident Management
    - Microsoft DLP Activity
    - Microsoft DLP Organizational Context
- Includes two options for automatically deploying the built-in Sentinel analytics rules:
    - A single rule to create alerts and incidents across all DLP workload types. This will work for most environments where the 150 events per 5 min. limit is not being exceeded.
    - A rule for each Purview DLP policy and workload (DLP Policy Sync). This is to be used in scenarios where the 150 events per 5 min. limit is being exceeded or where more customization is desired based on workload.
- The syncing of the sensitivity label information and analytics rules now uses modern authentication mechanisms.
- Better error handling has been introduced to the code along with a more hardened configuration for the Azure components. For example, secrets are now stored in a Key Vault with restricted access from the Function App.

## Solution Components
- **Function App** with all of the dependencies (i.e., Storage Account, Key Vault, Application Insights, etc.) and PowerShell code necessary to ingest the DLP events, sensitivity label information, and advanced Sentinel analytics rules (if desired). The [Azure Monitor Ingestion client library for .NET](https://learn.microsoft.com/en-us/dotnet/api/overview/azure/monitor.ingestion-readme?view=azure-dotnet) is used to send data to the Azure Monitor/Sentinel workspace.
- **Azure Monitor Custom Tables** to house the core DLP events along with the sensitive information data.
- **Azure Monitor Function** to parse and normalize the DLP event data across all of the different workload types (Endpoint, Teams/Exchange, and SharePoint/OneDrive)
- **Azure Monitor Data Collection Rule** and **Data Collection Endpoint** required to ingest the DLP events via the new Azure Monitor Logs Ingestion API.
- **Sentinel Analytics Rule(s)** to automatically start turning the raw DLP events into actionable alerts and incidents within Sentinel. The appropriate entity mapping is also pre-configured.
- **Sentinel Workbooks** to help with advanced DLP incident management and reporting.
- **Sentinel Watchlists** to house sensitivity label information and to help with the analytics rule "DLP Policy Sync" feature if enabled.

## Getting Started
### Prerequisites
- Sentinel workspace Azure RESOURCE ID (Not the WORKSPACE ID) that the solution will ingest data into and provision the associated Sentinel artifacts (i.e., analytics rules, workbooks, function, etc.).
- Owner permissions on the above Sentinel workspace.
- Global Admin permissions on the Purview DLP Entra ID tenant to create the App Registration and grant Admin Consent as outlined in step #2 below.
- Owner permissions on an Azure Resource Group or Subscription to deploy the solution to in step #3. If Owner permissions are not granted on the subscription, the Microsoft.ContainerInstance resource provider must be registered on the subscription before deployment in order for the code to be automatically deployed to the Function App.

### Deployment
1. Enable the **Microsoft 365 (formerly, Office 365) Sentinel Connector** and ensure the **OfficeActivity** table is provisioned if you would like further enrichment for SharePoint DLP events.
2. Create an **App Registration** with the following **Application** permissions and **grant Admin Consent**. Create a **secret** and copy the value along with the **Application (client) ID** and **Tenant ID** which will be used as parameter values in the below Azure deployment.
    - **Microsoft Graph**
        - Group.Read.All
        - User.Read.All
        - InformationProtectionPolicy.Read.All
    - **Office 365 Management APIs**
        - ActivityFeed.ReadDlp
3. Click the **button** below to deploy the solution and its components. After a successful deployment, you should be able to see data in the Azure Monitor tables along with alerts and incidents being created in Sentinel once new DLP events are generated.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fanders-alex%2FO365-ActivityFeed-AzureFunction%2FSentinel_Deployment4%2FSentinel_Deployment%2Fmain.json)

