# Release Notes
## 1.1.2 (1/4/2025)
### Changes/Fixes
- Function App Code
    - Updated .Net libraries and PowerShell modules to latest versions.
    - Updated QueueDLPEvents Function to use QueueClient.SendMessage method as required by new PS module.
- Deployment
    - Fixed issue where previous method to deploy Azure Files Share (required for Consumption and Elastic Premium plans) no longer worked and was causing depoyments to fail.
    - Updated Function App PowerShell to version 7.4.
    - Updated post deployment script to use Az module 12.3.

## 1.1.1 (11/20/2023)
### Changes/Fixes
- Function App Code
    - Configured Function timeout for 5 min.
    - Updated Az.Storage to 6.*.
    - Suppressed output when running Disable-AzContextAutosave.
    - Addded error handling to sync functions to prevent duplicates.
- Deployment
    - Set storage account to minimum TLS 1.2 and set trusted network exceptions where needed.
    - Reduced permissions needed on Watchlists.
    - Bicep Log Analytics Workspace Id reference cleanup.
    
## 1.1.0 (11/15/2023)
### Changes/Fixes
- Function App Code
    - Disabled the sending of Power BI SIT information by default as the core event was not being sent. To enable this workload (Private Preview), set the "EnablePBIWorkload" Application Setting to a value of "1" on the Function App.
    - Updated .Net libraries to latest versions. Added .csproj file to repo so GitHub Dependabot can monitor for updates.
    - Optimized Azure Monitor ingestion PowerShell function to make less authentication calls. Renamed to AzMon.Ingestion.
    - Resolved intermittent Azure Monitor HTTP 400 error during high/concurrent loads.
- Deployment
    - Added new configuration values to Function App and ARM parameters to make future updates more seamless.
    - Updated scope to create workbooks in the same resource group as the Sentinel workspace so they appear in the Sentinel workbooks interface.
    - Updated Function App to use 32 bit instead of 64 bit.
    - Removed network access rules on Key Vault as apparently [Function App does not always access Key Vault from the designated outboud IP addresses](https://learn.microsoft.com/en-us/azure/azure-functions/ip-addresses?tabs=portal#find-outbound-ip-addresses).
    - Updated Key Vault reference to dynamically populate the DNS suffix to make the deployment more cross-environment friendly.
    - Added parameter to specify GitHub content location to make testing new code easier.
    - Updated Azure Monitor function to account for events that don't have any SIT info and to account for potential duplicate sensitivity label entries in the Watchlist.
    - Added new "ShowDetections" parameter to Azure Monitor function to control if sensitive info type detection values are returned in the query/alerts.
    - Added custom role to reduce access needed to Sentinel workspace.
    - Added Private Networking (Private Endpoints) option to deployment.
    - Updated Readme.

## 1.0.0 (10/25/2023)
### New Features
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
