---
page_type: sample
products:
- Microsoft 365
- Sentinel
languages:
- powershellcore
extensions:
  contentType: samples
  createdDate: 12/17/2021 3:00:56 PM
description: "This sample can be used to create MIP events in Sentinel."
---


# Ingesting Micrsoft MIP events to Sentinel

Use the endpointdlp preview steps to deploy the code. https://github.com/OfficeDev/O365-ActivityFeed-AzureFunction/tree/master/Sentinel/EndPointDLP_preview

**During the deployment specify all content types in the dialog, deploy to Azure** 
  - DLP.ALL,Audit.General,Audit.Exchange,Audit.SharePoint (Alt. after deployment under configuration of the Function App)

**Replace STEP 5. by using the zip file in this repo.**

### Prerequisites

- You need to have an Azure Subscription
- Ability to create an Azure Function App. 
- A Sentinel Workspace and access to the Keys
- You need permissions to make a new App registration. 

### Installing
Permissions needed for the app
  - Office 365 Management APIs  (Application permissions)
     - ActivityFeed.Read
     - ActivityFeed.ReadDlp   (Needed for detailed events)
    
**Deployment of the code to the function**
  * Download mipservice.zip from this repo, the SHA256 hash is 9A8E886C9996157FFAFC21AF3661B1C243CAA1776B45B65FB914929C625FBCF3
  * Start to connect to Azure PowerShell Connect-AzAccout
  * Run Publish-AzWebApp -ResourceGroupName REPLACEWITHYOURRG -Name REPLACEWITHYOURAPPNAME -ArchivePath C:\YOURPATH\mipservice.zip  **Note:The names are case sensitive**

### Creating the Watchlists
Documentation for Watchlists https://docs.microsoft.com/en-us/azure/sentinel/watchlists

1. Export the MIP labels using SCC Powershell, sample Get-Label | select ImmutableId,DisplayName,LabelActions | Export-Csv c:\tmp\slabels.csv -NoTypeInformation
If you happen to get hyphens in the csv header fields, remove the hyphens since the WL engine cannot process. 
2. Create a new Microsoft Sentinel Watchlist call it **Sensitive**, set the ImmutableId as the index field.
3. Create a new Microsoft Sentinel Watchlist call it MipMap, import the mipmap.csv file in this repo. (File to translate MIP operations)
4. Create a new Microsoft Sentinel Watchlist call it UserAccounts, Import your account list, **for reporting to work well you need to include, userprincipalname,department,FullName,Title (The more detail you add the cooler you can make the report dashboard or any alerts)**
   - The Indexing field should be the UserPrincipalName, we use it as a key to enrich the items
   - You can start with a small csv file, for bulk uploading a lot of data please see importwatch.ps1 in this repo it works in PS and PS Core. It supports incremental uploads as well as updating existing objects in the list.
   - .\importwatch.ps1 -csv C:\tmp\UserAccounts.csv -Watchlist UserAccounts -Workspace usinstance -errlog c:\wlupload.log

### Deploy the Label Statistics Workbook
Deploy the workbook Sensitivitylabels.json in this repo by simply copying the code across to a new Azure Workbook. 
1. [Open] Workbooks from the Sentinel Workspace where you intend to install the workbooks / portal.azure.com
2. [Click] "Add workbook" 
3. When the New Workbook window open select edit, then select the Advanced Editor ([click] the </> icon )
4. Copy the text of the json template you are installing from this repository [paste] over any json that exists.
5. [Click] save, select the appropriate location and name for the workbook.
