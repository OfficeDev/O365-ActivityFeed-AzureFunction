Deploy MIP Label report [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com/OfficeDev/O365-ActivityFeed-AzureFunction/master/Sentinel_CloudApp/Label%20Statistics.json)

---/
page_type: sample
products:
- Microsoft 365
- Sentinel
languages:
- powershellcore
extensions:
  contentType: samples
  createdDate: 04/06/2021 3:00:56 PM
description: "This sample can be used to create MIP events in Sentinel."
---


# Utilizing MIP events in CloudAppEvents to visualise usage

### Prerequisites

- Microsoft Sentinel
- Microsoft Defender for Cloud
- Microsoft Information Protection
- Microsoft Endpoint Protection or Endpoint DLP

### Installing
Permissions needed for the app
  - Sentinel Workspace
  - CloudAppEvents
    
**Deployment of the code to the function**
  * 
### Creating the Watchlists
Documentation for Watchlists https://docs.microsoft.com/en-us/azure/sentinel/watchlists

1. Export the MIP labels using SCC Powershell, sample Get-Label | select ImmutableId,DisplayName,LabelActions | Export-Csv c:\tmp\slabels.csv -NoTypeInformation
If you happen to get hyphens in the csv header fields, remove the hyphens since the WL engine cannot process. 
2. Create a new Microsoft Sentinel Watchlist call it **Sensitive**, set the ImmutableId as the index field.
3. Create a new Microsoft Sentinel Watchlist call it **MipMap**, set the Value field as the index field, import the mipmap.csv file in this repo. (File to translate MIP operations)
4. Create a new Microsoft Sentinel Watchlist call it UserAccounts, Import your account list, **for reporting to work well you need to include, Userprincipalname,Department,FullName,Title,Country (The more detail you add the cooler you can make the report dashboard or any alerts), there is no normalization of the header so please capitalize the first letter as above or change the template.**
   - The Indexing field should be the UserPrincipalName, we use it as a key to enrich the items
   - Use the Microsoft Sentinel Large Watchlist to upload the list of users it scales well to 100's of thousands of users.

### Deploy the Label Statistics Workbook
Deploy the workbook Sensitivitylabels.json in this repo by simply copying the code across to a new Azure Workbook. 
1. [Open] Workbooks from the Sentinel Workspace where you intend to install the workbooks / portal.azure.com
2. [Click] "Add workbook" 
3. When the New Workbook window open select edit, then select the Advanced Editor ([click] the </> icon )
4. Copy the text of the json template you are installing from this repository [paste] over any json that exists.
5. [Click] save, select the appropriate location and name for the workbook.
