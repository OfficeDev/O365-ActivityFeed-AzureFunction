var deploymentVersion = '1.1.1'
@description('A globally unique name for the Function App to be created which will run the code to ingest DLP data into Sentinel.')
param FunctionAppName string = 'fa-sentineldlp-[Replace with globally unique identifier]'
@description('Select to enable Application Insights for the Function App. This will allow you to monitor the status of the Function App for any errors. The Log Analytics Workspace specified in the "Log Analytics Resource Id" Parameter will be used to store the Application Insights data.')
param DeployApplicationInsights bool = true
@description('A globally unique name for the Key Vault to be created which will store Function App secrets.')
param KeyVaultName string = 'kv-sentineldlp-[Replace with globally unique identifier]'
@description('A globally unique name for the Function App Storage Account. Must be between 3 and 24 characters in length and use numbers and lower-case letters only.')
param StorageAccountName string = 'stsentineldlp[Replace with globally unique identifier]'
@description('Name of custom role to be created at the Log Analytics resource group level. The name needs to be unique across the entire tenant. This role provides the Function App read/write access to Sentinel watchlists, alert rules, and read data in the PurviewDLP_CL table.')
param CustomRoleName string = 'Custom Role - Sentinel DLP Contributor'
@description('Azure AD tenant ID in which DLP instance resides.')
param TenantID string = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
@description('App Registration Client ID.')
param ClientID string = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
@secure()
@description('App Registration Client secret.')
param ClientSecret string
@description('Comma seperated list of internal domain names for your organization to better determine the source of email messages. If domains are left out, enrichment will not occur for those users.')
param InternalDomainNames string = 'yourtenant.onmicrosoft.com,yourdomain.com,youradditionaldomain.com'
@description('Name for Data Collection Endpoint to be created which is used to ingest data into Log Analytics workspace.')
param DataCollectionEndpointName string = 'dce-sentineldlp'
@description('Name for Data Collection Rule to be created which is used to ingest data into Log Analytics workspace.')
param DataCollectionRuleName string = 'dcr-sentineldlp'
@description('Azure Resource ID (NOT THE WORKSPACE ID) of the existing Log Analytics Workspace where you would like the DLP and optional Function App Application Insights data to reside. This can be found by clicking the "JSON View" link within the Overview page of the Log Analytics workspace resource. The format is: "/subscriptions/xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx/resourcegroups/xxxxxxxx/providers/microsoft.operationalinsights/workspaces/xxxxxxxx"')
param LogAnalyticsWorkspaceResourceID string = '/subscriptions/xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx/resourcegroups/xxxxxxxx/providers/microsoft.operationalinsights/workspaces/xxxxxxxx'
@description('Create Sentinel Analytics Rule(s) to create alerts and incidents out of DLP events.')
param DeployAnalyticsRules bool = true
@description('Create a Sentinel scheduled query rule for each DLP policy and workload (i.e., Teams, SharePoint, Endpoint, etc.). If "false", a single scheduled query rule will be created to cover all policies and workloads.')
param DLPPolicySync bool = false
@description('Sync Purview Sensitivity Label information to a Sentinel Watchlist so the label name can be looked up when referenced in events.')
param SensitivityLabelSync bool = true
@description('Required for Analytics Rule(s) and Workbooks. Create Azure Monitor Function named PurviewDLP to normalize DLP data at query time.')
param DeployAzureMonitorFunction bool = true
@description('Deploy Azure workbooks to help visualize the DLP data and manage DLP incidents.')
param DeployWorkbooks bool = true
@description('Use the Azure Deployment Script resource to automatically deploy the Function App code. This requires the Microsoft.ContainerInstance resource provider to be registred on the subsription.')
param DeployFunctionCode bool = true
@description('GitHub repo where Azure Function package and post deployment script is located. Leave the default value unless you are using content from a different location. This is not applicable if the Deploy Function Code parameter is set to false.')
param RepoUri string = 'https://raw.githubusercontent.com/OfficeDev/O365-ActivityFeed-AzureFunction/master'
@description('Select how you would like the the sensitive information type detections to be handled when ingesting into the Log Analytics workspace.')
@allowed(
  [
    'Keep'
    'Hash'
    'Remove'
  ]
)
param SensitiveDataHandling string = 'Hash'
@description('By default, the included PurviewDLP Azure Monitor function will not return sensitive info type detected values, you must explicitly specify the "PurviewDLP(ShowDetections=true)" parameter when running the function to return this data. Setting this deployment parameter to true will make the function return the detected values by default, including in alerts.')
param ShowSensitiveInfoDetectionValues bool = false
@description('Because the API does not currently supply the alert severity value for Endpoint events, you can choose to have Sentinel derive the severity from the DLP policy rule name. The rule name must have a "Low", "Medium", or "High" suffix value with a space as the delimiter. For example, "DLP rule name Medium" or "DLP rule name High". If set to false, the severity will default to Medium for all alerts unless the sensitive info detection count is above 50. This threshold can be modified via the "EndpointHighSeverityMatchCountTrigger" PurviewDLP Log Analytics function parameter.')
param EndpointSeverityInRuleName bool = true
@description('Recommended when processing a large number of events but increases cost.')
param EnableElasticPremiumPlan bool = false
@description('Enabling Private Networking will restrict public access to the Function App for additional security. A Virtual Network with the below address space and subnets, along with an NSG, Private Endpoints, and Private DNS Zones will be deployed to support this configuration. This will also leverage the Dedicated App Service Premium plan (P0v3) instead of the Consumption plan (If the Elastic Premium Plan is selected, it will be used instead of the Dedicated App Service Premium Plan.).')
param EnablePrivateNetworking bool = true
@description('If enabling Private Networking, choose the desired address space for the Virtual Network or leave the default.')
param PrivateNetworkAddressSpace string = '10.0.0.0/24'
@description('If enabling Private Networking, choose the desired address space for the Private Endpoints subnet or leave the default. Do not make subnets any smaller than the default.')
param PrivateEndpointsSubnet string = '10.0.0.0/26'
@description('If enabling Private Networking, choose the desired address space for the Function App vnet integration subnet or leave the default. Do not make subnets any smaller than the default.')
param FunctionAppSubnet string = '10.0.0.64/26'

var location = resourceGroup().location
var functionAppPackageUri = '${RepoUri}/Sentinel_Deployment/functionPackage.zip'
var deploymentScriptUri = '${RepoUri}/Sentinel_Deployment/deploymentScript.ps1'
var roleIdOwner = '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635'

resource law 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: split(LogAnalyticsWorkspaceResourceID, '/')[8]
  scope: resourceGroup(split(LogAnalyticsWorkspaceResourceID, '/')[2], split(LogAnalyticsWorkspaceResourceID, '/')[4])
}

resource userAssignedMi 'Microsoft.ManagedIdentity/userAssignedIdentities@2022-01-31-preview' = {
  name: 'uami-${FunctionAppName}'
  location: location
}

module createCustomTables 'modules/customDcrTables.bicep' = {
  name: 'createCustomTables'
  params: {
    LogAnalyticsWorkspaceLocation: law.location
    LogAnalyticsWorkspaceResourceId: law.id
    DataCollectionEndpointName: DataCollectionEndpointName
    DataCollectionRuleName: DataCollectionRuleName
    ServicePrincipalId: userAssignedMi.properties.principalId  
  }  
}

module purviewDLPFunction 'modules/lawFunction.bicep' = if(DeployAzureMonitorFunction == true) {
  scope: resourceGroup(split(law.id, '/')[2], split(law.id, '/')[4])
  name: 'purviewDLPFunction'
  dependsOn: [
    createCustomTables
  ] 
  params: {
    category: 'DLP' 
    displayName: 'Microsoft Purview DLP' 
    functionName: 'PurviewDLP' 
    lawName: split(law.id, '/')[8]
    functionAlias: 'PurviewDLP' 
    functionParams: 'WorkloadNames:dynamic = dynamic([\'Exchange\', \'MicrosoftTeams\', \'SharePoint\', \'OneDrive\', \'Endpoint\']), EndpointSeverityInRuleName:bool = ${string(EndpointSeverityInRuleName)}, EndpointHighSeverityMatchCountTrigger:int = 50, EndpointSeverityDelimiter:string = \' \', ShowDetections:bool = ${string(ShowSensitiveInfoDetectionValues)}'
    query: 'let _DetectionsMax = 5;\nlet _SITMax = 30;\nlet _EndpointSeverityInRuleName = EndpointSeverityInRuleName;\nlet _EndpointHighSeverityMatchCountTrigger = EndpointHighSeverityMatchCountTrigger;\nlet _EndpointSeverityDelimiter = EndpointSeverityDelimiter;\nlet _WorkloadNames = WorkloadNames;\nlet _ShowDetections = ShowDetections;\n\n//Get DLP data elements that are shared across all workloads.\nlet DLPCommon = PurviewDLP_CL\n| where Workload in (_WorkloadNames) and Workload != \'Endpoint\' and Operation =~ \'DLPRuleMatch\'\n| summarize arg_max(TimeGenerated, *) by Identifier\n| mv-expand PolicyDetails\n| where PolicyDetails.PolicyName != \'\'\n| mv-expand Rules = PolicyDetails.Rules\n| summarize TotalMatchCount = toint(sum(toint(Rules.ConditionsMatched.TotalCount))), arg_max(TimeGenerated, *) by Identifier\n| join kind=leftouter (PurviewDLPSIT_CL\n    | summarize arg_max(TimeGenerated, *) by Identifier, SensitiveInformationTypeName\n    | join kind=leftouter (PurviewDLPDetections_CL\n        | summarize arg_max(TimeGenerated, *) by Identifier, Name, Value, SensitiveInfoId\n        | extend Detections = bag_pack(\'Name\', Name, \'Value\', Value)\n        | summarize Detections = make_list_if(Detections, _ShowDetections == true,_DetectionsMax), arg_max(TimeGenerated, *) by SensitiveInfoId\n        ) on SensitiveInfoId\n    ) on Identifier\n| extend SensitiveInfoType = bag_pack(\'Name\', SensitiveInformationTypeName, \'Count\', toint(SITCount), \'Confidence\', toint(Confidence), \'Location\', Location, \'Detections\', Detections)\n| extend ActionsTaken = strcat_array(Rules.Actions, \', \')\n| extend SensitiveInfoTypeString = iff(SensitiveInfoType.Count > 0, strcat(SensitiveInfoType.Name, \' (\', SensitiveInfoType.Count, \', \', SensitiveInfoType.Confidence, \'%)\'), \'\')\n| summarize SensitiveInfoTypesArray = make_list_if(SensitiveInfoType, SensitiveInfoType.Count > 0, _SITMax), SensitiveInfoTypes = make_list(SensitiveInfoTypeString, _SITMax), SensitiveInfoTypeCount = count(), arg_max(TimeGenerated, *) by Identifier\n| extend\n    PolicyName = tostring(PolicyDetails.PolicyName),\n    RuleName = tostring(Rules.RuleName),\n    RuleSeverity = tostring(Rules.Severity),\n    UserPrincipalName = tolower(UserId),\n    UserObjectId = UserKey,\n    Deeplink = strcat(\'https://compliance.microsoft.com/datalossprevention/alerts/eventdeeplink?eventid=\', Identifier, \'&creationtime=\', CreationTime);\n\n//Get Sharepoint and OneDrive specific data elements from common datatable defined above.\nlet DLPSPOD = DLPCommon\n| where Workload in (\'SharePoint\', \'OneDrive\')\n| extend SensitivityLabelIds = todynamic(iff(array_length(SharePointMetaData.SensitivityLabelIds) == 0, \'\', SharePointMetaData.SensitivityLabelIds))\n| mv-expand SensitivityLabelId = SensitivityLabelIds\n| extend SensitivityLabelId = tostring(SensitivityLabelId)\n| join kind = leftouter (_GetWatchlist(\'SensitivityLabels\')\n    | extend SensitivityLabelId = tostring(column_ifexists(\'id\', \'\')),\n        SensitivityLabelName = tostring(column_ifexists(\'name\', \'\'))\n    | summarize arg_max(LastUpdatedTimeUTC, SensitivityLabelId, SensitivityLabelName) by SensitivityLabelId) on SensitivityLabelId\n| extend OfficeObjectId = url_decode(tostring(SharePointMetaData.FilePathUrl))\n| join kind = leftouter (OfficeActivity\n    | where TimeGenerated > ago(30m)\n    | where Operation == "AddedToSecureLink" or Operation == "SecureLinkUsed"\n    | extend UserId = tolower(UserId),\n        TargetUserOrGroupName = tolower(iff(isempty(TargetUserOrGroupName), split(UserId, "#")[1], TargetUserOrGroupName))\n    ) on $left.UserPrincipalName == $right.UserId, OfficeObjectId\n| extend Filename = tostring(SharePointMetaData.FileName),\n    FilePath = tostring(SharePointMetaData.FilePathUrl),\n    SiteUrl = tostring(SharePointMetaData.SiteCollectionUrl),\n    ExceptionReason = tostring(SharePointMetaData.ExceptionInfo.Reason)\n| summarize SensitivityLabels = make_list(SensitivityLabelName), arg_max(TimeGenerated, *) by Identifier;\n\n//Get Exchange and Teams specific data elements from common datatable defined above.\nlet DLPEXOT = DLPCommon\n| where Workload in (\'Exchange\', \'MicrosoftTeams\')\n| extend Recipients = iff(Workload == \'Exchange\', tostring(strcat(array_strcat(ExchangeMetaData.To, \', \'), iff(array_length(ExchangeMetaData.CC) == 0, \'\', ", "), array_strcat(ExchangeMetaData.CC, \', \'), iff(array_length(ExchangeMetaData.BCC) == 0, \'\', ", "))), tostring(strcat_array(ExchangeMetaData.To, \', \'))),\n    InternetMessageId = replace_string(replace_string(tostring(ExchangeMetaData.MessageID), \'<\', \'\'), \'>\',\'\'),\n    EmailSubject = tostring(ExchangeMetaData.Subject),\n    Sender = UserPrincipalName,\n    ExceptionReason = tostring(ExchangeMetaData.ExceptionInfo.Reason),\n    ExceptionJustification = tostring(ExchangeMetaData.ExceptionInfo.Justification)\n| summarize DetectedLocations = make_set(SensitiveInfoType.Location), arg_max(TimeGenerated, *) by Identifier;\n\n//Define datatable so we can lookup Endpoint DLP action names from their Id.\nlet EndpointAction = datatable(ActionName: string, ActionId: int) [\n    "None", "0",\n    "Audit", "1",\n    "Warn", "2",\n    "WarnAndBypass", "3",\n    "Block", "4",\n    "Allow", "5"\n];\n//Array to match severity as the last word in rule name if present.\nlet EndpointSeverities = dynamic([\'Low\', \'Medium\', \'High\']);\n\n//Get Endpoint specific data elements from common datatable defined above.\nlet DLPEndpoint = PurviewDLP_CL\n| where Workload in (\'Endpoint\') and \'Endpoint\' in (_WorkloadNames) and  Operation =~ \'DLPRuleMatch\'\n| summarize arg_max(TimeGenerated, *) by Identifier\n| extend IngestionTime = ingestion_time()\n| mv-expand PolicyDetails\n| where PolicyDetails.PolicyName != \'\'\n| mv-expand Rules = PolicyDetails.Rules\n| join kind=leftouter (PurviewDLPSIT_CL\n    | summarize arg_max(TimeGenerated, *) by Identifier, SensitiveInformationTypeName\n    | join kind=leftouter (PurviewDLPDetections_CL\n        | summarize arg_max(TimeGenerated, *) by Identifier, Name, Value\n        | extend Detections = bag_pack(\'Name\', Name, \'Value\', Value)\n        | summarize Detections = make_list_if(Detections, _ShowDetections == true, _DetectionsMax), arg_max(TimeGenerated, *) by SensitiveInfoId\n        ) on SensitiveInfoId\n    ) on Identifier\n| extend SensitiveInfoType = bag_pack(\'Name\', SensitiveInformationTypeName, \'Count\', toint(SITCount), \'Confidence\', toint(Confidence), \'Location\', Location, \'Detections\', Detections)\n| extend SensitiveInfoType = bag_pack(\'Name\', SensitiveInformationTypeName, \'Count\', toint(SITCount), \'Confidence\', toint(Confidence)),\n    DeviceFullName = tostring(EndpointMetaData.DeviceName)\n| extend TotalMatchCount = toint(EndpointMetaData.SensitiveInfoTypeTotalCount)\n| extend RuleSplit = split(tostring(Rules.RuleName), _EndpointSeverityDelimiter)\n| extend RuleLength = array_length(RuleSplit)\n| extend RuleSeverity = iff(RuleSplit[RuleLength - 1] in (EndpointSeverities) and _EndpointSeverityInRuleName == true, RuleSplit[RuleLength - 1], iff(TotalMatchCount >= _EndpointHighSeverityMatchCountTrigger and _EndpointSeverityInRuleName == false, \'High\', \'Medium\'))\n| extend Exception = tostring(EndpointMetaData.Justification)\n| extend ExceptionReason = substring(Exception, indexof(Exception, \'_\') + 1)\n| extend ExceptionReason = substring(ExceptionReason, 0, indexof(ExceptionReason, \':\'))\n| extend ExceptionJustification = substring(Exception, indexof(Exception, \':\') + 1)\n| extend SensitiveInfoTypeString = iff(SensitiveInfoType.Count > 0, strcat(SensitiveInfoType.Name, \' (\', SensitiveInfoType.Count, \', \', SensitiveInfoType.Confidence, \'%)\'), \'\'),\n    ActionId = toint(EndpointMetaData.EnforcementMode),\n    ClientIP = tostring(EndpointMetaData.ClientIP),\n    DeviceHostName = tostring(split(DeviceFullName, \'.\')[0]), \n    DeviceDNSName = tostring(substring(DeviceFullName, indexof(DeviceFullName, \'.\')+1)),\n    Filename = DocumentName,\n    FilePath = ObjectId,\n    FileHash = tostring(EndpointMetaData.Sha256),\n    FileHashAlgorithm = \'SHA256\',\n    RMSEncrypted = tostring(EndpointMetaData.RMSEncrypted),\n    EvidenceFileUrl = tostring(EvidenceFile.FullUrl),\n    SourceLocationType = tostring(EndpointMetaData.SourceLocationType), \n    EndpointOperation = tostring(EndpointMetaData.EndpointOperation),\n    EndpointApplication = tostring(EndpointMetaData.Application),\n    EndpointClientIp = tostring(EndpointMetaData.ClientIP),\n    PolicyName = tostring(PolicyDetails.PolicyName),\n    RuleName = tostring(Rules.RuleName),\n    UserPrincipalName = tolower(UserId),\n    UserObjectId = UserKey,\n    Deeplink = strcat(\'https://compliance.microsoft.com/datalossprevention/alerts/eventdeeplink?eventid=\', Identifier, \'&creationtime=\', CreationTime)\n| join kind = inner(EndpointAction) on ActionId\n| extend ActionsTaken = ActionName\n| summarize SensitiveInfoTypesArray = make_list_if(SensitiveInfoType, SensitiveInfoType.Count > 0, _SITMax), SensitiveInfoTypes = make_list(SensitiveInfoTypeString, _SITMax), SensitiveInfoTypeCount = count(), arg_max(TimeGenerated, *) by Identifier;\n\n//Merge all the SharePoint/OneDrive, Exchange/Teams, and Endpoints results together.\nunion DLPSPOD, DLPEXOT, DLPEndpoint\n| extend FileDirectory = parse_path(FilePath).DirectoryPath\n| project \n//Common attributes\nTimeGenerated, CreationTime, \nCreationTimeString = strcat(format_datetime(CreationTime,\'M/d/yyyy, H:mm:ss tt\'), \' (UTC)\'),\nIdentifier, Workload, Deeplink, usageLocation, UserPrincipalName, UserObjectId, department, manager, jobTitle, PolicyName, RuleName, ActionsTaken, SensitiveInfoTypesArray = iff(array_length(SensitiveInfoTypesArray) > 0, SensitiveInfoTypesArray, \'\'), TotalMatchCount, \nUsername = split(UserPrincipalName, \'@\')[0], UPNSuffix =split(UserPrincipalName, \'@\')[1],\nRuleSeverity,\nSensitiveInfoTypes = iff(array_length(SensitiveInfoTypes) > 1, strcat(SensitiveInfoTypes[0], \' +\', SensitiveInfoTypeCount - 1, \' more\'), strcat_array(SensitiveInfoTypes, \', \')),\n//Endpoint specific attributes\nDeviceFullName, DeviceHostName, DeviceDNSName, Filename, FilePath, FileDirectory, FileHash, FileHashAlgorithm, RMSEncrypted, EvidenceFileUrl, SourceLocationType, EndpointOperation, EndpointApplication, EndpointClientIp, Operation,\n//Exchange and Teams specific attributes\nRecipients, InternetMessageId, EmailSubject, Sender, ExceptionReason, ExceptionJustification,\n//SharePoint and OneDrive specific attributes\nSiteUrl, TargetUserOrGroupName,\nDetectedLocations = strcat_array(DetectedLocations, \', \'), SensitivityLabels = strcat_array(SensitivityLabels, \', \')\n| order by CreationTime'
  }
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2021-08-01' = {
  name: StorageAccountName
  dependsOn: [
    createCustomTables 
  ]
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    allowBlobPublicAccess: false
    publicNetworkAccess: EnablePrivateNetworking == true ? 'Disabled' : 'Enabled'
    minimumTlsVersion: 'TLS1_2'
    networkAcls: {
      defaultAction: EnablePrivateNetworking == true ? 'Deny' : 'Allow'
      bypass: 'None' 
    } 
  }
}

resource fileShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2022-09-01' = {
  name: '${storageAccount.name}/default/${toLower(FunctionAppName)}'
}

resource queue 'Microsoft.Storage/storageAccounts/queueServices/queues@2022-09-01' = {
  name: '${storageAccount.name}/default/dlpqueue'
}

resource keyVault 'Microsoft.KeyVault/vaults@2022-07-01' = {
  name: KeyVaultName
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'premium'
    }
    tenantId: subscription().tenantId
    accessPolicies: [
      {
        objectId: userAssignedMi.properties.principalId
        permissions: {
          secrets: [
            'get'
            'set'
            'list'
            'delete'
          ]
        }
        tenantId: subscription().tenantId
      }
    ]
    publicNetworkAccess: EnablePrivateNetworking == true ? 'Disabled' : 'Enabled'
    networkAcls: {
      defaultAction: EnablePrivateNetworking == true ? 'Deny' :'Allow'
      bypass: 'None'  
    }
  }
}

resource keyVaultSecretStorageAccountConnectionString 'Microsoft.KeyVault/vaults/secrets@2022-07-01' = {
  parent: keyVault
  name: 'StorageAccountConnectionString'
  properties: {
    value: 'DefaultEndpointsProtocol=https;AccountName=${StorageAccountName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'
  }
}

resource keyVaultSecretClientSecret 'Microsoft.KeyVault/vaults/secrets@2022-07-01' = if (ClientSecret != '') {
  parent: keyVault
  name: 'ClientSecret'
  properties: {
    value: ClientSecret
  }
}

resource hostingPlan 'Microsoft.Web/serverfarms@2021-03-01' = {
  name: FunctionAppName
  location: location
  sku: {
    name: EnableElasticPremiumPlan == true ? 'EP1' : EnablePrivateNetworking == true ? 'P0v3' : 'Y1'
    tier: EnableElasticPremiumPlan == true ? 'ElasticPremium' : EnablePrivateNetworking == true ? 'PremiumV3' : 'Dynamic'
  }
}

resource functionApp 'Microsoft.Web/sites@2022-03-01' = {
  name: FunctionAppName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${userAssignedMi.id}': {}
    }
  }
  kind: 'functionapp'
  properties: {
    serverFarmId: hostingPlan.id
    keyVaultReferenceIdentity: userAssignedMi.id
    httpsOnly: true
    clientCertEnabled: true
    clientCertMode: 'OptionalInteractiveUser'
    virtualNetworkSubnetId: EnablePrivateNetworking == true ? privateNetwork.outputs.functionAppSubnetId : (null)
    vnetContentShareEnabled: EnablePrivateNetworking == true ? true : false
    vnetRouteAllEnabled: EnablePrivateNetworking == true ? true : false 
    siteConfig: {
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: '@Microsoft.KeyVault(VaultName=${KeyVaultName};SecretName=StorageAccountConnectionString)'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: '@Microsoft.KeyVault(VaultName=${KeyVaultName};SecretName=StorageAccountConnectionString)'
        }
        {
          name: 'AzureWebJobsSecretStorageType'
          value: 'keyvault'
        }
        {
          name: 'AzureWebJobsSecretStorageKeyVaultUri'
          value: 'https://${KeyVaultName}${environment().suffixes.keyvaultDns}/'
        }
        {
          name: 'AzureWebJobsSecretStorageKeyVaultClientId'
          value: userAssignedMi.properties.clientId
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower(FunctionAppName)
        }
        {
          name: 'WEBSITE_SKIP_CONTENTSHARE_VALIDATION'
          value: '1'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: DeployApplicationInsights == true ? applicationInsights.properties.InstrumentationKey : ''
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'powershell'
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: '1'
        }
        {
          name: 'WEBSITE_CONTENTOVERVNET'
          value: EnablePrivateNetworking == true ? '1' : '0'
        }
        {
          name: 'AzureWebJobs.SyncDLPAnalyticsRules.Disabled'
          value: DLPPolicySync == false ? '1' : '0'
        }
        {
          name: 'AzureWebJobs.SyncSensitivityLabels.Disabled'
          value: SensitivityLabelSync == false ? '1' : '0'
        }
        {
          name: 'ClientID'
          value: ClientID
        }
        {
          name: 'ClientSecret'
          value: '@Microsoft.KeyVault(VaultName=${KeyVaultName};SecretName=ClientSecret)'
        }
        {
          name: 'ContentTypes'
          value: 'DLP.ALL'
        }
        {
          name: 'customLogName'
          value: 'PurviewDLP'
        }
        {
          name: 'domains'
          value: InternalDomainNames
        }
        {
          name: 'storageQueue'
          value: 'dlpqueue'
        }
        {
          name: 'TenantGuid'
          value: TenantID
        }
        {
          name: 'SentinelWorkspace'
          value: split(law.id, '/')[8]
        }
        {
          name: 'UamiClientId'
          value: userAssignedMi.properties.clientId
        }
        {
          name: 'DcrImmutableId'
          value: createCustomTables.outputs.DcrImmutableId
        }
        {
          name: 'DceUri'
          value: createCustomTables.outputs.DceUri
        }
        {
          name: 'LawResourceId'
          value: law.id
        }
        {
          name: 'SensitiveDataHandling'
          value: SensitiveDataHandling
        }
        {
          name: 'DeploymentVersion'
          value: deploymentVersion
        }
        {
          name: 'StorageAccountName'
          value: StorageAccountName
        }
        {
          name: 'DcrName'
          value: DataCollectionRuleName
        }
        {
          name: 'DceName'
          value: DataCollectionEndpointName
        }
        {
          name: 'EnablePBIWorkload'
          value: '0'
        }
      ]
      powerShellVersion: '7.2'
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      http20Enabled: true
      alwaysOn: EnablePrivateNetworking != true || EnableElasticPremiumPlan == true ? false : true
    }
  }
  dependsOn: [
    keyVaultSecretStorageAccountConnectionString
    storageAccount
    fileShare
  ]
}

resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = if (DeployApplicationInsights == true) {
  name: 'appInsights-${FunctionAppName}'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    Request_Source: 'rest'
    WorkspaceResourceId: law.id
  }
}

module roleAssignmentLaw 'modules/lawRoleAssignment.bicep' = if (DLPPolicySync == true || SensitivityLabelSync == true) {
  scope: resourceGroup(split(law.id, '/')[2], split(law.id, '/')[4])
  dependsOn: [
    createCustomTables
  ]
  name: 'rbacAssignmentLaw'
  params: {
    principalId: userAssignedMi.properties.principalId
    lawName: split(law.id, '/')[8]
    roleName: CustomRoleName
  }
}

resource roleAssignmentFa 'Microsoft.Authorization/roleAssignments@2022-04-01' = if(DeployFunctionCode == true) {
  name: guid(subscription().id, resourceGroup().id, functionApp.id)
  scope: functionApp
  properties: {
    principalId: userAssignedMi.properties.principalId
    roleDefinitionId: roleIdOwner
    principalType: 'ServicePrincipal'
  }
}

module sentinelWatchlists 'modules/sentinelWatchlists.bicep' = if(DLPPolicySync == true || SensitivityLabelSync == true) {
  name: 'sentinelWatchlists'
  scope: resourceGroup(split(law.id, '/')[2], split(law.id, '/')[4])
  params: {
    lawName: split(law.id, '/')[8]
    policySync: DLPPolicySync
    labelSync: SensitivityLabelSync
    principalId: userAssignedMi.properties.principalId
  }
}

module sentinelRules 'modules/sentinelRules.bicep' = if (DeployAnalyticsRules == true) {
  name: 'sentinelRules'
  scope: resourceGroup(split(law.id, '/')[2], split(law.id, '/')[4])
  dependsOn: [
    createCustomTables
    functionApp
    purviewDLPFunction
  ]
  params: {
    lawId: law.id
    policySync: DLPPolicySync
  }
}

module sentinelWorkbooks 'modules/sentinelWorkbooks.bicep' = if(DeployWorkbooks == true) {
  name: 'sentinelWorkbooks'
  scope: resourceGroup(split(law.id, '/')[2], split(law.id, '/')[4]) 
  dependsOn: [
    createCustomTables
    functionApp 
  ]
  params: {
    workbookSourceId: law.id
    location: law.location
  } 
}

module privateNetwork 'modules/privateNetwork.bicep' = if(EnablePrivateNetworking == true) {
  name: 'privateNetwork'
  params: {
    FunctionAppName: FunctionAppName
    KeyVaultId: keyVault.id 
    location: location 
    StorageAccountId: storageAccount.id 
    StorageAccountName: StorageAccountName
    KeyVaultName: KeyVaultName
    PrivateNetworkAddressSpace: PrivateNetworkAddressSpace
    FunctionAppSubnet: FunctionAppSubnet
    PrivateEndpointsSubnet: PrivateEndpointsSubnet
    PrincipalId: userAssignedMi.properties.principalId
    DeployCode: DeployFunctionCode
  }
}


module functionAppPe 'modules/functionAppPE.bicep' = if(EnablePrivateNetworking == true) {
  name: 'functionAppPe'
  params: {
    location: location
    FunctionAppId: functionApp.id  
    FunctionAppName: FunctionAppName 
    PrivateEndpointSubnetId: EnablePrivateNetworking == true ? privateNetwork.outputs.privateEndpointSubnetId : (null)
    VnetId: EnablePrivateNetworking == true ? privateNetwork.outputs.vnetId : (null)
  }  
}


resource deploymentScript 'Microsoft.Resources/deploymentScripts@2020-10-01' = if(DeployFunctionCode == true) {
  name: 'deployCode'
  location: location
  kind: 'AzurePowerShell'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${userAssignedMi.id}': {}
    }
  }
  properties: {
    azPowerShellVersion: '10.0'
    retentionInterval: 'PT1H'
    timeout: 'PT10M'
    cleanupPreference: 'Always'
    environmentVariables: [
      {
        name:'TenantId'
        value: TenantID 
      }
      {
        name:'ClientId'
        value: ClientID 
      }
      {
        name: 'ClientSecret'
        secureValue: ClientSecret  
      } 
    ] 
    primaryScriptUri: deploymentScriptUri
    arguments: EnablePrivateNetworking == true ? '-PackageUri ${functionAppPackageUri} -SubscriptionId ${split(subscription().id, '/')[2]} -ResourceGroupName ${resourceGroup().name} -FunctionAppName ${functionAppPe.outputs.functionAppName} -FAScope ${functionApp.id} -UAMIPrincipalId ${userAssignedMi.properties.principalId} -VnetScope ${privateNetwork.outputs.vnetId} -RestrictedIPs "None"' : '-PackageUri ${functionAppPackageUri} -SubscriptionId ${split(subscription().id, '/')[2]} -ResourceGroupName ${resourceGroup().name} -FunctionAppName ${functionApp.name} -FAScope ${functionApp.id} -UAMIPrincipalId ${userAssignedMi.properties.principalId}'
  }
}

output UserAssignedManagedIdentityPrincipalId string = userAssignedMi.properties.principalId
output UserAssignedManagedIdentityPrincipalName string = userAssignedMi.name
