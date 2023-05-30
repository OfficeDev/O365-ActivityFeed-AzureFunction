@description('A globally unique name for the Function App to be created which will run the code to ingest DLP data into Sentinel.')
param FunctionAppName string = 'fa-sentineldlp-[Replace with globally unique identifier]'
@description('Select to enable Application Insights for the Function App. This will allow you to monitor the status of the Function App for any errors. The Log Analytics Workspace specified in the "Log Analytics Resource Id" Parameter will be used to store the Application Insights data.')
param DeployApplicationInsights bool = true
@description('A globally unique name for the Key Vault to be created which will store Function App secrets.')
param KeyVaultName string = 'kv-sentineldlp-[Replace with globally unique identifier]'
@description('A globally unique name for the Function App Storage Account. Must be between 3 and 24 characters in length and use numbers and lower-case letters only.')
param StorageAccountName string = 'stsentineldlp[Replace with globally unique identifier]'
@description('Azure AD tenant ID in which DLP instance resides.')
param TenantID string = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
@description('App Registration Client ID.')
param ClientID string = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
@secure()
@description('App Registration Client secret.')
param ClientSecret string
@description('Internal domain names for your organization to better determine the source of email messages.')
param InternalDomainNames string = 'youradditionaldomain.com,yourdomain.com,yourtenant.onmicrosoft.com'
@description('Name for Data Collection Endpoint to be created which is used to ingest data into Log Analytics workspace.')
param DataCollectionEndpointName string = 'dce-sentineldlp'
@description('Name for Data Collection Rule to be created which is used to ingest data into Log Analytics workspace.')
param DataCollectionRuleName string = 'dcr-sentineldlp'
@description('Azure Resource ID of the existing Log Analytics Workspace where you would like the DLP and optional Function App Application Insights data to reside. The format is: "/subscriptions/xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx/resourcegroups/xxxxxxxx/providers/microsoft.operationalinsights/workspaces/xxxxxxxx"')
param LogAnalyticsWorkspaceResourceID string = '/subscriptions/xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx/resourcegroups/xxxxxxxx/providers/microsoft.operationalinsights/workspaces/xxxxxxxx'
@description('Azure location/region of the Log Analytics Workspace referenced in the LogAnalyticsWorkspaceResourceID parameter.')
@allowed(
  [
    'asia'
    'asiapacific'
    'australia'
    'australiacentral'
    'australiacentral2'
    'australiaeast'
    'australiasoutheast'
    'brazil'
    'brazilsouth'
    'brazilsoutheast'
    'canada'
    'canadacentral'
    'canadaeast'
    'centralindia'
    'centralus'
    'centraluseuap'
    'eastasia'
    'eastus'
    'eastus2'
    'eastus2euap'
    'europe'
    'france'
    'francecentral'
    'francesouth'
    'germany'
    'germanynorth'
    'germanywestcentral'
    'global'
    'india'
    'japan'
    'japaneast'
    'japanwest'
    'korea'
    'koreacentral'
    'koreasouth'
    'northcentralus'
    'northeurope'
    'norway'
    'norwayeast'
    'norwaywest'
    'qatarcentral'
    'southafrica'
    'southafricanorth'
    'southafricawest'
    'southcentralus'
    'southeastasia'
    'southindia'
    'swedencentral'
    'switzerland'
    'switzerlandnorth'
    'switzerlandwest'
    'uaecentral'
    'uaenorth'
    'uksouth'
    'ukwest'
    'unitedstates'
    'westcentralus'
    'westeurope'
    'westindia'
    'westus'
    'westus2'
    'westus3'
  ]
)
param LogAnalyticsWorkspaceLocation string
@description('Create a Sentinel scheduled query rule for each DLP policy and workload (i.e., Teams, SharePoint, Endpoint, etc.). If "false", a single scheduled query rule will be created to cover all policies and workloads.')
param DLPPolicySync bool = false
@description('Deploy Azure workbooks to help visualize the DLP data and manage DLP incidents.')
param DeployWorkbooks bool = true
@description('Use the Azure Deployment Script resource to automatically deploy the Function App code. This requires the Microsoft.ContainerInstance resource provider to be registred on the subsription.')
param DeployFunctionCode bool = true
@description('Ingest the sensitive data detected by DLP rules into Log Analytics workpace.')
@allowed(
  [
    'Keep'
    'Hash'
    'Remove'
  ]
)
param SensitiveDataHandling string = 'Hash'

var location = resourceGroup().location
var functionAppPackageUri = 'https://raw.githubusercontent.com/anders-alex/O365-ActivityFeed-AzureFunction/Sentinel_Deployment/Sentinel_Deployment/functionPackage.zip'
var deploymentScriptUri = 'https://raw.githubusercontent.com/anders-alex/O365-ActivityFeed-AzureFunction/Sentinel_Deployment/Sentinel_Deployment/deploymentScript.ps1'

resource userAssignedMi 'Microsoft.ManagedIdentity/userAssignedIdentities@2022-01-31-preview' = {
  name: 'uami-${FunctionAppName}'
  location: location
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
  }
}

module keyVaultUpdateNetworAcl 'modules/keyVault.bicep' = {
  name: 'keyVaultUpdateNetworkAcl'
  params: {
    kvName: keyVault.name
    location: keyVault.location
    skuFamily: keyVault.properties.sku.family
    skuName: keyVault.properties.sku.name   
    principalId: userAssignedMi.properties.principalId
    aclBypass: 'None'
    aclDefaultAction: 'Deny'
    aclIpRules: functionApp.properties.possibleOutboundIpAddresses
    secretPermissions: keyVault.properties.accessPolicies[0].permissions.secrets
  }
}

resource keyVaultSecretStorageAccountConnectionString 'Microsoft.KeyVault/vaults/secrets@2022-07-01' = {
  parent: keyVault
  name: 'StorageAccountConnectionString'
  properties: {
    value: 'DefaultEndpointsProtocol=https;AccountName=${StorageAccountName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'
  }
}

resource keyVaultSecretClientSecret 'Microsoft.KeyVault/vaults/secrets@2022-07-01' = {
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
    name: 'Y1'
    tier: 'Dynamic'
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
          value: 'https://${KeyVaultName}.vault.azure.net/'
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
          value: '0'
        }
        {
          name: 'AzureWebJobs.SyncEndpointDLPAnalyticRules.Disabled'
          value: DLPPolicySync == false ? '1' : '0'
        }
        {
          name: 'AzureWebJobs.SyncEXOTeamsDLPAnalyticRules.Disabled'
          value: DLPPolicySync == false ? '1' : '0'
        }
        {
          name: 'AzureWebJobs.SyncSPODDLPAnalyticRules.Disabled'
          value: DLPPolicySync == false ? '1' : '0'
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
          value: split(LogAnalyticsWorkspaceResourceID, '/')[8]
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
          value: LogAnalyticsWorkspaceResourceID
        }
        {
          name: 'SensitiveDataHandling'
          value: SensitiveDataHandling
        }
      ]
      powerShellVersion: '7.2'
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      use32BitWorkerProcess: false 
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
    WorkspaceResourceId: LogAnalyticsWorkspaceResourceID
  }
}

module createCustomTables 'modules/customDcrTables.bicep' = {
  name: 'createCustomTables'
  params: {
    LogAnalyticsWorkspaceLocation: LogAnalyticsWorkspaceLocation 
    LogAnalyticsWorkspaceResourceId: LogAnalyticsWorkspaceResourceID
    DataCollectionEndpointName: DataCollectionEndpointName
    DataCollectionRuleName: DataCollectionRuleName
    ServicePrincipalId: userAssignedMi.properties.principalId  
  }  
}

module purviewDLPFunction 'modules/lawFunction.bicep' = {
  scope: resourceGroup(split(LogAnalyticsWorkspaceResourceID, '/')[2], split(LogAnalyticsWorkspaceResourceID, '/')[4])
  name: 'purviewDLPFunction'
  dependsOn: [
    createCustomTables
    functionApp  
  ] 
  params: {
    category: 'DLP' 
    displayName: 'Microsoft Purview DLP' 
    functionName: 'PurviewDLP' 
    lawName: split(LogAnalyticsWorkspaceResourceID, '/')[8]
    functionParams: 'WorkloadNames:dynamic = dynamic([\'Exchange\', \'MicrosoftTeams\', \'SharePoint\', \'OneDrive\', \'Endpoint\']), alertProductName:string = \'Microsoft Data Loss Prevention (Custom)\''
    query: '//Get DLP data elements that are shared across all workloads.\r\nlet DLPCommon = PurviewDLP_CL\r\n| where Workload in (WorkloadNames) and Operation =~ \'DLPRuleMatch\'\r\n| mv-expand PolicyDetails\r\n| where PolicyDetails.PolicyName != \'\'\r\n| mv-expand Rules = PolicyDetails.Rules\r\n| mv-expand ActionsTaken = Rules.Actions\r\n| mv-expand SensitiveInfo = Rules.ConditionsMatched.SensitiveInformation\r\n| extend RulesString = tostring(Rules), SensitiveInfoString = tostring(SensitiveInfo)\r\n| summarize ActionsTaken = make_set(ActionsTaken), arg_max(TimeGenerated, *) by TimeGenerated, CreationTime, Identifier, RulesString, SensitiveInfoString\r\n| extend SensitiveInfoType = bag_pack(\'Name\', SensitiveInfo.SensitiveInformationTypeName, \'Count\', toint(SensitiveInfo.Count), \'Confidence\', toint(SensitiveInfo.Confidence))\r\n| extend\r\n    ActionsTaken = strcat_array(ActionsTaken, \', \'),\r\n    SensitiveInfoTypeString = strcat(SensitiveInfoType.Name, \' (\', SensitiveInfoType.Count, \', \', SensitiveInfoType.Confidence, \'%)\'),\r\n    PolicyName = tostring(PolicyDetails.PolicyName),\r\n    RuleName = tostring(Rules.RuleName),\r\n    RuleSeverity = tostring(Rules.Severity),\r\n    UserPrincipalName = tolower(UserId),\r\n    UserObjectId = UserKey,\r\n    Deeplink = strcat(\'https://compliance.microsoft.com/datalossprevention/alerts/eventdeeplink?eventid=\', Identifier, \'&creationtime=\', CreationTime);\r\n\r\n//Get Sharepoint and OneDrive specific data elements from common datatable defined above.\r\nlet DLPSPOD = DLPCommon\r\n| where Workload in (\'SharePoint\', \'OneDrive\')\r\n| mv-expand SensitivityLablelId = SharePointMetaData.SensitivityLablelIds\r\n| extend SensitivityLabelId = tostring(SharePointMetaData.SensitivityLablelId)\r\n| join kind = leftouter (_GetWatchlist(\'SensitivityLabels\')\r\n    | extend SensitivityLabelId = tostring(column_ifexists(\'id\', \'\')),\r\n        SensitivityLabelName = tostring(column_ifexists(\'name\', \'\'))) on SensitivityLabelId\r\n| extend OfficeObjectId = url_decode(tostring(SharePointMetaData.FilePathUrl))\r\n| extend CreationTimeBin = bin(CreationTime, 1m)\r\n| join kind = leftouter (OfficeActivity\r\n    | where ingestion_time() > ago(24h)\r\n    | where Operation == "AddedToSecureLink" or Operation == "SecureLinkUsed"\r\n    | extend CreationTimeBin = bin(TimeGenerated, 1m),\r\n        TargetUserOrGroupName = tolower(iff(isempty(TargetUserOrGroupName), split(UserId, "#")[1], TargetUserOrGroupName))\r\n    ) on OfficeObjectId, CreationTimeBin\r\n| extend Filename = tostring(SharePointMetaData.FileName),\r\n    FilePath = tostring(SharePointMetaData.FilePathUrl),\r\n    SiteUrl = tostring(SharePointMetaData.SiteCollectionUrl),\r\n    ExceptionReason = tostring(SharePointMetaData.ExceptionInfo.Reason)\r\n| summarize SensitiveInfoTypesArray = make_list(SensitiveInfoType), SensitiveInfoTypes = make_set(SensitiveInfoTypeString), TotalMatchCount = sum(toint(SensitiveInfoType.Count)), SensitivityLabels = make_list(SensitivityLabelName) by TimeGenerated, CreationTime, Identifier, Workload, Deeplink, usageLocation, UserPrincipalName, UserObjectId, department, manager, jobTitle, PolicyName, RuleName, RuleSeverity, ActionsTaken, FilePath, Filename, SiteUrl, TargetUserOrGroupName, ExceptionReason, Operation;\r\n\r\n//Get Exchange and Teams specific data elements from common datatable defined above.\r\nlet DLPEXOT = DLPCommon\r\n| where Workload in (\'Exchange\', \'MicrosoftTeams\')\r\n| extend Recipients = iff(Workload == \'Exchange\', tostring(strcat(array_strcat(ExchangeMetaData.To, \', \'), iff(array_length(ExchangeMetaData.CC) == 0, \'\', ", "), array_strcat(ExchangeMetaData.CC, \', \'), iff(array_length(ExchangeMetaData.BCC) == 0, \'\', ", "))), tostring(strcat_array(ExchangeMetaData.To, \', \'))),\r\n    InternetMessageId = replace_string(replace_string(tostring(ExchangeMetaData.MessageID), \'<\', \'\'), \'>\',\'\'),\r\n    EmailSubject = tostring(ExchangeMetaData.Subject),\r\n    Sender = UserPrincipalName,\r\n    ExceptionReason = tostring(ExchangeMetaData.ExceptionInfo.Reason)\r\n| summarize SensitiveInfoTypesArray = make_list(SensitiveInfoType), SensitiveInfoTypes = make_set(SensitiveInfoTypeString), TotalMatchCount = sum(toint(SensitiveInfoType.Count)), DetectedLocations = make_set(SensitiveInfo.Location) by TimeGenerated, CreationTime, Identifier, Workload, Deeplink, usageLocation, UserPrincipalName, UserObjectId, department, manager, jobTitle, PolicyName, RuleName, RuleSeverity, ActionsTaken, Recipients, InternetMessageId, EmailSubject, Sender, ExceptionReason, Operation;\r\n\r\n//Define datatable so we can lookup Endpoint DLP action names from their Id.\r\nlet EndpointAction = datatable(ActionName: string, ActionId: int) [\r\n    "None", "0",\r\n    "Audit", "1",\r\n    "Warn", "2",\r\n    "WarnAndBypass", "3",\r\n    "Block", "4",\r\n    "Allow", "5"\r\n];\r\n//Array to match severity as the last word in rule name if present.\r\nlet EndpointSeverities = dynamic([\'Low\', \'Medium\', \'High\']);\r\n\r\n//Get Endpoint specific data elements from common datatable defined above.\r\nlet DLPEndpoint = DLPCommon\r\n| where Workload in (\'Endpoint\')\r\n| mv-expand SensitiveInfo = EndpointMetaData.SensitiveInfoTypeData\r\n| extend SensitiveInfoType = bag_pack(\'Name\', SensitiveInfo.SensitiveInfoTypeName, \'Count\', toint(SensitiveInfo.Count), \'Confidence\', toint(SensitiveInfo.Confidence)),\r\n    DeviceFullName = tostring(EndpointMetaData.DeviceName)\r\n| extend RuleSplit = split(tostring(RuleName), \' \')\r\n| extend RuleLength = array_length(RuleSplit)\r\n| extend RuleSeverity = iff(RuleSplit[RuleLength - 1] in (EndpointSeverities) and EndpointSeverityInRuleName == true, RuleSplit[RuleLength - 1], \'\')\r\n| extend SensitiveInfoTypeString = strcat(SensitiveInfoType.Name, \' (\', SensitiveInfoType.Count, \', \', SensitiveInfoType.Confidence, \'%)\'),\r\n    ActionId = toint(EndpointMetaData.EnforcementMode),\r\n    ClientIP = tostring(EndpointMetaData.ClientIP),\r\n    DeviceHostName = tostring(split(DeviceFullName, \'.\')[0]), \r\n    DeviceDNSName = tostring(substring(DeviceFullName, indexof(DeviceFullName, \'.\')+1)),\r\n    Filename = DocumentName,\r\n    FilePath = ObjectId,\r\n    FileHash = tostring(EndpointMetaData.Sha256),\r\n    FileHashAlgorithm = \'SHA256\',\r\n    RMSEncrypted = tostring(EndpointMetaData.RMSEncrypted),\r\n    EvidenceFileUrl = tostring(EvidenceFile.FullUrl),\r\n    SourceLocationType = tostring(EndpointMetaData.SourceLocationType), \r\n    EndpointOperation = tostring(EndpointMetaData.EndpointOperation),\r\n    EndpointApplication = tostring(EndpointMetaData.Application),\r\n    EndpointClientIp = tostring(EndpointMetaData.ClientIP)\r\n| join kind = inner(EndpointAction) on ActionId\r\n| extend ActionsTaken = ActionName\r\n| summarize SensitiveInfoTypesArray = make_list(SensitiveInfoType), SensitiveInfoTypes = make_list(SensitiveInfoTypeString), TotalMatchCount = sum(toint(SensitiveInfo.Count)) by TimeGenerated, CreationTime, Identifier, Workload, Deeplink, usageLocation, UserPrincipalName, UserObjectId, department, manager, jobTitle, PolicyName, RuleName, RuleSeverity, ActionsTaken, DeviceFullName, DeviceHostName, DeviceDNSName, Filename, FilePath, FileHash, FileHashAlgorithm, RMSEncrypted, EvidenceFileUrl, SourceLocationType, EndpointOperation, EndpointApplication, EndpointClientIp, Operation;\r\n\r\n//Merge all the SharePoint/OneDrive, Exchange/Teams, and Endpoints results together.\r\nunion DLPSPOD, DLPEXOT, DLPEndpoint\r\n| extend FileDirectory = parse_path(FilePath).DirectoryPath\r\n| project \r\n//Common attributes\r\nTimeGenerated, CreationTime, Identifier, Workload, Deeplink, usageLocation, UserPrincipalName, UserObjectId, department, manager, jobTitle, PolicyName, RuleName, ActionsTaken, SensitiveInfoTypesArray, TotalMatchCount, \r\nUsername = split(UserPrincipalName, \'@\')[0], UPNSuffix =split(UserPrincipalName, \'@\')[1],\r\nRuleSeverity = iff(TotalMatchCount >= EndpointHighSeverityMatchCountTrigger and Workload == \'Endpoint\' and EndpointSeverityInRuleName == false, \'High\', RuleSeverity),\r\nSensitiveInfoTypes = iff(array_length(SensitiveInfoTypes) > 1, strcat(SensitiveInfoTypes[0], \' +\', array_length(SensitiveInfoTypes) - 1, \' more\'), strcat_array(SensitiveInfoTypes, \', \')),\r\n//Endpoint specific attributes\r\nDeviceFullName, DeviceHostName, DeviceDNSName, Filename, FilePath, FileDirectory, FileHash, FileHashAlgorithm, RMSEncrypted, EvidenceFileUrl, SourceLocationType, EndpointOperation, EndpointApplication, EndpointClientIp, Operation,\r\n//Exchange and Teams specific attributes\r\nRecipients, InternetMessageId, EmailSubject, Sender, ExceptionReason,\r\n//SharePoint and OneDrive specific attributes\r\nSiteUrl, TargetUserOrGroupName,\r\nDetectedLocations = strcat_array(DetectedLocations, \', \'), SensitivityLabels = strcat_array(SensitivityLabels, \', \')'
  }
}

module roleAssignmentLaw 'modules/lawRoleAssignment.bicep' = {
  scope: resourceGroup(split(LogAnalyticsWorkspaceResourceID, '/')[2], split(LogAnalyticsWorkspaceResourceID, '/')[4])
  name: 'rbacAssignmentLaw'
  params: {
    principalId: userAssignedMi.properties.principalId
    roleDefId: '/providers/Microsoft.Authorization/roleDefinitions/ab8e14d6-4a74-4a29-9ba8-549422addade'
    scopedResourceName: split(LogAnalyticsWorkspaceResourceID, '/')[8]
  }
}

resource roleAssignmentFa 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, functionApp.id)
  scope: functionApp
  properties: {
    principalId: userAssignedMi.properties.principalId
    roleDefinitionId: '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
    principalType: 'ServicePrincipal'
  }
}

module sentinelWatchlists 'modules/sentinelWatchlists.bicep' = {
  name: 'sentinelWatchlists'
  scope: resourceGroup(split(LogAnalyticsWorkspaceResourceID, '/')[2], split(LogAnalyticsWorkspaceResourceID, '/')[4])
  dependsOn: [
    createCustomTables
    functionApp 
  ]
  params: {
    lawName: split(LogAnalyticsWorkspaceResourceID, '/')[8]
    policySync: DLPPolicySync 
  }
}

module sentinelRules 'modules/sentinelRules.bicep' = {
  name: 'sentinelRules'
  scope: resourceGroup(split(LogAnalyticsWorkspaceResourceID, '/')[2], split(LogAnalyticsWorkspaceResourceID, '/')[4])
  dependsOn: [
    createCustomTables
    functionApp 
  ]
  params: {
    workspace: split(LogAnalyticsWorkspaceResourceID, '/')[8]
  }
}

module sentinelWorkbooks 'modules/sentinelWorkbooks.bicep' = if(DeployWorkbooks == true) {
  name: 'sentinelWorkbooks'
  dependsOn: [
    createCustomTables
    functionApp 
  ]
  params: {
    workbookSourceId: LogAnalyticsWorkspaceResourceID
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
    azPowerShellVersion: '8.3'
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
    arguments: '-PackageUri ${functionAppPackageUri} -SubscriptionId ${split(subscription().id, '/')[2]} -ResourceGroupName ${resourceGroup().name} -FunctionAppName ${functionApp.name} -FAScope ${functionApp.id} -UAMIPrincipalId ${userAssignedMi.properties.principalId}'
  }
}

output UserAssignedManagedIdentityPrincipalId string = userAssignedMi.properties.principalId
output UserAssignedManagedIdentityPrincipalName string = userAssignedMi.name
