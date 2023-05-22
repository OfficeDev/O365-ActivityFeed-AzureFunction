@description('A globally unique name for the Function App to be created which will run the code to ingest DLP data into Sentinel.')
param FunctionAppName string = 'fa-sentineldlp'
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

var location = resourceGroup().location
var functionAppPackageUri = 'https://raw.githubusercontent.com/anders-alex/O365-ActivityFeed-AzureFunction/Sentinel_Deployment/Sentinel_Deployment/functionPackage.zip'
var deploymentScriptUri = 'https://raw.githubusercontent.com/anders-alex/O365-ActivityFeed-AzureFunction/Sentinel_Deployment/Sentinel_Deployment/deploymentScript.ps1'

resource userAssignedMi 'Microsoft.ManagedIdentity/userAssignedIdentities@2022-01-31-preview' = {
  name: 'uami-${FunctionAppName}'
  location: location
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2021-08-01' = {
  name: StorageAccountName
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
      ]
      powerShellVersion: '7.2'
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      use32BitWorkerProcess: false 
    }
  }
  dependsOn: [
    sentinelWatchlists
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
    deploymentScript
  ]
  params: {
    workspace: split(LogAnalyticsWorkspaceResourceID, '/')[8]
  }
}

module sentinelWorkbooks 'modules/sentinelWorkbooks.bicep' = if(DeployWorkbooks == true) {
  name: 'sentinelWorkbooks'
  dependsOn: [
    createCustomTables
    deploymentScript
  ]
  params: {
    workbookSourceId: LogAnalyticsWorkspaceResourceID
  } 
}

resource deploymentScript 'Microsoft.Resources/deploymentScripts@2020-10-01' = {
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
