@description('The name of the function app that you wish to create.')
param appName string

@description('Select to enable Application Insights for the Function App. This will allow you to monitor the status of the Function App for any errors. The Log Analytics Workspace specified in the "Log Analytics Resource Id" Parameter will be used to store the Application Insights data.')
param DeployApplicationInsights bool = true

@description('The name of the Key Vault to store Function App secrets.')
param keyVaultName string

@description('Location for all resources.')
param location string = resourceGroup().location

@description('Application Client ID')
param ClientID string = 'Provide the client ID'
@secure()
param ClientSecret string
param ContentTypes string = 'DLP.ALL'
param tenantDomain string = 'Yourtenant.onmicrosoft.com'
param TenantGuid string = 'Your Tenant GUID'
param domains string = 'youradditionaldomain.com,yourdomain.com,yourtenant.onmicrosoft.com'

@description('Provide the Document library where you want to store the full email. IMPORTANT full path, with trailing /')
param SPUS string = 'https://tenant.sharepoint.com/sites/DLPArchive/'
param storageQueue string = 'dlpqueue'
param workspaceId string = 'LogAnalytics Workspace Id'
@secure()
param workspaceKey string
param SentinelWorkspace string = 'Sentinel Workspace Name'

@description('Azure Resource Id of the Log Analytics Workspace where you like the DLP and optional Function App Application Insights data to reside. The format is: "/subscriptions/xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx/resourcegroups/xxxxxxxx/providers/microsoft.operationalinsights/workspaces/xxxxxxxx"')
param LogAnalyticsWorkspaceResourceId string

@description('Uri where the post deployment script is located. This is used to publish the Function App code after the resources have been deploted. Use default value unless you are hosting the script somewhere else.')
param DeploymentScriptUri string = 'https://raw.githubusercontent.com/anders-alex/O365-ActivityFeed-AzureFunction/Sentinel_Deployment/Sentinel_Deployment/deploymentScript.ps1'

@description('Uri where the post deployment script is located. This is used to publish the Function App code after the resources have been deploted. Use default value unless you are hosting the script somewhere else.')
param FunctionAppPackageUri string = 'https://raw.githubusercontent.com/anders-alex/O365-ActivityFeed-AzureFunction/Sentinel_Deployment/Sentinel_Deployment/functionPackage.zip'

var functionAppName = appName
var hostingPlanName = appName
var storageAccountName = '${uniqueString(resourceGroup().id)}azfunctions'

resource userAssignedMi 'Microsoft.ManagedIdentity/userAssignedIdentities@2022-01-31-preview' = {
  name: 'uami-${appName}'
  location: location
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2021-08-01' = {
  name: storageAccountName
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
  name: '${storageAccount.name}/default/${toLower(appName)}'
}

resource dlpQueue 'Microsoft.Storage/storageAccounts/queueServices/queues@2022-09-01' = {
  name: '${storageAccount.name}/default/${storageQueue}'
}

resource keyVault 'Microsoft.KeyVault/vaults@2022-07-01' = {
  name: keyVaultName
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

resource hostingPlan 'Microsoft.Web/serverfarms@2021-03-01' = {
  name: hostingPlanName
  location: location
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
}

resource keyVaultSecretStorageAccountConnectionString 'Microsoft.KeyVault/vaults/secrets@2022-07-01' = {
  parent: keyVault
  name: 'StorageAccountConnectionString'
  properties: {
    value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccountName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'
  }
}

resource keyVaultSecretClientSecret 'Microsoft.KeyVault/vaults/secrets@2022-07-01' = {
  parent: keyVault
  name: 'ClientSecret'
  properties: {
    value: ClientSecret
  }
}

resource keyVaultSecretLawKey 'Microsoft.KeyVault/vaults/secrets@2022-07-01' = {
  parent: keyVault
  name: 'LawKey'
  properties: {
    value: workspaceKey
  }
}

resource functionApp 'Microsoft.Web/sites@2022-03-01' = {
  name: functionAppName
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
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=StorageAccountConnectionString)'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=StorageAccountConnectionString)'
        }
        {
          name: 'AzureWebJobsSecretStorageType'
          value: 'keyvault'
        }
        {
          name: 'AzureWebJobsSecretStorageKeyVaultUri'
          value: 'https://${keyVaultName}.vault.azure.net/'
        }
        {
          name: 'AzureWebJobsSecretStorageKeyVaultClientId'
          value: userAssignedMi.properties.clientId
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower(appName)
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
          name: 'ClientID'
          value: ClientID
        }
        {
          name: 'ClientSecret'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=ClientSecret)'
        }
        {
          name: 'ContentTypes'
          value: ContentTypes
        }
        {
          name: 'customLogName'
          value: 'O365DLP'
        }
        {
          name: 'domains'
          value: domains
        }
        {
          name: 'SPUS'
          value: SPUS
        }
        {
          name: 'storageQueue'
          value: storageQueue
        }
        {
          name: 'endpointstorageQueue'
          value: 'endpointqueue'
        }
        {
          name: 'tenantDomain'
          value: tenantDomain
        }
        {
          name: 'TenantGuid'
          value: TenantGuid
        }
        {
          name: 'workspaceId'
          value: workspaceId
        }
        {
          name: 'workspaceKey'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=LawKey)'
        }
        {
          name: 'SentinelWorkspace'
          value: SentinelWorkspace
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
    dlpQueue
  ]
}

resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = if (DeployApplicationInsights == true) {
  name: 'appInsights-${appName}'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    Request_Source: 'rest'
    WorkspaceResourceId: LogAnalyticsWorkspaceResourceId
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

module roleAssignmentLaw 'modules/lawRoleAssignment.bicep' = {
  scope: resourceGroup(split(LogAnalyticsWorkspaceResourceId, '/')[2], split(LogAnalyticsWorkspaceResourceId, '/')[4])
  name: 'rbacAssignmentLaw'
  params: {
    principalId: userAssignedMi.properties.principalId
    roleDefId: '/providers/Microsoft.Authorization/roleDefinitions/ab8e14d6-4a74-4a29-9ba8-549422addade'
    scopedResourceName: split(LogAnalyticsWorkspaceResourceId, '/')[8]
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
    timeout: 'PT5M'
    cleanupPreference: 'Always'
    primaryScriptUri: DeploymentScriptUri
    arguments: '-PackageUri ${FunctionAppPackageUri} -SubscriptionId ${split(subscription().id, '/')[2]} -ResourceGroupName ${resourceGroup().name} -FunctionAppName ${functionApp.name} -FAScope ${functionApp.id} -UAMIPrincipalId ${userAssignedMi.properties.principalId}'
  }
}
