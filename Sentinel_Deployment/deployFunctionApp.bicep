@description('The name of the function app that you wish to create.')
param FunctionAppName string
@description('Select to enable Application Insights for the Function App. This will allow you to monitor the status of the Function App for any errors. The Log Analytics Workspace specified in the "Log Analytics Resource Id" Parameter will be used to store the Application Insights data.')
param DeployApplicationInsights bool = true
@description('The name of the Key Vault to store Function App secrets.')
param KeyVaultName string
@description('App Registration Client ID.')
param ClientID string
@secure()
@description('App Registration Client secret.')
param ClientSecret string
@description('Azure AD tenant domain in which DLP instance resides.')
param TenantDomain string = 'Yourtenant.onmicrosoft.com'
@description('Azure AD tenant ID in which DLP instance resides.')
param TenantID string
@description('Trusted domain names.')
param TrustedDomains string = 'youradditionaldomain.com,yourdomain.com,yourtenant.onmicrosoft.com'
@description('Provide the Document library where you want to store the full email. IMPORTANT full path, with trailing /')
param SharepointDocumentLibrary string = 'https://tenant.sharepoint.com/sites/DLPArchive/'
@description('Log Analytics Workspace ID for the Sentinel instance you wish to use.')
param LogAnalayticsWorkspaceID string
@secure()
@description('Log Analytics Workspace key for the Sentinel instance you wish to use.')
param LogAnalyticsWorkspaceKey string
@description('Log Analytics Workspace name for the Sentinel instance you wish to use.')
param LogAnalyticsWorkspaceName string
@description('Azure Resource ID of the Log Analytics Workspace where you would like the DLP and optional Function App Application Insights data to reside. The format is: "/subscriptions/xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx/resourcegroups/xxxxxxxx/providers/microsoft.operationalinsights/workspaces/xxxxxxxx"')
param LogAnalyticsWorkspaceResourceID string
@description('Uri where the post deployment script is located. This is used to publish the Function App code after the resources have been deploted. Use default value unless you are hosting the script somewhere else.')

var storageAccountName = 'functionapp${uniqueString(resourceGroup().id)}'
var location = resourceGroup().location
var functionAppPackageUri = 'https://raw.githubusercontent.com/anders-alex/O365-ActivityFeed-AzureFunction/Sentinel_Deployment/Sentinel_Deployment/functionPackage.zip'
var deploymentScriptUri = 'https://raw.githubusercontent.com/anders-alex/O365-ActivityFeed-AzureFunction/Sentinel_Deployment/Sentinel_Deployment/deploymentScript.ps1'

resource userAssignedMi 'Microsoft.ManagedIdentity/userAssignedIdentities@2022-01-31-preview' = {
  name: 'uami-${FunctionAppName}'
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
  name: '${storageAccount.name}/default/${toLower(FunctionAppName)}'
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

resource hostingPlan 'Microsoft.Web/serverfarms@2021-03-01' = {
  name: FunctionAppName
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
    value: LogAnalyticsWorkspaceKey
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
          name: 'AzureWebJobs.Enablement.Disabled'
          value: '1'
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
          value: 'O365DLP'
        }
        {
          name: 'domains'
          value: TrustedDomains
        }
        {
          name: 'SPUS'
          value: SharepointDocumentLibrary
        }
        {
          name: 'storageQueue'
          value: 'dlpqueue'
        }
        {
          name: 'endpointstorageQueue'
          value: 'endpointqueue'
        }
        {
          name: 'tenantDomain'
          value: TenantDomain
        }
        {
          name: 'TenantGuid'
          value: TenantID
        }
        {
          name: 'workspaceId'
          value: LogAnalayticsWorkspaceID
        }
        {
          name: 'workspaceKey'
          value: '@Microsoft.KeyVault(VaultName=${KeyVaultName};SecretName=LawKey)'
        }
        {
          name: 'SentinelWorkspace'
          value: LogAnalyticsWorkspaceName
        }
        {
          name: 'UamiClientId'
          value: userAssignedMi.properties.clientId
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
  scope: resourceGroup(split(LogAnalyticsWorkspaceResourceID, '/')[2], split(LogAnalyticsWorkspaceResourceID, '/')[4])
  name: 'rbacAssignmentLaw'
  params: {
    principalId: userAssignedMi.properties.principalId
    roleDefId: '/providers/Microsoft.Authorization/roleDefinitions/ab8e14d6-4a74-4a29-9ba8-549422addade'
    scopedResourceName: split(LogAnalyticsWorkspaceResourceID, '/')[8]
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
    primaryScriptUri: deploymentScriptUri
    arguments: '-PackageUri ${functionAppPackageUri} -SubscriptionId ${split(subscription().id, '/')[2]} -ResourceGroupName ${resourceGroup().name} -FunctionAppName ${functionApp.name} -FAScope ${functionApp.id} -UAMIPrincipalId ${userAssignedMi.properties.principalId}'
  }
}