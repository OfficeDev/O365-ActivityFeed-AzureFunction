@description('Name for Data Collection Endpoint used to ingest data into Log Analytics workspace.')
param DataCollectionEndpointName string = 'dce-mdvm-${uniqueString(resourceGroup().id)}'
@description('Name for Data Collection Rule used to ingest data into Log Analytics workspace.')
param DataCollectionRuleName string = 'dcr-mdmv-${uniqueString(resourceGroup().id)}'
@description('Azure Resource Id of the Log Analytics Workspace where you like the MDVM and optional Function App Application Insights data to reside. The format is: "/subscriptions/xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx/resourcegroups/xxxxxxxx/providers/microsoft.operationalinsights/workspaces/xxxxxxxx"')
param LogAnalyticsWorkspaceResourceId string
@description('Azure location/region of the Log Analytics Workspace referenced in the LogAnalyticsWorkspaceResourceId parameter.')
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
@description('Optional: Managed Identity or Service Principal ID to be assigned the Metrics Publisher role on the data collection rule.')
param ServicePrincipalId string = ''

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2021-09-01-preview' = {
  name: DataCollectionEndpointName
  location: LogAnalyticsWorkspaceLocation
  properties: {}
}

resource roleAssignmentDcr 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = if (ServicePrincipalId != '') {
  name: guid(dcr.id, '/providers/Microsoft.Authorization/roleDefinitions/3913510d-42f4-4e42-8a64-420c390055eb')
  scope: dcr
  properties: {
    roleDefinitionId: '/providers/Microsoft.Authorization/roleDefinitions/3913510d-42f4-4e42-8a64-420c390055eb'
    principalId: ServicePrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2021-09-01-preview' = {
  dependsOn: [
    tablePurviewDLP
  ]
  name: DataCollectionRuleName
  location: LogAnalyticsWorkspaceLocation
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      'Custom-PurviewDLP_CL': {
        columns: [
          {
            name: 'TimeGenerated'
            type: 'datetime'
          }
          {
            name: 'CreationTime'
            type: 'datetime'
          }
          {
            name: 'Identifier'
            type: 'string'
          }
          {
            name: 'Operation'
            type: 'string'
          }
          {
            name: 'OrganizationId'
            type: 'string'
          }
          {
            name: 'RecordType'
            type: 'int'
          }
          {
            name: 'UserKey'
            type: 'string'
          }
          {
            name: 'UserType'
            type: 'int'
          }
          {
            name: 'Version'
            type: 'int'
          }
          {
            name: 'Workload'
            type: 'string'
          }
          {
            name: 'ObjectId'
            type: 'string'
          }
          {
            name: 'UserId'
            type: 'string'
          }
          {
            name: 'IncidentId'
            type: 'string'
          }
          {
            name: 'PolicyDetails'
            type: 'dynamic'
          }
          {
            name: 'SensitiveInfoDetectionIsIncluded'
            type: 'boolean'
          }
          {
            name: 'SharePointMetaData'
            type: 'dynamic'
          }
          {
            name: 'ExchangeMetaData'
            type: 'dynamic'
          }
          {
            name: 'EndpointMetaData'
            type: 'dynamic'
          }
          {
            name: 'EvidenceFile'
            type: 'dynamic'
          }
          {
            name: 'Scope'
            type: 'int'
          }
          {
            name: 'DocumentName'
            type: 'string'
          }
          {
            name: 'usageLocation'
            type: 'string'
          }
          {
            name: 'department'
            type: 'string'
          }
          {
            name: 'manager'
            type: 'string'
          }
          {
            name: 'originalContent'
            type: 'string'
          }
        ]        
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: split(LogAnalyticsWorkspaceResourceId, '/')[8]
          workspaceResourceId: LogAnalyticsWorkspaceResourceId
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Custom-PurviewDLP_CL'
        ]
        destinations: [
          split(LogAnalyticsWorkspaceResourceId, '/')[8]
        ]
        transformKql: 'source'
        outputStream: 'Custom-PurviewDLP_CL'
      }
    ]
  }
}

module tablePurviewDLP 'lawCustomTable.bicep' = {
  name: 'tablePurviewDLP'
  scope: resourceGroup(split(LogAnalyticsWorkspaceResourceId, '/')[2], split(LogAnalyticsWorkspaceResourceId, '/')[4])
  params: {
    lawName: split(LogAnalyticsWorkspaceResourceId, '/')[8]
    tableName: 'PurviewDLP_CL'
    plan: 'Analytics'
    columns: [
      {
        name: 'TimeGenerated'
        type: 'datetime'
      }
      {
        name: 'CreationTime'
        type: 'datetime'
      }
      {
        name: 'Identifier'
        type: 'string'
      }
      {
        name: 'Operation'
        type: 'string'
      }
      {
        name: 'OrganizationId'
        type: 'string'
      }
      {
        name: 'RecordType'
        type: 'int'
      }
      {
        name: 'UserKey'
        type: 'string'
      }
      {
        name: 'UserType'
        type: 'int'
      }
      {
        name: 'Version'
        type: 'int'
      }
      {
        name: 'Workload'
        type: 'string'
      }
      {
        name: 'ObjectId'
        type: 'string'
      }
      {
        name: 'UserId'
        type: 'string'
      }
      {
        name: 'IncidentId'
        type: 'string'
      }
      {
        name: 'PolicyDetails'
        type: 'dynamic'
      }
      {
        name: 'SensitiveInfoDetectionIsIncluded'
        type: 'boolean'
      }
      {
        name: 'SharePointMetaData'
        type: 'dynamic'
      }
      {
        name: 'ExchangeMetaData'
        type: 'dynamic'
      }
      {
        name: 'EndpointMetaData'
        type: 'dynamic'
      }
      {
        name: 'EvidenceFile'
        type: 'dynamic'
      }
      {
        name: 'Scope'
        type: 'int'
      }
      {
        name: 'DocumentName'
        type: 'string'
      }
      {
        name: 'usageLocation'
        type: 'string'
      }
      {
        name: 'department'
        type: 'string'
      }
      {
        name: 'manager'
        type: 'string'
      }
      {
        name: 'originalContent'
        type: 'string'
      }
    ]    
  }
}

output DcrImmutableId string = dcr.properties.immutableId
output DceUri string = dce.properties.logsIngestion.endpoint
output DcrName string = dcr.name
