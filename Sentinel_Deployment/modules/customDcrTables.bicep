@description('Name for Data Collection Endpoint used to ingest data into Log Analytics workspace.')
param DataCollectionEndpointName string = 'dce-${uniqueString(resourceGroup().id)}'
@description('Name for Data Collection Rule used to ingest data into Log Analytics workspace.')
param DataCollectionRuleName string = 'dcr-${uniqueString(resourceGroup().id)}'
@description('Azure Resource Id of the Log Analytics Workspace where you like the data and optional Function App Application Insights data to reside. The format is: "/subscriptions/xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx/resourcegroups/xxxxxxxx/providers/microsoft.operationalinsights/workspaces/xxxxxxxx"')
param LogAnalyticsWorkspaceResourceId string
@description('Azure location/region of the Log Analytics Workspace referenced in the LogAnalyticsWorkspaceResourceId parameter.')
param LogAnalyticsWorkspaceLocation string
@description('Optional: Managed Identity or Service Principal ID to be assigned the Metrics Publisher role on the data collection rule.')
param ServicePrincipalId string = ''

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2021-09-01-preview' = {
  name: DataCollectionEndpointName
  location: LogAnalyticsWorkspaceLocation
  properties: {}
}

resource roleAssignmentDcr 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = if (ServicePrincipalId != '') {
  name: guid(dcr.id, '/providers/Microsoft.Authorization/roleDefinitions/3913510d-42f4-4e42-8a64-420c390055eb', ServicePrincipalId)
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
          {
            name: 'ExceptionInfo'
            type: 'dynamic'
          }
          {
            name: 'jobTitle'
            type: 'string'
          }
        ]        
      }
      'Custom-PurviewDLPSIT_CL': {
        columns: [
          {
            name: 'TimeGenerated'
            type: 'datetime'
          }
          {
            name: 'Identifier'
            type: 'string'
          }
          {
            name: 'ClassifierType'
            type: 'string'
          }
          {
            name: 'Confidence'
            type: 'int'
          }
          {
            name: 'Location'
            type: 'string'
          }
          {
            name: 'SensitiveInformationTypeName'
            type: 'string'
          }
          {
            name: 'SensitiveType'
            type: 'string'
          }
          {
            name: 'UniqueCount'
            type: 'int'
          }
          {
            name: 'PolicyId'
            type: 'string'
          }
          {
            name: 'RuleId'
            type: 'string'
          }
          {
            name: 'DetectionResultsTruncated'
            type: 'boolean'
          }
          {
            name: 'ClassificationAttributes'
            type: 'dynamic'
          }
          {
            name: 'SITCount'
            type: 'int'
          }
          {
            name: 'SensitiveInfoId'
            type: 'string'
          }
        ]        
      }
      'Custom-PurviewDLPDetections_CL': {
        columns: [
          {
            name: 'TimeGenerated'
            type: 'datetime'
          }
          {
            name: 'Identifier'
            type: 'string'
          }
          {
            name: 'Name'
            type: 'string'
          }
          {
            name: 'Value'
            type: 'string'
          }
          {
            name: 'SensitiveType'
            type: 'string'
          }
          {
            name: 'SensitiveInfoTypeName'
            type: 'string'
          }
          {
            name: 'SensitiveInfoId'
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
      {
        streams: [
          'Custom-PurviewDLPSIT_CL'
        ]
        destinations: [
          split(LogAnalyticsWorkspaceResourceId, '/')[8]
        ]
        transformKql: 'source'
        outputStream: 'Custom-PurviewDLPSIT_CL'
      }
      {
        streams: [
          'Custom-PurviewDLPDetections_CL'
        ]
        destinations: [
          split(LogAnalyticsWorkspaceResourceId, '/')[8]
        ]
        transformKql: 'source'
        outputStream: 'Custom-PurviewDLPDetections_CL'
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
      {
        name: 'ExceptionInfo'
        type: 'dynamic'
      }
      {
        name: 'jobTitle'
        type: 'string'
      }
    ]    
  }
}

module tablePurviewDLPSIT 'lawCustomTable.bicep' = {
  name: 'tablePurviewDLPSIT'
  scope: resourceGroup(split(LogAnalyticsWorkspaceResourceId, '/')[2], split(LogAnalyticsWorkspaceResourceId, '/')[4])
  params: {
    lawName: split(LogAnalyticsWorkspaceResourceId, '/')[8]
    tableName: 'PurviewDLPSIT_CL'
    plan: 'Analytics'
    columns: [
      {
        name: 'TimeGenerated'
        type: 'datetime'
      }
      {
        name: 'Identifier'
        type: 'string'
      }
      {
        name: 'ClassifierType'
        type: 'string'
      }
      {
        name: 'Confidence'
        type: 'int'
      }
      {
        name: 'Location'
        type: 'string'
      }
      {
        name: 'SensitiveInformationTypeName'
        type: 'string'
      }
      {
        name: 'UserTypeSensitiveType'
        type: 'string'
      }
      {
        name: 'UniqueCount'
        type: 'int'
      }
      {
        name: 'PolicyId'
        type: 'string'
      }
      {
        name: 'RuleId'
        type: 'string'
      }
      {
        name: 'DetectionResultsTruncated'
        type: 'boolean'
      }
      {
        name: 'ClassificationAttributes'
        type: 'dynamic'
      }
      {
        name: 'SITCount'
        type: 'int'
      }
      {
        name: 'SensitiveInfoId'
        type: 'string'
      }
    ]    
  }
}

module tablePurviewDLPDetections 'lawCustomTable.bicep' = {
  name: 'tablePurviewDLPDetections'
  scope: resourceGroup(split(LogAnalyticsWorkspaceResourceId, '/')[2], split(LogAnalyticsWorkspaceResourceId, '/')[4])
  params: {
    lawName: split(LogAnalyticsWorkspaceResourceId, '/')[8]
    tableName: 'PurviewDLPDetections_CL'
    plan: 'Analytics'
    columns: [
      {
        name: 'TimeGenerated'
        type: 'datetime'
      }
      {
        name: 'Identifier'
        type: 'string'
      }
      {
        name: 'Name'
        type: 'string'
      }
      {
        name: 'Value'
        type: 'string'
      }
      {
        name: 'SensitiveType'
        type: 'string'
      }
      {
        name: 'SensitiveInfoTypeName'
        type: 'string'
      }
      {
        name: 'SensitiveInfoId'
        type: 'string'
      }
    ]    
  }
}

output DcrImmutableId string = dcr.properties.immutableId
output DceUri string = dce.properties.logsIngestion.endpoint
output DcrName string = dcr.name
