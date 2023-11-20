param lawName string
param principalId string
param roleName string = 'Custom Role - Sentinel DLP Contributor'

resource law 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
 name: lawName  
}

resource tablePurviewDLP 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' existing = {
  parent: law
  name: 'PurviewDLP_CL'
}

resource tableWatchlist 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' existing = {
  parent: law
  name: 'Watchlist'
}

@description('Array of actions for the roleDefinition')
param actions array = [
  'Microsoft.SecurityInsights/alertRules/write'
  'Microsoft.SecurityInsights/alertRules/read'
  'Microsoft.OperationalInsights/workspaces/read'
  'Microsoft.OperationalInsights/workspaces/query/read'
  'Microsoft.OperationalInsights/workspaces/analytics/query/action'
  'Microsoft.OperationalInsights/workspaces/search/action'
]

@description('Array of notActions for the roleDefinition')
param notActions array = [
  'Microsoft.OperationalInsights/workspaces/sharedKeys/read'
]

var roleDescription = 'Provides access to query Sentinel Watchlists and alert rules. Also provides limited permissions to read workspace details and run a query in the workspace, but not to read data from any tables.'

var roleDefName = guid(resourceGroup().id, string(actions), string(notActions))

resource roleDef 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: roleDefName
  properties: {
    roleName: roleName
    description: roleDescription
    type: 'customRole'
    permissions: [
      {
        actions: actions
        notActions: notActions
      }
    ]
    assignableScopes: [
      resourceGroup().id
    ]
  }
}

resource roleAssignmentWorkspace 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(law.id, roleDef.id, principalId)
  scope: law
  properties: {
    roleDefinitionId: roleDef.id
    principalId: principalId
    principalType: 'ServicePrincipal'
  }
}

var roleIdReader = '/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7'

resource roleAssignmentPurviewDLP 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(tablePurviewDLP.id, roleIdReader, principalId)
  scope: tablePurviewDLP
  properties: {
    roleDefinitionId: roleIdReader
    principalId: principalId
    principalType: 'ServicePrincipal'
  }
}

resource roleAssignmentWatchlist 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(tableWatchlist.id, roleIdReader, principalId)
  scope: tableWatchlist
  properties: {
    roleDefinitionId: roleIdReader
    principalId: principalId
    principalType: 'ServicePrincipal'
  }
}
