param lawName string
param functionName string
param category string
param displayName string
param query string
param functionParams string = ''
param functionAlias string

resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: lawName
}

resource function 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
  parent: logAnalyticsWorkspace 
  name: functionName
  properties: {
    category: category 
    displayName: displayName 
    query: query
    functionParameters: functionParams
    functionAlias: functionAlias
  }
}
