param lawName string


resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: lawName
}

resource watchlistPolicy 'Microsoft.SecurityInsights/watchlists@2023-02-01' = {
  name: 'Policy'
  scope: workspace
  properties: {
    displayName: 'Policy'
    itemsSearchKey: 'Name'
    provider: 'DLP'
    source: 'DLP'
    contentType: 'text/csv'
    numberOfLinesToSkip: 0
    description: 'DLP Policies'
    rawContent: '''
Name,Workload
Default,Exchange
'''
  }
}

resource watchlistSL 'Microsoft.SecurityInsights/watchlists@2023-02-01' = {
  name: 'SensitivityLabels'
  scope: workspace
  properties: {
    displayName: 'SensitivityLabels'
    itemsSearchKey: 'id'
    provider: 'DLP'
    source: 'DLP'
    contentType: 'text/csv'
    numberOfLinesToSkip: 0
    description: 'Sensitivity Labels'
    rawContent: '''
id,name,parent
defa4170-0d19-0005-000b-bc8871434242,Specific People, Highly Confidential
'''
  }
}
