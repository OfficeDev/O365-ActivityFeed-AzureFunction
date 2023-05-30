param workspace string
param policySync bool = false

resource sentinelRuleAll 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2022-11-01-preview' = if(policySync == false) {
  name: '${workspace}/Microsoft.SecurityInsights/64621844-3809-45b1-a072-50b93283e095'
  kind: 'Scheduled'
  properties: {
    displayName: 'Microsoft DLP Incident Creation'
    description: ''
    severity: 'Medium'
    enabled: true
    query: 'let AlertProductName = \'Microsoft Data Loss Prevention (Custom)\';\r\nlet Workloads = dynamic([\'Endpoint\', \'SharePoint\', \'OneDrive\', \'Exchange\', \'MicrosoftTeams\']);\r\n\r\nPurviewDLP(Workloads,true)\r\n| extend Product = AlertProductName\r\n| join kind=leftanti (SecurityAlert\r\n    | where TimeGenerated > ago(12h)\r\n    | where ProductName == AlertProductName\r\n    | extend Identifier = substring(AlertLink, indexof(AlertLink, \'eventid=\') + 8, indexof(AlertLink, \'&creationtime\') - indexof(AlertLink, \'eventid=\') - 8)\r\n    ) on Identifier\r\n| order by TimeGenerated asc'
    queryFrequency: 'PT6M'
    queryPeriod: 'PT8H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
      'Exfiltration'
    ]
    techniques: []
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: true
        lookbackDuration: 'PT45M'
        matchingMethod: 'Selected'
        groupByEntities: [
          'Account'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: '{{RuleName}} ({{Workload}})'
      alertDescriptionFormat: 'Microsoft Purview DLP ({{Workload}}) alert for {{UserPrincipalName}}. Use the alert link to view more details about the events within the alert.'
      alertSeverityColumnName: 'RuleSeverity'
      alertDynamicProperties: [
        {
          alertProperty: 'AlertLink'
          value: 'Deeplink'
        }
        {
          alertProperty: 'ProductName'
          value: 'Product'
        }
      ]
    }
    customDetails: {
      User: 'UserPrincipalName'
      JobTitle: 'jobTitle'
      Department: 'department'
      Manager: 'manager'
      Location: 'usageLocation'
      Workload: 'Workload'
      MatchCount: 'TotalMatchCount'
      SensitiveInfo: 'SensitiveInfoTypes'
      ActionsTaken: 'ActionsTaken'
      SharedWith: 'TargetUserOrGroupName'
      DetectedLocations: 'DetectedLocations'
      SensitivityLabels: 'SensitivityLabels'
      Subject: 'EmailSubject'
      Operation: 'EndpointOperation'
      Application: 'EndpointApplication'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'AadUserId'
            columnName: 'UserObjectId'
          }
          {
            identifier: 'Name'
            columnName: 'Username'
          }
          {
            identifier: 'UPNSuffix'
            columnName: 'UPNSuffix'
          }
        ]
      }
      {
        entityType: 'File'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'Filename'
          }
          {
            identifier: 'Directory'
            columnName: 'FileDirectory'
          }
        ]
      }
      {
        entityType: 'MailMessage'
        fieldMappings: [
          {
            identifier: 'InternetMessageId'
            columnName: 'InternetMessageId'
          }
          {
            identifier: 'Recipient'
            columnName: 'Recipients'
          }
          {
            identifier: 'Sender'
            columnName: 'Sender'
          }
        ]
      }
      {
        entityType: 'FileHash'
        fieldMappings: [
          {
            identifier: 'Algorithm'
            columnName: 'FileHashAlgorithm'
          }
          {
            identifier: 'Value'
            columnName: 'FileHash'
          }
        ]
      }
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'DnsDomain'
            columnName: 'DeviceDNSName'
          }
          {
            identifier: 'HostName'
            columnName: 'DeviceHostName'
          }
          {
            identifier: 'FullName'
            columnName: 'DeviceFullName'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}

resource sentinelRuleEndpoint 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2022-11-01-preview' = if(policySync == true) {
  name: '${workspace}/Microsoft.SecurityInsights/da07a488-6336-4854-bc4d-cbfc5d7f52d5'
  kind: 'Scheduled'
  properties: {
    displayName: 'Microsoft DLP Incident Creation Template (Endpoint)'
    description: ''
    severity: 'Medium'
    enabled: true
    query: 'let AlertProductName = \'Microsoft Data Loss Prevention (Custom)\';\r\nlet Workloads = dynamic([\'Endpoint\']);\r\n\r\nlet CurrentPolicies = (PurviewDLP_CL\r\n    | where TimeGenerated > ago(90d) and Workload in (Workloads)\r\n    | mv-expand PolicyDetails\r\n    | extend Name = tostring(PolicyDetails.PolicyName)\r\n    | where Name != ""\r\n    | summarize by Name);\r\n\r\nlet policywatchlist =(_GetWatchlist(\'Policy\')\r\n    | where Workload in (Workloads) and Name in (CurrentPolicies)\r\n    | project SearchKey);\r\n\r\nPurviewDLP(Workloads,true)\r\n| where PolicyName != "" //Do Not Remove\r\n| where not(PolicyName has_any (policywatchlist)) //Do not remove\r\n| extend Product = AlertProductName\r\n| order by TimeGenerated'
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
      'Exfiltration'
    ]
    techniques: []
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: true
        lookbackDuration: 'PT45M'
        matchingMethod: 'Selected'
        groupByEntities: [
          'Account'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: '{{RuleName}} ({{Workload}})'
      alertDescriptionFormat: 'Microsoft Purview DLP ({{Workload}}) alert for {{UserPrincipalName}}. Use the alert link to view more details about the events within the alert.'
      alertSeverityColumnName: 'RuleSeverity'
      alertDynamicProperties: [
        {
          alertProperty: 'AlertLink'
          value: 'Deeplink'
        }
        {
          alertProperty: 'ProductName'
          value: 'Product'
        }
      ]
    }
    customDetails: {
      User: 'UserPrincipalName'
      JobTitle: 'jobTitle'
      Department: 'department'
      Manager: 'manager'
      Location: 'usageLocation'
      Workload: 'Workload'
      MatchCount: 'TotalMatchCount'
      SensitiveInfo: 'SensitiveInfoTypes'
      ActionsTaken: 'ActionsTaken'
      SharedWith: 'TargetUserOrGroupName'
      DetectedLocations: 'DetectedLocations'
      SensitivityLabels: 'SensitivityLabels'
      Subject: 'EmailSubject'
      Operation: 'EndpointOperation'
      Application: 'EndpointApplication'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'AadUserId'
            columnName: 'UserObjectId'
          }
          {
            identifier: 'Name'
            columnName: 'Username'
          }
          {
            identifier: 'UPNSuffix'
            columnName: 'UserPrincipalName'
          }
        ]
      }
      {
        entityType: 'File'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'Filename'
          }
          {
            identifier: 'Directory'
            columnName: 'FileDirectory'
          }
        ]
      }
      {
        entityType: 'MailMessage'
        fieldMappings: [
          {
            identifier: 'InternetMessageId'
            columnName: 'InternetMessageId'
          }
          {
            identifier: 'Recipient'
            columnName: 'Recipients'
          }
          {
            identifier: 'Sender'
            columnName: 'Sender'
          }
        ]
      }
      {
        entityType: 'FileHash'
        fieldMappings: [
          {
            identifier: 'Algorithm'
            columnName: 'FileHashAlgorithm'
          }
          {
            identifier: 'Value'
            columnName: 'FileHash'
          }
        ]
      }
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'DnsDomain'
            columnName: 'DeviceDNSName'
          }
          {
            identifier: 'HostName'
            columnName: 'DeviceHostName'
          }
          {
            identifier: 'FullName'
            columnName: 'DeviceFullName'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}

resource sentinelRuleEXOT 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2022-11-01-preview' = if(policySync == true) {
  name: '${workspace}/Microsoft.SecurityInsights/fb51d8a8-575c-4aea-8d90-42bf9a4aca1c'
  kind: 'Scheduled'
  properties: {
    displayName: 'Microsoft DLP Incident Creation Template (EXOT)'
    description: ''
    severity: 'Medium'
    enabled: true
    query: 'let AlertProductName = \'Microsoft Data Loss Prevention (Custom)\';\r\nlet Workloads = dynamic([\'Exchange\', \'MicrosoftTeams\']);\r\n\r\nlet CurrentPolicies = (PurviewDLP_CL\r\n    | where TimeGenerated > ago(90d) and Workload in (Workloads)\r\n    | mv-expand PolicyDetails\r\n    | extend Name = tostring(PolicyDetails.PolicyName)\r\n    | where Name != ""\r\n    | summarize by Name);\r\n\r\nlet policywatchlist =(_GetWatchlist(\'Policy\')\r\n    | where Workload in (Workloads) and Name in (CurrentPolicies)\r\n    | project SearchKey);\r\n\r\nPurviewDLP(Workloads,true)\r\n| where PolicyName != "" //Do Not Remove\r\n| where not(PolicyName has_any (policywatchlist)) //Do not remove\r\n| extend Product = AlertProductName\r\n| order by TimeGenerated'
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
      'Exfiltration'
    ]
    techniques: []
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: true
        lookbackDuration: 'PT45M'
        matchingMethod: 'Selected'
        groupByEntities: [
          'Account'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: '{{RuleName}} ({{Workload}})'
      alertDescriptionFormat: 'Microsoft Purview DLP ({{Workload}}) alert for {{UserPrincipalName}}. Use the alert link to view more details about the events within the alert.'
      alertSeverityColumnName: 'RuleSeverity'
      alertDynamicProperties: [
        {
          alertProperty: 'AlertLink'
          value: 'Deeplink'
        }
        {
          alertProperty: 'ProductName'
          value: 'Product'
        }
      ]
    }
    customDetails: {
      User: 'UserPrincipalName'
      JobTitle: 'jobTitle'
      Department: 'department'
      Manager: 'manager'
      Location: 'usageLocation'
      Workload: 'Workload'
      MatchCount: 'TotalMatchCount'
      SensitiveInfo: 'SensitiveInfoTypes'
      ActionsTaken: 'ActionsTaken'
      SharedWith: 'TargetUserOrGroupName'
      DetectedLocations: 'DetectedLocations'
      SensitivityLabels: 'SensitivityLabels'
      Subject: 'EmailSubject'
      Operation: 'EndpointOperation'
      Application: 'EndpointApplication'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'AadUserId'
            columnName: 'UserObjectId'
          }
          {
            identifier: 'Name'
            columnName: 'Username'
          }
          {
            identifier: 'UPNSuffix'
            columnName: 'UserPrincipalName'
          }
        ]
      }
      {
        entityType: 'File'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'Filename'
          }
          {
            identifier: 'Directory'
            columnName: 'FileDirectory'
          }
        ]
      }
      {
        entityType: 'MailMessage'
        fieldMappings: [
          {
            identifier: 'InternetMessageId'
            columnName: 'InternetMessageId'
          }
          {
            identifier: 'Recipient'
            columnName: 'Recipients'
          }
          {
            identifier: 'Sender'
            columnName: 'Sender'
          }
        ]
      }
      {
        entityType: 'FileHash'
        fieldMappings: [
          {
            identifier: 'Algorithm'
            columnName: 'FileHashAlgorithm'
          }
          {
            identifier: 'Value'
            columnName: 'FileHash'
          }
        ]
      }
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'DnsDomain'
            columnName: 'DeviceDNSName'
          }
          {
            identifier: 'HostName'
            columnName: 'DeviceHostName'
          }
          {
            identifier: 'FullName'
            columnName: 'DeviceFullName'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}

resource sentinelRuleSPOD 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2022-11-01-preview' = if(policySync == true) {
  name: '${workspace}/Microsoft.SecurityInsights/00036c1a-b3b5-4a54-bb53-bdb5df05cb6b'
  kind: 'Scheduled'
  properties: {
    displayName: 'Microsoft DLP Incident Creation Template (SPOT)'
    description: ''
    severity: 'Medium'
    enabled: true
    query: 'let AlertProductName = \'Microsoft Data Loss Prevention (Custom)\';\r\nlet Workloads = dynamic([\'SharePoint\', \'OneDrive\']);\r\n\r\nlet CurrentPolicies = (PurviewDLP_CL\r\n    | where TimeGenerated > ago(90d) and Workload in (Workloads)\r\n    | mv-expand PolicyDetails\r\n    | extend Name = tostring(PolicyDetails.PolicyName)\r\n    | where Name != ""\r\n    | summarize by Name);\r\n\r\nlet policywatchlist =(_GetWatchlist(\'Policy\')\r\n    | where Workload in (Workloads) and Name in (CurrentPolicies)\r\n    | project SearchKey);\r\n\r\nPurviewDLP(Workloads,true)\r\n| where PolicyName != "" //Do Not Remove\r\n| where not(PolicyName has_any (policywatchlist)) //Do not remove\r\n| extend Product = AlertProductName\r\n| order by TimeGenerated'
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
      'Exfiltration'
    ]
    techniques: []
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: true
        lookbackDuration: 'PT45M'
        matchingMethod: 'Selected'
        groupByEntities: [
          'Account'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: '{{RuleName}} ({{Workload}})'
      alertDescriptionFormat: 'Microsoft Purview DLP ({{Workload}}) alert for {{UserPrincipalName}}. Use the alert link to view more details about the events within the alert.'
      alertSeverityColumnName: 'RuleSeverity'
      alertDynamicProperties: [
        {
          alertProperty: 'AlertLink'
          value: 'Deeplink'
        }
        {
          alertProperty: 'ProductName'
          value: 'Product'
        }
      ]
    }
    customDetails: {
      User: 'UserPrincipalName'
      JobTitle: 'jobTitle'
      Department: 'department'
      Manager: 'manager'
      Location: 'usageLocation'
      Workload: 'Workload'
      MatchCount: 'TotalMatchCount'
      SensitiveInfo: 'SensitiveInfoTypes'
      ActionsTaken: 'ActionsTaken'
      SharedWith: 'TargetUserOrGroupName'
      DetectedLocations: 'DetectedLocations'
      SensitivityLabels: 'SensitivityLabels'
      Subject: 'EmailSubject'
      Operation: 'EndpointOperation'
      Application: 'EndpointApplication'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'AadUserId'
            columnName: 'UserObjectId'
          }
          {
            identifier: 'Name'
            columnName: 'Username'
          }
          {
            identifier: 'UPNSuffix'
            columnName: 'UserPrincipalName'
          }
        ]
      }
      {
        entityType: 'File'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'Filename'
          }
          {
            identifier: 'Directory'
            columnName: 'FileDirectory'
          }
        ]
      }
      {
        entityType: 'MailMessage'
        fieldMappings: [
          {
            identifier: 'InternetMessageId'
            columnName: 'InternetMessageId'
          }
          {
            identifier: 'Recipient'
            columnName: 'Recipients'
          }
          {
            identifier: 'Sender'
            columnName: 'Sender'
          }
        ]
      }
      {
        entityType: 'FileHash'
        fieldMappings: [
          {
            identifier: 'Algorithm'
            columnName: 'FileHashAlgorithm'
          }
          {
            identifier: 'Value'
            columnName: 'FileHash'
          }
        ]
      }
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'DnsDomain'
            columnName: 'DeviceDNSName'
          }
          {
            identifier: 'HostName'
            columnName: 'DeviceHostName'
          }
          {
            identifier: 'FullName'
            columnName: 'DeviceFullName'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}

