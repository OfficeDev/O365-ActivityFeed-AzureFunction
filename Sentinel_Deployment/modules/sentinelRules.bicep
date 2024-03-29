param lawId string
param policySync bool = false
param guids array = [
  guid(lawId, '21a0c0e5-7633-4e0f-945d-886d653d658a')
  guid(lawId, 'c484978b-7cf8-4034-a49c-3ff347234842')
  guid(lawId, 'adcc3e90-dfda-44e0-b2fa-c34364bb7f70')
  guid(lawId, 'e2a469c4-9c65-4d82-9b48-f0662971a09e')
  guid(lawId, '53be747c-c4f7-49d0-9386-62371514a283')
  guid(lawId, 'f76a9cbd-fe00-42f2-815d-421de9c0cc04')
]

var workloads = loadJsonContent('../functionPackage/SyncDLPAnalyticsRules/workloads.json')
var querySyncVar1 = 'let Workloads = dynamic(WORKLOADSREPLACE);\r\n'
var querySyncVar2 = 'let WorkloadAlias = "WORKLOADALIASREPLACE";\r\n'
var querySync = 'let AlertProductName = "Microsoft Data Loss Prevention (Custom)";\r\n\r\nlet PolicyWatchlist = _GetWatchlist("Policy")\r\n    | extend Workload = column_ifexists("Workload", ""), Name = column_ifexists("Name", "")\r\n    | where Workload == WorkloadAlias\r\n    | project SearchKey;\r\n\r\nPurviewDLP(Workloads, true)\r\n| where PolicyName != "" //Do Not Remove\r\n| where not(PolicyName has_any (PolicyWatchlist)) //Do not remove\r\n| extend Product = AlertProductName\r\n| order by TimeGenerated'
var queryAll = 'let AlertProductName = "Microsoft Data Loss Prevention (Custom)";\r\n\r\nPurviewDLP\r\n| extend Product = AlertProductName\r\n| order by TimeGenerated'

resource sentinelRuleAll 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2022-11-01-preview' = if (policySync == false) {
  name: '${split(lawId, '/')[8]}/Microsoft.SecurityInsights/${guid(lawId, 'e4243705-c479-4e14-8443-7bad89119ba5')}'
  kind: 'Scheduled'
  properties: {
    displayName: 'Microsoft DLP Incident Creation'
    description: ''
    severity: 'Medium'
    enabled: true
    query: queryAll
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
      CreationTime: 'CreationTimeString'
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

resource sentinelRuleSync 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2022-11-01-preview' = [for (workload, i) in workloads: if (policySync == true) {
  name: '${split(lawId, '/')[8]}/Microsoft.SecurityInsights/${guids[i]}'
  kind: 'Scheduled'
  properties: {
    displayName: 'Microsoft DLP Incident Creation Template (${workload.Alias})'
    description: ''
    severity: 'Medium'
    enabled: true
    query: concat(replace(querySyncVar1, 'WORKLOADSREPLACE', string(workload.Names)), replace(querySyncVar2, 'WORKLOADALIASREPLACE', workload.Alias), querySync)
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
      CreationTime: 'CreationTimeString'
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
    entityMappings: workload.Alias == 'EXOT' ? [
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
    ] : [
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
}]
