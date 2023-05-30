param workspace string
param policySync bool = false

resource workspace_Microsoft_SecurityInsights_64621844_3809_45b1_a072_50b93283e095 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2022-11-01-preview' = if(policySync == false) {
  name: '${workspace}/Microsoft.SecurityInsights/64621844-3809-45b1-a072-50b93283e095'
  kind: 'Scheduled'
  properties: {
    displayName: 'Microsoft DLP Incident Creation'
    description: ''
    severity: 'Medium'
    enabled: true
    query: 'let alertProductName = \'Microsoft Data Loss Prevention (Custom)\';\r\nlet endpointSeverityMatchCountTrigger = 2;\r\n\r\nlet DLPCommon = PurviewDLP_CL\r\n| join kind=leftanti (SecurityAlert\r\n    | where TimeGenerated > ago(12h)\r\n    | where ProductName == alertProductName\r\n    | extend Identifier = substring(AlertLink, indexof(AlertLink, \'eventid=\') + 8, indexof(AlertLink, \'&creationtime\') - indexof(AlertLink, \'eventid=\') - 8)\r\n    ) on Identifier\r\n| mv-expand PolicyDetails\r\n| where PolicyDetails.PolicyName != \'\'\r\n| mv-expand Rules = PolicyDetails.Rules\r\n| mv-expand ActionsTaken = Rules.Actions\r\n| mv-expand SensitiveInfo = Rules.ConditionsMatched.SensitiveInformation\r\n| extend RulesString = tostring(Rules), SensitiveInfoString = tostring(SensitiveInfo)\r\n| summarize ActionsTaken = make_set(ActionsTaken), arg_max(TimeGenerated, *) by TimeGenerated, CreationTime, Identifier, RulesString, SensitiveInfoString\r\n| extend SensitiveInfoType = bag_pack(\'Name\', SensitiveInfo.SensitiveInformationTypeName, \'Count\', toint(SensitiveInfo.Count), \'Confidence\', toint(SensitiveInfo.Confidence))\r\n| extend\r\n    ActionsTaken = strcat_array(ActionsTaken, \', \'),\r\n    SensitiveInfoTypeString = strcat(SensitiveInfoType.Name, \' (\', SensitiveInfoType.Count, \', \', SensitiveInfoType.Confidence, \'%)\'),\r\n    Product = alertProductName,\r\n    PolicyName = tostring(PolicyDetails.PolicyName),\r\n    RuleName = tostring(Rules.RuleName),\r\n    RuleSeverity = tostring(Rules.Severity),\r\n    UserPrincipalName = tolower(UserId),\r\n    UserObjectId = UserKey,\r\n    Deeplink = strcat(\'https://compliance.microsoft.com/datalossprevention/alerts/eventdeeplink?eventid=\', Identifier, \'&creationtime=\', CreationTime)\r\n| order by TimeGenerated asc\r\n| take 150;\r\n\r\nlet DLPSPOD = DLPCommon\r\n| where Workload in (\'SharePoint\', \'OneDrive\')\r\n| mv-expand SensitivityLablelId = SharePointMetaData.SensitivityLablelIds\r\n| extend SensitivityLabelId = tostring(SharePointMetaData.SensitivityLablelId)\r\n| join kind = leftouter (_GetWatchlist(\'SensitivityLabels\')\r\n    | extend SensitivityLabelId = tostring(column_ifexists(\'id\', \'\')),\r\n        SensitivityLabelName = tostring(column_ifexists(\'name\', \'\'))) on SensitivityLabelId\r\n| extend OfficeObjectId = url_decode(tostring(SharePointMetaData.FilePathUrl))\r\n| extend CreationTimeBin = bin(CreationTime, 1m)\r\n| join kind = leftouter (OfficeActivity\r\n    | where ingestion_time() > ago(24h)\r\n    | where Operation == "AddedToSecureLink" or Operation == "SecureLinkUsed"\r\n    | extend CreationTimeBin = bin(TimeGenerated, 1m),\r\n        TargetUserOrGroupName = tolower(iff(isempty(TargetUserOrGroupName), split(UserId, "#")[1], TargetUserOrGroupName))\r\n    ) on OfficeObjectId, CreationTimeBin\r\n| extend Filename = tostring(SharePointMetaData.FileName),\r\n    FilePath = tostring(SharePointMetaData.FilePathUrl),\r\n    SiteUrl = tostring(SharePointMetaData.SiteCollectionUrl),\r\n    ExceptionReason = tostring(SharePointMetaData.ExceptionInfo.Reason)\r\n| summarize SensitiveInfoTypesArray = make_list(SensitiveInfoType), SensitiveInfoTypes = make_set(SensitiveInfoTypeString), TotalMatchCount = sum(toint(SensitiveInfoType.Count)), SensitivityLabels = make_list(SensitivityLabelName) by TimeGenerated, CreationTime, Identifier, Product, Workload, Deeplink, usageLocation, UserPrincipalName, UserObjectId, department, manager, jobTitle, PolicyName, RuleName, RuleSeverity, ActionsTaken, FilePath, Filename, SiteUrl, TargetUserOrGroupName, ExceptionReason, Operation;\r\n\r\nlet DLPEXOT = DLPCommon\r\n| where Workload in (\'Exchange\', \'MicrosoftTeams\')\r\n| extend Recipients = iff(Workload == \'Exchange\', tostring(strcat(array_strcat(ExchangeMetaData.To, \', \'), iff(array_length(ExchangeMetaData.CC) == 0, \'\', ", "), array_strcat(ExchangeMetaData.CC, \', \'), iff(array_length(ExchangeMetaData.BCC) == 0, \'\', ", "))), tostring(strcat_array(ExchangeMetaData.To, \', \'))),\r\n    InternetMessageId = replace_string(replace_string(tostring(ExchangeMetaData.MessageID), \'<\', \'\'), \'>\',\'\'),\r\n    EmailSubject = tostring(ExchangeMetaData.Subject),\r\n    Sender = UserPrincipalName,\r\n    ExceptionReason = tostring(ExchangeMetaData.ExceptionInfo.Reason)\r\n| summarize SensitiveInfoTypesArray = make_list(SensitiveInfoType), SensitiveInfoTypes = make_set(SensitiveInfoTypeString), TotalMatchCount = sum(toint(SensitiveInfoType.Count)), DetectedLocations = make_set(SensitiveInfo.Location) by TimeGenerated, CreationTime, Identifier, Product, Workload, Deeplink, usageLocation, UserPrincipalName, UserObjectId, department, manager, jobTitle, PolicyName, RuleName, RuleSeverity, ActionsTaken, Recipients, InternetMessageId, EmailSubject, Sender, ExceptionReason, Operation;\r\n\r\nlet EndpointAction = datatable(ActionName: string, ActionId: int) [\r\n    "None", "0",\r\n    "Audit", "1",\r\n    "Warn", "2",\r\n    "WarnAndBypass", "3",\r\n    "Block", "4",\r\n    "Allow", "5"\r\n];\r\n\r\nlet DLPEndpoint = DLPCommon\r\n| where Workload in (\'Endpoint\')\r\n| mv-expand SensitiveInfo = EndpointMetaData.SensitiveInfoTypeData\r\n| extend SensitiveInfoType = bag_pack(\'Name\', SensitiveInfo.SensitiveInfoTypeName, \'Count\', toint(SensitiveInfo.Count), \'Confidence\', toint(SensitiveInfo.Confidence)),\r\n    DeviceFullName = tostring(EndpointMetaData.DeviceName)\r\n| extend SensitiveInfoTypeString = strcat(SensitiveInfoType.Name, \' (\', SensitiveInfoType.Count, \', \', SensitiveInfoType.Confidence, \'%)\'),\r\n    ActionId = toint(EndpointMetaData.EnforcementMode),\r\n    ClientIP = tostring(EndpointMetaData.ClientIP),\r\n    DeviceHostName = tostring(split(DeviceFullName, \'.\')[0]), \r\n    DeviceDNSName = tostring(substring(DeviceFullName, indexof(DeviceFullName, \'.\')+1)),\r\n    Filename = DocumentName,\r\n    FilePath = ObjectId,\r\n    FileHash = tostring(EndpointMetaData.Sha256),\r\n    FileHashAlgorithm = \'SHA256\',\r\n    RMSEncrypted = tostring(EndpointMetaData.RMSEncrypted),\r\n    EvidenceFileUrl = tostring(EvidenceFile.FullUrl),\r\n    SourceLocationType = tostring(EndpointMetaData.SourceLocationType), \r\n    EndpointOperation = tostring(EndpointMetaData.EndpointOperation),\r\n    EndpointApplication = tostring(EndpointMetaData.Application)   \r\n| join kind = inner(EndpointAction) on ActionId\r\n| extend ActionsTaken = ActionName\r\n| summarize SensitiveInfoTypesArray = make_list(SensitiveInfoType), SensitiveInfoTypes = make_list(SensitiveInfoTypeString), TotalMatchCount = sum(toint(SensitiveInfo.Count)) by TimeGenerated, CreationTime, Identifier, Product, Workload, Deeplink, usageLocation, UserPrincipalName, UserObjectId, department, manager, jobTitle, PolicyName, RuleName, ActionsTaken, DeviceFullName, DeviceHostName, DeviceDNSName, Filename, FilePath, FileHash, FileHashAlgorithm, RMSEncrypted, EvidenceFileUrl, SourceLocationType, EndpointOperation, EndpointApplication, Operation;\r\n\r\nunion DLPSPOD, DLPEXOT, DLPEndpoint\r\n| extend FileDirectory = parse_path(FilePath).DirectoryPath\r\n| project TimeGenerated, CreationTime, Identifier, Product, Workload, Deeplink, usageLocation, UserPrincipalName, UserObjectId, department, manager, jobTitle, PolicyName, RuleName, ActionsTaken, SensitiveInfoTypesArray, TotalMatchCount, DeviceFullName, DeviceHostName, DeviceDNSName, Filename, FilePath, FileDirectory, FileHash, FileHashAlgorithm, RMSEncrypted, EvidenceFileUrl, SourceLocationType, EndpointOperation, EndpointApplication, Recipients, InternetMessageId, EmailSubject, Sender, ExceptionReason, SiteUrl, TargetUserOrGroupName, Operation,\r\n    Username = split(UserPrincipalName, \'@\')[0], UPNSuffix =split(UserPrincipalName, \'@\')[1], \r\n    RuleSeverity = iff(TotalMatchCount >= endpointSeverityMatchCountTrigger and Workload == \'Endpoint\', \'High\', RuleSeverity), \r\n    SensitiveInfoTypes = iff(array_length(SensitiveInfoTypes) > 1, strcat(SensitiveInfoTypes[0], \' +\', array_length(SensitiveInfoTypes) - 1, \' more\'), strcat_array(SensitiveInfoTypes, \', \')), \r\n    DetectedLocations = strcat_array(DetectedLocations, \', \'), SensitivityLabels = strcat_array(SensitivityLabels, \', \')\r\n| order by TimeGenerated'
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
  name: '${workspace}/Microsoft.SecurityInsights/da0f142a-bb82-43bc-a168-5e7e3d7107d3'
  kind: 'Scheduled'
  properties: {
    displayName: 'Microsoft DLP Incident Creation Template (Endpoint)'
    description: ''
    severity: 'Medium'
    enabled: false
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
  name: '${workspace}/Microsoft.SecurityInsights/da0f142a-bb82-43bc-a168-5e7e3d7107d3'
  kind: 'Scheduled'
  properties: {
    displayName: 'Microsoft DLP Incident Creation Template (EXOT)'
    description: ''
    severity: 'Medium'
    enabled: false
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
  name: '${workspace}/Microsoft.SecurityInsights/da0f142a-bb82-43bc-a168-5e7e3d7107d3'
  kind: 'Scheduled'
  properties: {
    displayName: 'Microsoft DLP Incident Creation Template (SPOT)'
    description: ''
    severity: 'Medium'
    enabled: false
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

