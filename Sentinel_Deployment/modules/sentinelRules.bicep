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

resource workspace_Microsoft_SecurityInsights_1192ede7_9c2d_465a_8a7a_b0ea1da7323b 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2022-11-01-preview' = if(policySync == true) {
  name: '${workspace}/Microsoft.SecurityInsights/1192ede7-9c2d-465a-8a7a-b0ea1da7323b'
  kind: 'Scheduled'
  properties: {
    displayName: 'Microsoft DLP Template (Endpoint)'
    description: ''
    severity: 'Medium'
    enabled: true
    query: 'let policywatchlist =(_GetWatchlist(\'Policy\')\n    | project SearchKey);\n\nlet EndPointAction = datatable(ActionName: string, Action: int) [\n    "None", "0",\n    "Audit", "1",\n    "Warn", "2",\n    "WarnAndBypass", "3",\n    "Block", "4",\n    "Allow", "5"\n];\n\nPurviewDLP_CL\n| extend RuleName = tostring(PolicyDetails[0].Rules[0].RuleName)\n| extend Policy = tostring(PolicyDetails[0].PolicyName)\n| extend PolicyId = tostring(PolicyDetails[0].PolicyId)\n| where Policy != "" //Do Not Remove\n| where not(Policy has_any (policywatchlist)) //Do not remove\n| extend RuleId = tostring(PolicyDetails[0].Rules[0].RuleId)\n| extend SensitiveInfoTypeName1 = tostring(EndpointMetaData.SensitiveInfoTypeData[0].SensitiveInfoTypeName)      \n| extend Detected1 = tostring(EndpointMetaData.SensitiveInfoTypeData[0].SensitiveInformationDetectionsInfo.DetectedValues)\n| extend Detected = array_slice(todynamic(Detected1), 0, 5)\n| extend Deeplink = strcat("https://compliance.microsoft.com/datalossprevention/alerts/eventdeeplink?eventid=", Identifier, "&creationtime=", CreationTime)\n| extend Action = toint(EndpointMetaData.EnforcementMode)\n| extend accountsplit = split(UserId, "@")\n| mv-expand EndpointMetaData.SensitiveInfoTypeData\n| summarize\n    MatchCount = sum(toint(EndpointMetaData_SensitiveInfoTypeData.Count)),\n    arg_max(TimeGenerated, *)\n    by Identifier\n| extend Provider = "Microsoft Purview Sentinel Solution"\n| extend Product = "Microsoft Data Loss Prevention (Advanced)"\n| join kind= inner\n    (\n    EndPointAction\n    )\n    on Action\n| project PolicyId, SensitiveInfoTypeName1, UserKey, DocumentName, ObjectId, EndpointMetaData.ClientIP, EndpointMetaData.RMSEncrypted, EndpointMetaData.EnforcementMode, EndpointMetaData.DeviceName, EndpointMetaData.SourceLocationType, Policy, RuleName, usageLocation, EndpointMetaData.EndpointOperation, EndpointMetaData.Sha256, department, manager, ActionName, Detected,    Workload, jobTitle, Deeplink, UserId, accountsplit[0], accountsplit[1], EvidenceFile.FullUrl, MatchCount, Identifier, Provider, Product\n'
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT2H'
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
        reopenClosedIncident: false
        lookbackDuration: 'PT45M'
        matchingMethod: 'Selected'
        groupByEntities: [
          'Account'
        ]
        groupByAlertDetails: [
          'DisplayName'
        ]
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: '{{RuleName}}'
      alertDescriptionFormat: '{{UserId}}, {{DocumentName}}' 
      alertDynamicProperties: [
        {
          alertProperty: 'AlertLink'
          value: 'Deeplink'
        }
        {
          alertProperty: 'ProviderName'
          value: 'Provider'
        }
        {
          alertProperty: 'ProductName'
          value: 'Product'
        }
      ]
    }
    customDetails: {
      User: 'UserId'
      JobTitle: 'jobTitle'
      Department: 'department'
      Manager: 'manager'
      Location: 'usageLocation'
      Workload: 'Workload'
      MatchCount: 'MatchCount'
      SensitiveInfoType: 'SensitiveInfoTypeName1'
      DataDetected: 'Detected'
      Action: 'EndpointMetaData_EndpointOperation'
      BlockAction: 'ActionName'
      Evidence: 'EvidenceFile_FullUrl'
      Encrypted: 'EndpointMetaData_RMSEncrypted'
      EventID: 'Identifier'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'accountsplit_0'
          }
          {
            identifier: 'UPNSuffix'
            columnName: 'accountsplit_1'
          }
        ]
      }
      {
        entityType: 'File'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'DocumentName'
          }
          {
            identifier: 'Directory'
            columnName: 'ObjectId'
          }
        ]
      }
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'HostName'
            columnName: 'EndpointMetaData_DeviceName'
          }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'EndpointMetaData_ClientIP'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}

resource workspace_Microsoft_SecurityInsights_03507f90_ed2d_420e_8530_e9e66b643bee 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2022-11-01-preview' = if(policySync == true) {
  name: '${workspace}/Microsoft.SecurityInsights/03507f90-ed2d-420e-8530-e9e66b643bee'
  kind: 'Scheduled'
  properties: {
    displayName: 'Microsoft DLP Template (Exchange and Teams)'
    description: ''
    severity: 'Medium'
    enabled: true
    query: 'let policywatchlist =(_GetWatchlist(\'Policy\')\n    | project SearchKey);\n\nPurviewDLP_CL\n| where Workload !in (\'SharePoint\', \'Endpoint\', \'OneDrive\')\n| extend Policy = tostring(PolicyDetails[0].PolicyName)\n| where Policy != "" //Do Not Remove\n| where not(Policy has_any (policywatchlist)) //Do not remove\n| extend Detected1 = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].SensitiveInformationDetections.DetectedValues)\n| extend Detected = array_slice(todynamic(Detected1), 0, 5)\n| extend SensitiveInformationTypeName = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].SensitiveInformationTypeName)\n| extend MessageId = ObjectId\n| extend linkoriginal = originalContent\n| extend Actions = tostring(PolicyDetails[0].Rules[0].Actions)       \n| extend linkoriginal = tostring(iff(isempty(SharePointMetaData.FilePathUrl), originalContent, SharePointMetaData.FilePathUrl))\n| extend Account = tostring(iff(isempty(SharePointMetaData.From), ExchangeMetaData.From, SharePointMetaData.From))\n| extend SubjectDoc = tostring(iff(isempty(SharePointMetaData.FileName), ExchangeMetaData.Subject, SharePointMetaData.FileName))\n| extend Recipients = tostring(strcat("To:", ExchangeMetaData.To, " CC:", ExchangeMetaData.CC, " BCC:", ExchangeMetaData.BCC))\n| extend MatchConfidence = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].Confidence)\n| extend UserId = tostring(ExchangeMetaData.From)\n| extend accountsplit = split(UserId, "@")\n| extend SensitiveLabelIdnew = tostring(SharePointMetaData.SensitivityLabelIds[0])\n| extend RuleName = tostring(PolicyDetails[0].Rules[0].RuleName)\n| extend SITLocation = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].Location)\n| extend OtherMatch = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.OtherConditions[0])\n| extend severity = tostring(PolicyDetails[0].Rules[0].Severity)\n| extend Deeplink = strcat("https://compliance.microsoft.com/datalossprevention/alerts/eventdeeplink?eventid=", Identifier, "&creationtime=", CreationTime)\n| extend Provider = "Microsoft Purview Sentinel Solution"\n| extend Product = "Microsoft Data Loss Prevention (Advanced)"\n| mv-expand PolicyDetails\n| mv-expand PolicyDetails.Rules\n| mv-expand PolicyDetails_Rules.ConditionsMatched.SensitiveInformation\n| summarize\n    MatchCount = sum(toint(PolicyDetails_Rules_ConditionsMatched_SensitiveInformation.Count)),\n    arg_max(TimeGenerated, *)\n    by Identifier\n| project Account, Workload, SensitiveInformationTypeName, Detected, linkoriginal, Recipients, SubjectDoc, TimeGenerated, manager, department, Actions, Policy, MatchConfidence, MatchCount,    MessageID=ExchangeMetaData.MessageID, accountsplit[0], accountsplit[1], UserId, Identifier, ExceptionReason = ExchangeMetaData.ExceptionInfo.Reason, RuleName, usageLocation, SITLocation, OtherMatch, severity, jobTitle, tostring(ExceptionInfo.Justification), Detected1, Deeplink, Provider, Product\n'
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT2H'
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
        groupByCustomDetails: [
          'User'
          'DocumentorSubject'
          'Recipients'
        ]
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: '{{RuleName}}'
      alertDescriptionFormat: '{{Account}}, {{SubjectDoc}}'
      alertSeverityColumnName: 'severity'
      alertDynamicProperties: [
        {
          alertProperty: 'AlertLink'
          value: 'Deeplink'
        }
        {
          alertProperty: 'ProviderName'
          value: 'Provider'
        }
        {
          alertProperty: 'ProductName'
          value: 'Product'
        }
      ]
    }
    customDetails: {
      User: 'Account'
      JobTitle: 'jobTitle'
      Department: 'department'
      Manager: 'manager'
      Location: 'usageLocation'
      Workload: 'Workload'
      MatchCount: 'MatchCount'
      Recipients: 'Recipients'
      SensitiveInfoType: 'SensitiveInformationTypeName'
      DataDetected: 'Detected'
      Actions: 'Actions'
      DocumentorSubject: 'SubjectDoc'
      LocationofDetection: 'SITLocation'
      RuleMatchOther: 'OtherMatch'
      EventID: 'Identifier'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'accountsplit_0'
          }
          {
            identifier: 'UPNSuffix'
            columnName: 'accountsplit_1'
          }
        ]
      }
      {
        entityType: 'MailMessage'
        fieldMappings: [
          {
            identifier: 'InternetMessageId'
            columnName: 'MessageID'
          }
          {
            identifier: 'Recipient'
            columnName: 'Recipients'
          }
          {
            identifier: 'Sender'
            columnName: 'UserId'
          }
        ]
      }
      {
        entityType: 'File'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'SubjectDoc'
          }
          {
            identifier: 'Directory'
            columnName: 'linkoriginal'
          }
        ]
      }
      {
        entityType: 'RegistryKey'
        fieldMappings: [
          {
            identifier: 'Key'
            columnName: 'Actions'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}

resource workspace_Microsoft_SecurityInsights_7e6ed702_770a_4945_98b4_a9506bbbd964 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2022-11-01-preview' = if(policySync == true) {
  name: '${workspace}/Microsoft.SecurityInsights/7e6ed702-770a-4945-98b4-a9506bbbd964'
  kind: 'Scheduled'
  properties: {
    displayName: 'Microsoft DLP Template (SharePoint and OneDrive)'
    description: ''
    severity: 'Medium'
    enabled: true
    query: 'let policywatchlist =(_GetWatchlist(\'Policy\')\n    | project SearchKey);\n\nlet domains=(_GetWatchlist(\'domains\')\n    | project SearchKey);\n\nlet DLP = (PurviewDLP_CL\n    | extend path = parse_path(tostring(SharePointMetaData.FilePathUrl))\n    | extend DirectoryPath = tostring(path.DirectoryPath)\n    | summarize by DirectoryPath);\nlet officedata = (\n    OfficeActivity\n    | where ingestion_time() > ago(24h)\n    | where Operation == "AddedToSecureLink" or Operation == "SecureLinkUsed"\n    | where OfficeObjectId has_any (DLP)\n    | extend SiteCollectionUrl = Site_Url\n    | extend FileName = SourceFileName\n    | extend Account = tolower(UserId)\n    | extend Targetsplit = split(UserId, "#")\n    | extend TargetUserOrGroupName = iff(isempty(TargetUserOrGroupName), Targetsplit[1], TargetUserOrGroupName)\n    //Exclude internal domains\n    //| where TargetUserOrGroupName !has "mydom1.com"\n    | extend TargetUserOrGroupName = tolower(TargetUserOrGroupName)\n    | summarize\n        by FileName, SiteCollectionUrl, TargetUserOrGroupName, OfficeObjectId, Account);\n\nlet dlpmain = (\n    PurviewDLP_CL\n    | where Workload in (\'SharePoint\', \'OneDrive\')\n    | extend Policy = tostring(PolicyDetails[0].PolicyName)\n    | where Policy != "" //Do Not Remove\n    | where not(Policy has_any (policywatchlist)) //Do not remove\n    | extend Detected1 = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].SensitiveInformationDetections.DetectedValues)\n    | extend Detected = array_slice(todynamic(Detected1), 0, 5)\n    | extend SensitiveInformationTypeName = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].SensitiveInformationTypeName)\n    | extend MessageId = ObjectId\n    | extend linkoriginal = originalContent\n    | extend Actions = tostring(PolicyDetails[0].Rules[0].Actions)   \n    | extend FilePathUrl = url_decode(tostring(SharePointMetaData.FilePathUrl))\n    | extend linkoriginal = iff(isempty(FilePathUrl), originalContent, FilePathUrl)\n    | extend Account = iff(isempty(SharePointMetaData.From), ExchangeMetaData.From, tolower(SharePointMetaData.From))    \n    | extend SubjectDoc = tostring(iff(isempty(SharePointMetaData.FileName), ExchangeMetaData.Subject, SharePointMetaData.FileName))\n    | extend Recipients = strcat("To:", ExchangeMetaData.To, " CC:", ExchangeMetaData.CC, " BCC:", ExchangeMetaData.BCC) \n    | extend MatchConfidence = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(PolicyDetails[0].Rules))[0].ConditionsMatched)).SensitiveInformation))[0].Confidence)\n    | extend accountsplit = split(UserId, "@")\n    | extend SensitiveLabelIdnew = tostring(SharePointMetaData.SensitivityLabelIds[0])\n    | extend path = parse_path(FilePathUrl)\n    | extend OfficeObjectId = tostring(path.DirectoryPath)\n    | join kind = leftouter\n        (\n        _GetWatchlist(\'SensitivityLabels\')\n        | extend SensitiveLabelIdnew = tostring(column_ifexists(\'id\', \'\'))\n        | extend Label = tostring(column_ifexists(\'name\', \'\'))\n        )\n        on SensitiveLabelIdnew);\n\nlet folder = (dlpmain\n    | join kind = leftouter\n        (officedata\n        | summarize\n            by\n            SiteCollectionUrl,\n            FileName,\n            TargetUserOrGroupName,\n            OfficeObjectId\n        | summarize TargetUserOrGroupName = make_list(strcat(TargetUserOrGroupName))\n            by\n            OfficeObjectId,\n            SiteCollectionUrl,\n            FileName\n        | summarize take_any(TargetUserOrGroupName)\n            by\n            OfficeObjectId,\n            SiteCollectionUrl,\n            FileName\n        | join kind = leftouter\n            (\n            officedata\n            | summarize\n                by\n                SiteCollectionUrl,\n                FileName,\n                TargetUserOrGroupName,\n                OfficeObjectId\n            | extend Domsplit = split(TargetUserOrGroupName, "@")\n            | extend domain = Domsplit[1]\n            | summarize TargetDomain = make_list(strcat(domain)) by FileName, OfficeObjectId\n            | summarize take_any(TargetDomain) by FileName, OfficeObjectId\n            )\n            on OfficeObjectId\n        )\n        on OfficeObjectId\n    );\n\nlet files = (folder\n    //| where TargetUserOrGroupName == ""\n    | join kind = leftouter\n        (officedata\n        | summarize TargetUserOrGroupName = make_list(strcat(TargetUserOrGroupName)) by FileName, SiteCollectionUrl\n        | summarize take_any(TargetUserOrGroupName) by FileName, SiteCollectionUrl   \n        | join kind = leftouter\n            (\n            officedata\n            | summarize\n                by\n                SiteCollectionUrl,\n                FileName,\n                TargetUserOrGroupName\n            | extend Domsplit = split(TargetUserOrGroupName, "@")\n            | extend domain = Domsplit[1]\n            | summarize TargetDomain = make_list(strcat(domain)) by FileName\n            | summarize take_any(TargetDomain) by FileName\n            )\n            on FileName\n        )\n        on FileName, SiteCollectionUrl\n    | extend TargetUserOrGroupName = TargetUserOrGroupName1\n    | extend TargetDomain = TargetDomain1\n    | where TargetUserOrGroupName != ""\n    );\n    \nunion folder, files\n| summarize arg_max(TimeGenerated, *) by SubjectDoc, UserId, Identifier\n| join kind = leftouter\n    (\n    officedata\n    | extend Domsplit = split(TargetUserOrGroupName, "@")\n    | extend domain = Domsplit[1]\n    | where tolower(domain) in (domains)\n    | summarize TargetDomain = make_list(strcat(domain)) by tostring(SiteCollectionUrl)\n    )\n    on SiteCollectionUrl\n| extend HighRiskDomain = iff(isempty(TargetDomain), "", "HighRiskDomain")\n| extend Policy = strcat(tostring(PolicyDetails[0].PolicyName), " ", HighRiskDomain)\n| extend RuleName = strcat(tostring(parse_json(tostring(PolicyDetails[0].Rules))[0].RuleName), " ", HighRiskDomain)\n| extend SITLocation = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(PolicyDetails[0].Rules))[0].ConditionsMatched)).SensitiveInformation))[0].Location)\n| extend OtherMatch = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(PolicyDetails[0].Rules))[0].ConditionsMatched)).OtherConditions))[0])\n| extend severity = tostring(PolicyDetails[0].Rules[0].Severity)\n| extend Deeplink = strcat("https://compliance.microsoft.com/datalossprevention/alerts/eventdeeplink?eventid=", Identifier, "&creationtime=", CreationTime)\n| mv-expand PolicyDetails\n| mv-expand PolicyDetails.Rules\n| mv-expand PolicyDetails_Rules.ConditionsMatched.SensitiveInformation\n| extend Provider = "Microsoft Purview Sentinel Solution"\n| extend Product = "Microsoft Data Loss Prevention (Advanced)"\n| summarize MatchCount = sum(toint(PolicyDetails_Rules_ConditionsMatched_SensitiveInformation.Count))\n    by Account, Workload, SensitiveInformationTypeName, tostring(Detected), linkoriginal, Recipients, SubjectDoc, TimeGenerated, manager, department, Actions, Policy, MatchConfidence, tostring(ExchangeMetaData.MessageID), tostring(accountsplit[0]), tostring(accountsplit[1]), UserId, Identifier, Label, tostring(SharePointMetaData.ExceptionInfo.Reason), RuleName, SITLocation, OtherMatch,\n    tostring(severity), jobTitle, tostring(ExceptionInfo.Justification), Deeplink, tostring(TargetUserOrGroupName), HighRiskDomain, usageLocation, Provider, Product\n'
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT2H'
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
        groupByCustomDetails: [
          'User'
          'Document'
          'SharedWith'
        ]
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: '{{RuleName}}'
      alertDescriptionFormat: '{{Account}}, {{SubjectDoc}}'
      alertSeverityColumnName: 'severity'
      alertDynamicProperties: [
        {
          alertProperty: 'AlertLink'
          value: 'Deeplink'
        }
        {
          alertProperty: 'ProviderName'
          value: 'Provider'
        }
        {
          alertProperty: 'ProductName'
          value: 'Product'
        }
      ]
    }
    customDetails: {
      User: 'Account'
      JobTitle: 'jobTitle'
      Department: 'department'
      Manager: 'manager'
      Location: 'usageLocation'
      Workload: 'Workload'
      MatchCount: 'MatchCount'
      SensitiveInfoType: 'SensitiveInformationTypeName'
      DataDetected: 'Detected'
      Actions: 'Actions'
      SharedWith: 'TargetUserOrGroupName'
      Document: 'SubjectDoc'
      LocationofDetection: 'SITLocation'
      RuleMatchOther: 'OtherMatch'
      SharePointLabel: 'Label'
      EventID: 'Identifier'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'accountsplit_0'
          }
          {
            identifier: 'UPNSuffix'
            columnName: 'accountsplit_1'
          }
        ]
      }
      {
        entityType: 'File'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'SubjectDoc'
          }
          {
            identifier: 'Directory'
            columnName: 'linkoriginal'
          }
        ]
      }
      {
        entityType: 'RegistryKey'
        fieldMappings: [
          {
            identifier: 'Key'
            columnName: 'Actions'
          }
        ]
      }
      {
        entityType: 'CloudApplication'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'Workload'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}

