param workspace string

resource workspace_Microsoft_SecurityInsights_1192ede7_9c2d_465a_8a7a_b0ea1da7323b 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2022-09-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/1192ede7-9c2d-465a-8a7a-b0ea1da7323b'
  kind: 'Scheduled'
  properties: {
    displayName: 'Purview DLP Template (Endpoint)'
    description: ''
    severity: 'Medium'
    enabled: true
    query: 'let policywatchlist =(_GetWatchlist(\'Policy\')\n    | project SearchKey);\n\nlet EndPointAction = datatable(ActionName: string, Action: int) [\n    "None", "0",\n    "Audit", "1",\n    "Warn", "2",\n    "WarnAndBypass", "3",\n    "Block", "4",\n    "Allow", "5"\n];\n\nPurviewDLP_CL\n| extend RuleName = tostring(PolicyDetails[0].Rules[0].RuleName)\n| extend Policy = tostring(PolicyDetails[0].PolicyName)\n| extend PolicyId = tostring(PolicyDetails[0].PolicyId)\n| where Policy != "" //Do Not Remove\n| where not(Policy has_any (policywatchlist)) //Do not remove\n| extend RuleId = tostring(PolicyDetails[0].Rules[0].RuleId)\n| extend SensitiveInfoTypeName1 = tostring(EndpointMetaData.SensitiveInfoTypeData[0].SensitiveInfoTypeName)      \n| extend Detected1 = tostring(EndpointMetaData.SensitiveInfoTypeData[0].SensitiveInformationDetectionsInfo.DetectedValues)\n| extend Detected = array_slice(todynamic(Detected1), 0, 5)\n| extend Deeplink = strcat("https://compliance.microsoft.com/datalossprevention/alerts/eventdeeplink?eventid=", Identifier, "&creationtime=", CreationTime)\n| extend Action = toint(EndpointMetaData.EnforcementMode)\n| extend accountsplit = split(UserId, "@")\n| mv-expand EndpointMetaData.SensitiveInfoTypeData\n| summarize\n    MatchCount = sum(toint(EndpointMetaData_SensitiveInfoTypeData.Count)),\n    arg_max(TimeGenerated, *)\n    by Identifier\n| extend ProviderName = "Microsoft Purview Sentinel Solution"\n| extend ProductName = "Microsoft Data Loss Prevention (Advanced)"\n| join kind= inner\n    (\n    EndPointAction\n    )\n    on Action\n| project PolicyId, SensitiveInfoTypeName1, UserKey, DocumentName, ObjectId, EndpointMetaData.ClientIP, EndpointMetaData.RMSEncrypted, EndpointMetaData.EnforcementMode, EndpointMetaData.DeviceName, EndpointMetaData.SourceLocationType, Policy, RuleName, usageLocation, EndpointMetaData.EndpointOperation, EndpointMetaData.Sha256, department, manager, ActionName, Detected,    Workload, jobTitle, Deeplink, UserId, accountsplit[0], accountsplit[1], EvidenceFile.FullUrl, MatchCount, ProviderName, ProductName\n'
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
          value: 'ProviderName'
        }
        {
          alertProperty: 'ProductName'
          value: 'ProductName'
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
      Action: 'EndpointMetaData_EndpointOperation'
      BlockAction: 'ActionName'
      Evidence: 'EvidenceFile_FullUrl'
      Encrypted: 'EndpointMetaData_RMSEncrypted'
      DataShared: 'Detected'
      Deeplink: 'Deeplink'
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

resource workspace_Microsoft_SecurityInsights_03507f90_ed2d_420e_8530_e9e66b643bee 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2022-09-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/03507f90-ed2d-420e-8530-e9e66b643bee'
  kind: 'Scheduled'
  properties: {
    displayName: 'Purview DLP Template (Exchange and Teams)'
    description: ''
    severity: 'Medium'
    enabled: true
    query: 'let policywatchlist =(_GetWatchlist(\'Policy\')\n    | project SearchKey);\n\nPurviewDLP_CL\n| where Workload !in (\'SharePoint\', \'Endpoint\', \'OneDrive\')\n| extend Policy = tostring(PolicyDetails[0].PolicyName)\n| where Policy != "" //Do Not Remove\n| where not(Policy has_any (policywatchlist)) //Do not remove\n| extend Detected1 = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].SensitiveInformationDetections.DetectedValues)\n| extend Detected = array_slice(todynamic(Detected1), 0, 5)\n| extend SensitiveInformationTypeName = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].SensitiveInformationTypeName)\n| extend MessageId = ObjectId\n| extend linkoriginal = originalContent\n| extend Actions = tostring(PolicyDetails[0].Rules[0].Actions)       \n| extend linkoriginal = tostring(iff(isempty(SharePointMetaData.FilePathUrl), originalContent, SharePointMetaData.FilePathUrl))\n| extend Account = tostring(iff(isempty(SharePointMetaData.From), ExchangeMetaData.From, SharePointMetaData.From))\n| extend SubjectDoc = tostring(iff(isempty(SharePointMetaData.FileName), ExchangeMetaData.Subject, SharePointMetaData.FileName))\n| extend Recipients = tostring(strcat("To:", ExchangeMetaData.To, " CC:", ExchangeMetaData.CC, " BCC:", ExchangeMetaData.BCC))\n| extend MatchConfidence = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].Confidence)\n| extend UserId = tostring(ExchangeMetaData.From)\n| extend accountsplit = split(UserId, "@")\n| extend SensitiveLabelIdnew = tostring(SharePointMetaData.SensitivityLabelIds[0])\n| extend RuleName = tostring(PolicyDetails[0].Rules[0].RuleName)\n| extend SITLocation = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].Location)\n| extend OtherMatch = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.OtherConditions[0])\n| extend severity = tostring(PolicyDetails[0].Rules[0].Severity)\n| extend Deeplink = strcat("https://compliance.microsoft.com/datalossprevention/alerts/eventdeeplink?eventid=", Identifier, "&creationtime=", CreationTime)\n| extend ProviderName = "Microsoft Purview Sentinel Solution"\n| extend ProductName = "Microsoft Data Loss Prevention (Advanced)"\n| mv-expand PolicyDetails\n| mv-expand PolicyDetails.Rules\n| mv-expand PolicyDetails_Rules.ConditionsMatched.SensitiveInformation\n| summarize\n    MatchCount = sum(toint(PolicyDetails_Rules_ConditionsMatched_SensitiveInformation.Count)),\n    arg_max(TimeGenerated, *)\n    by Identifier\n| project Account, Workload, SensitiveInformationTypeName, Detected, linkoriginal, Recipients, SubjectDoc, TimeGenerated, manager, department, Actions, Policy, MatchConfidence, MatchCount,    MessageID=ExchangeMetaData.MessageID, accountsplit[0], accountsplit[1], UserId, Identifier, ExceptionReason = ExchangeMetaData.ExceptionInfo.Reason, RuleName, usageLocation, SITLocation, OtherMatch, severity, jobTitle, tostring(ExceptionInfo.Justification), Detected1, Deeplink, ProviderName, ProductName\n'
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
          value: 'ProviderName'
        }
        {
          alertProperty: 'ProductName'
          value: 'ProductName'
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
      Actions: 'Actions'
      DocumentorSubject: 'SubjectDoc'
      DataShared: 'Detected'
      LocationofDetection: 'SITLocation'
      RuleMatchOther: 'OtherMatch'
      DeepLink: 'Deeplink'
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

resource workspace_Microsoft_SecurityInsights_7e6ed702_770a_4945_98b4_a9506bbbd964 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2022-09-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/7e6ed702-770a-4945-98b4-a9506bbbd964'
  kind: 'Scheduled'
  properties: {
    displayName: 'Purview DLP Template (SharePoint and OneDrive)'
    description: ''
    severity: 'Medium'
    enabled: true
    query: 'let policywatchlist =(_GetWatchlist(\'Policy\')\n    | project SearchKey);\n\nlet domains=(_GetWatchlist(\'domains\')\n    | project SearchKey);\n\nlet DLP = (PurviewDLP_CL\n    | extend path = parse_path(tostring(SharePointMetaData.FilePathUrl))\n    | extend DirectoryPath = tostring(path.DirectoryPath)\n    | summarize by DirectoryPath);\nlet officedata = (\n    OfficeActivity\n    | where ingestion_time() > ago(24h)\n    | where Operation == "AddedToSecureLink" or Operation == "SecureLinkUsed"\n    | where OfficeObjectId has_any (DLP)\n    | extend SiteCollectionUrl = Site_Url\n    | extend FileName = SourceFileName\n    | extend Account = tolower(UserId)\n    | extend Targetsplit = split(UserId, "#")\n    | extend TargetUserOrGroupName = iff(isempty(TargetUserOrGroupName), Targetsplit[1], TargetUserOrGroupName)\n    //Exclude internal domains\n    //| where TargetUserOrGroupName !has "mydom1.com"\n    | extend TargetUserOrGroupName = tolower(TargetUserOrGroupName)\n    | summarize\n        by FileName, SiteCollectionUrl, TargetUserOrGroupName, OfficeObjectId, Account);\n\nlet dlpmain = (\n    PurviewDLP_CL\n    | where Workload in (\'SharePoint\', \'OneDrive\')\n    | extend Policy = tostring(PolicyDetails[0].PolicyName)\n    | where Policy != "" //Do Not Remove\n    | where not(Policy has_any (policywatchlist)) //Do not remove\n    | extend Detected1 = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].SensitiveInformationDetections.DetectedValues)\n    | extend Detected = array_slice(todynamic(Detected1), 0, 5)\n    | extend SensitiveInformationTypeName = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].SensitiveInformationTypeName)\n    | extend MessageId = ObjectId\n    | extend linkoriginal = originalContent\n    | extend Actions = tostring(PolicyDetails[0].Rules[0].Actions)   \n    | extend FilePathUrl = url_decode(tostring(SharePointMetaData.FilePathUrl))\n    | extend linkoriginal = iff(isempty(FilePathUrl), originalContent, FilePathUrl)\n    | extend Account = iff(isempty(SharePointMetaData.From), ExchangeMetaData.From, tolower(SharePointMetaData.From))    \n    | extend SubjectDoc = tostring(iff(isempty(SharePointMetaData.FileName), ExchangeMetaData.Subject, SharePointMetaData.FileName))\n    | extend Recipients = strcat("To:", ExchangeMetaData.To, " CC:", ExchangeMetaData.CC, " BCC:", ExchangeMetaData.BCC) \n    | extend MatchConfidence = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(PolicyDetails[0].Rules))[0].ConditionsMatched)).SensitiveInformation))[0].Confidence)\n    | extend accountsplit = split(UserId, "@")\n    | extend SensitiveLabelIdnew = tostring(SharePointMetaData.SensitivityLabelIds[0])\n    | extend path = parse_path(FilePathUrl)\n    | extend OfficeObjectId = tostring(path.DirectoryPath)\n    | join kind = leftouter\n        (\n        _GetWatchlist(\'SensitivityLabels\')\n        | extend SensitiveLabelIdnew = tostring(id)\n        | extend Label = tostring(name)\n        )\n        on SensitiveLabelIdnew);\n\nlet folder = (dlpmain\n    | join kind = leftouter\n        (officedata\n        | summarize\n            by\n            SiteCollectionUrl,\n            FileName,\n            TargetUserOrGroupName,\n            OfficeObjectId\n        | summarize TargetUserOrGroupName = make_list(strcat(TargetUserOrGroupName))\n            by\n            OfficeObjectId,\n            SiteCollectionUrl,\n            FileName\n        | summarize take_any(TargetUserOrGroupName)\n            by\n            OfficeObjectId,\n            SiteCollectionUrl,\n            FileName\n        | join kind = leftouter\n            (\n            officedata\n            | summarize\n                by\n                SiteCollectionUrl,\n                FileName,\n                TargetUserOrGroupName,\n                OfficeObjectId\n            | extend Domsplit = split(TargetUserOrGroupName, "@")\n            | extend domain = Domsplit[1]\n            | summarize TargetDomain = make_list(strcat(domain)) by FileName, OfficeObjectId\n            | summarize take_any(TargetDomain) by FileName, OfficeObjectId\n            )\n            on OfficeObjectId\n        )\n        on OfficeObjectId\n    );\n\nlet files = (folder\n    //| where TargetUserOrGroupName == ""\n    | join kind = leftouter\n        (officedata\n        | summarize TargetUserOrGroupName = make_list(strcat(TargetUserOrGroupName)) by FileName, SiteCollectionUrl\n        | summarize take_any(TargetUserOrGroupName) by FileName, SiteCollectionUrl   \n        | join kind = leftouter\n            (\n            officedata\n            | summarize\n                by\n                SiteCollectionUrl,\n                FileName,\n                TargetUserOrGroupName\n            | extend Domsplit = split(TargetUserOrGroupName, "@")\n            | extend domain = Domsplit[1]\n            | summarize TargetDomain = make_list(strcat(domain)) by FileName\n            | summarize take_any(TargetDomain) by FileName\n            )\n            on FileName\n        )\n        on FileName, SiteCollectionUrl\n    | extend TargetUserOrGroupName = TargetUserOrGroupName1\n    | extend TargetDomain = TargetDomain1\n    | where TargetUserOrGroupName != ""\n    );\n    \nunion folder, files\n| summarize arg_max(TimeGenerated, *) by SubjectDoc, UserId, Identifier\n| join kind = leftouter\n    (\n    officedata\n    | extend Domsplit = split(TargetUserOrGroupName, "@")\n    | extend domain = Domsplit[1]\n    | where tolower(domain) in (domains)\n    | summarize TargetDomain = make_list(strcat(domain)) by tostring(SiteCollectionUrl)\n    )\n    on SiteCollectionUrl\n| extend HighRiskDomain = iff(isempty(TargetDomain), "", "HighRiskDomain")\n| extend Policy = strcat(tostring(PolicyDetails[0].PolicyName), " ", HighRiskDomain)\n| extend RuleName = strcat(tostring(parse_json(tostring(PolicyDetails[0].Rules))[0].RuleName), " ", HighRiskDomain)\n| extend SITLocation = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(PolicyDetails[0].Rules))[0].ConditionsMatched)).SensitiveInformation))[0].Location)\n| extend OtherMatch = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(PolicyDetails[0].Rules))[0].ConditionsMatched)).OtherConditions))[0])\n| extend severity = tostring(PolicyDetails[0].Rules[0].Severity)\n| extend Deeplink = strcat("https://compliance.microsoft.com/datalossprevention/alerts/eventdeeplink?eventid=", Identifier, "&creationtime=", CreationTime)\n| mv-expand PolicyDetails\n| mv-expand PolicyDetails.Rules\n| mv-expand PolicyDetails_Rules.ConditionsMatched.SensitiveInformation\n| extend ProviderName = "Microsoft Purview Sentinel Solution"\n| extend ProductName = "Microsoft Data Loss Prevention (Advanced)"\n| summarize MatchCount = sum(toint(PolicyDetails_Rules_ConditionsMatched_SensitiveInformation.Count))\n    by Account, Workload, SensitiveInformationTypeName, tostring(Detected), linkoriginal, Recipients, SubjectDoc, TimeGenerated, manager, department, Actions, Policy, MatchConfidence, tostring(ExchangeMetaData.MessageID), tostring(accountsplit[0]), tostring(accountsplit[1]), UserId, Identifier, Label, tostring(SharePointMetaData.ExceptionInfo.Reason), RuleName, SITLocation, OtherMatch,\n    tostring(severity), jobTitle, tostring(ExceptionInfo.Justification), Deeplink, tostring(TargetUserOrGroupName), HighRiskDomain, usageLocation, ProviderName, ProductName\n'
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
          value: 'ProviderName'
        }
        {
          alertProperty: 'ProductName'
          value: 'ProductName'
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
      Actions: 'Actions'
      SharedWith: 'TargetUserOrGroupName'
      Document: 'SubjectDoc'
      DataShared: 'Detected'
      LocationofDetection: 'SITLocation'
      RuleMatchOther: 'OtherMatch'
      SharePointLabel: 'Label'
      DeepLink: 'Deeplink'
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
