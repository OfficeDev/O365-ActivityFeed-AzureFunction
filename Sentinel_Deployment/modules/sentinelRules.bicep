param workspace string

resource workspace_Microsoft_SecurityInsights_1192ede7_9c2d_465a_8a7a_b0ea1da7323b 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2022-09-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/1192ede7-9c2d-465a-8a7a-b0ea1da7323b'
  kind: 'Scheduled'
  properties: {
    displayName: 'Template_EndPoint'
    description: ''
    severity: 'Medium'
    enabled: true
    query: 'let policywatchlist =(_GetWatchlist(\'Policy\'));\r\nlet EndPointAction = datatable(ActionName: string, Action: int) [\r\n    "None", "0",\r\n    "Audit", "1",\r\n    "Warn", "2",\r\n    "WarnAndBypass", "3",\r\n    "Block", "4",\r\n    "Allow", "5"\r\n];\r\nPurviewDLP_CL\r\n| extend RuleName = tostring(PolicyDetails[0].Rules[0].RuleName)\r\n| extend Policy = tostring(PolicyDetails[0].PolicyName)\r\n| extend PolicyId = tostring(PolicyDetails[0].PolicyId)\r\n| where Policy != "" //Do Not Remove\r\n| where not(Policy has_any (policywatchlist)) //Do not remove\r\n| extend RuleId = tostring(PolicyDetails[0].Rules[0].RuleId)\r\n| extend SensitiveInfoTypeName1 = tostring(EndpointMetaData.SensitiveInfoTypeData[0].SensitiveInfoTypeName)      \r\n| extend Detected1 = tostring(EndpointMetaData.SensitiveInfoTypeData[0].SensitiveInformationDetectionsInfo.DetectedValues)\r\n| extend Detected = array_slice(todynamic(Detected1), 0, 5)\r\n| extend Deeplink = strcat("https://compliance.microsoft.com/datalossprevention/alerts/eventdeeplink?eventid=", Identifier, "&creationtime=", CreationTime)\r\n| extend Action = toint(EndpointMetaData.EnforcementMode)\r\n| extend accountsplit = split(UserId, "@")\r\n| join kind= inner\r\n    (\r\n    EndPointAction\r\n    )\r\n    on Action\r\n| project\r\n    PolicyId,\r\n    SensitiveInfoTypeName1,\r\n    UserKey,\r\n    DocumentName,\r\n    ObjectId,\r\n    EndpointMetaData.ClientIP,\r\n    EndpointMetaData.RMSEncrypted,\r\n    EndpointMetaData.EnforcementMode,\r\n    EndpointMetaData.DeviceName,\r\n    EndpointMetaData.SourceLocationType,\r\n    Policy,\r\n    RuleName,\r\n    usageLocation,\r\n    EndpointMetaData.EndpointOperation,\r\n    EndpointMetaData.Sha256,\r\n    department,\r\n    manager,\r\n    ActionName,\r\n    Detected,\r\n    Workload,\r\n    jobTitle,\r\n    Deeplink,\r\n    UserId,\r\n    accountsplit[0],\r\n    accountsplit[1],\r\n    EvidenceFile.FullUrl'
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
      alertDynamicProperties: []
    }
    customDetails: {
      User: 'UserId'
      JobTitle: 'jobTitle'
      Department: 'department'
      Location: 'usageLocation'
      Detected: 'SensitiveInfoTypeName1'
      Action: 'EndpointMetaData_EndpointOperation'
      Evidence: 'EvidenceFile_FullUrl'
      BlockAction: 'ActionName'
      Encrypted: 'EndpointMetaData_RMSEncrypted'
      Manager: 'manager'
      DataMatch: 'Detected'
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
    displayName: 'Template_email_teams'
    description: ''
    severity: 'Medium'
    enabled: true
    query: 'let policywatchlist =(_GetWatchlist(\'Policy\')\r\n| project SearchKey);\r\nPurviewDLP_CL\r\n| where Workload !in (\'SharePoint\', \'Endpoint\', \'OneDrive\')\r\n| extend Policy = tostring(PolicyDetails[0].PolicyName)\r\n| where Policy != "" //Do Not Remove\r\n| where not(Policy has_any (policywatchlist)) //Do not remove\r\n| extend Detected1 = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].SensitiveInformationDetections.DetectedValues)\r\n| extend Detected = array_slice(todynamic(Detected1), 0, 5)\r\n| extend SensitiveInformationTypeName = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].SensitiveInformationTypeName)\r\n| extend MessageId = ObjectId\r\n| extend linkoriginal = originalContent\r\n| extend Actions = tostring(PolicyDetails[0].Rules[0].Actions)       \r\n| extend linkoriginal = tostring(iff(isempty(SharePointMetaData.FilePathUrl), originalContent, SharePointMetaData.FilePathUrl))\r\n| extend Account = tostring(iff(isempty(SharePointMetaData.From), ExchangeMetaData.From, SharePointMetaData.From))\r\n| extend SubjectDoc = tostring(iff(isempty(SharePointMetaData.FileName), ExchangeMetaData.Subject, SharePointMetaData.FileName))\r\n| extend Recipients = tostring(strcat("To:", ExchangeMetaData.To, " CC:", ExchangeMetaData.CC, " BCC:", ExchangeMetaData.BCC))\r\n| extend MatchCount = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].UniqueCount)\r\n| extend MatchConfidence = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].Confidence)\r\n| extend UserId = tostring(ExchangeMetaData.From)\r\n| extend accountsplit = split(UserId, "@")\r\n| extend SensitiveLabelIdnew = tostring(SharePointMetaData.SensitivityLabelIds[0])\r\n| extend RuleName = tostring(PolicyDetails[0].Rules[0].RuleName)\r\n| extend SITLocation = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].Location)\r\n| extend OtherMatch = tostring(PolicyDetails[0].Rules[0].ConditionsMatched.OtherConditions[0])\r\n| extend severity = tostring(PolicyDetails[0].Rules[0].Severity)\r\n| extend Deeplink = strcat("https://compliance.microsoft.com/datalossprevention/alerts/eventdeeplink?eventid=", Identifier, "&creationtime=", CreationTime)\r\n| project\r\n    Account,\r\n    Workload,\r\n    SensitiveInformationTypeName,\r\n    Detected,\r\n    linkoriginal,\r\n    Recipients,\r\n    SubjectDoc,\r\n    TimeGenerated,\r\n    manager,\r\n    department,\r\n    Actions,\r\n    Policy,\r\n    MatchConfidence,\r\n    MatchCount,\r\n    MessageID=ExchangeMetaData.MessageID,\r\n    accountsplit[0],\r\n    accountsplit[1],\r\n    UserId,\r\n    Identifier,\r\n    ExceptionReason = ExchangeMetaData.ExceptionInfo.Reason,\r\n    RuleName,\r\n    SITLocation,\r\n    OtherMatch,\r\n    severity,\r\n    jobTitle,\r\n    tostring(ExceptionInfo.Justification),\r\n    Detected1,\r\n    Deeplink'
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
      alertDynamicProperties: []
    }
    customDetails: {
      User: 'Account'
      JobTitle: 'jobTitle' 
      Recipients: 'Recipients'
      SensitiveData: 'SensitiveInformationTypeName'
      DocumentorSubject: 'SubjectDoc'
      DataShared: 'Detected'
      LocationofDetection: 'SITLocation'
      RuleMatchOther: 'OtherMatch'
      Actions: 'Actions'
      NumberofMatches: 'MatchCount'
      WorkloadType: 'Workload'
      Manager: 'manager'
      Department: 'department'
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
    displayName: 'Template_SPOD'
    description: ''
    severity: 'Medium'
    enabled: true
    query: 'let policywatchlist =(_GetWatchlist(\'Policy\')\r\n    | project SearchKey);\r\nlet domains=(_GetWatchlist(\'domains\')\r\n    | project SearchKey);\r\nlet DLP = (PurviewDLP_CL\r\n    | extend SharePointMetaData_FilePathUrl_s = url_decode(tostring(SharePointMetaData.FilePathUrl))\r\n    | extend path = parse_path(tostring(SharePointMetaData.FilePathUrl))\r\n    | extend DirectoryPath = tostring(path.DirectoryPath)\r\n    | summarize by DirectoryPath);\r\nlet officedata = (\r\n    OfficeActivity\r\n    | where ingestion_time() > ago(24h)\r\n    | where Operation == "AddedToSecureLink" or Operation == "SecureLinkUsed"\r\n    | where OfficeObjectId has_any (DLP)\r\n    | extend SharePointMetaData_SiteCollectionUrl_s = Site_Url\r\n    | extend SharePointMetaData_FileName_s = SourceFileName\r\n    | extend Account = tolower(UserId)\r\n    | extend Targetsplit = split(UserId, "#")\r\n    | extend TargetUserOrGroupName = iff(isempty(TargetUserOrGroupName), Targetsplit[1], TargetUserOrGroupName)\r\n    //Exclude internal domains\r\n    //| where TargetUserOrGroupName !has "mydom1.com"\r\n    | extend TargetUserOrGroupName = tolower(TargetUserOrGroupName)\r\n    | summarize\r\n        by\r\n        SharePointMetaData_FileName_s,\r\n        SharePointMetaData_SiteCollectionUrl_s,\r\n        TargetUserOrGroupName,\r\n        OfficeObjectId,\r\n        Account);\r\nlet dlpmain = (\r\n    PurviewDLP_CL\r\n    | where ingestion_time() > ago(30m)\r\n    | where Workload in (\'SharePoint\', \'OneDrive\')\r\n    | extend Policy = tostring(PolicyDetails[0].PolicyName)\r\n    | where Policy != "" //Do Not Remove\r\n    | where not(Policy has_any (policywatchlist)) //Do not remove\r\n    | extend Detected1 = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(PolicyDetails[0].Rules))[0].ConditionsMatched)).SensitiveInformation))[0].SensitiveInformationDetections)).DetectedValues)))\r\n    | extend Detected = array_slice(todynamic(Detected1), 0, 5)\r\n    | extend SensitiveInformationTypeName = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(PolicyDetails[0].Rules))[0].ConditionsMatched)).SensitiveInformation))[0].SensitiveInformationTypeName)\r\n    | extend MessageId = ObjectId\r\n    | extend linkoriginal = originalContent\r\n    | extend Actions = tostring(parse_json(tostring(parse_json(tostring(PolicyDetails[0].Rules))[0].Actions)))   \r\n    | extend SharePointMetaData_FilePathUrl_s = url_decode(tostring(SharePointMetaData.FilePathUrl))\r\n    | extend linkoriginal = iff(isempty(SharePointMetaData_FilePathUrl_s), originalContent, SharePointMetaData_FilePathUrl_s)\r\n    | extend Account = iff(isempty(SharePointMetaData.From), ExchangeMetaData.From, tolower(SharePointMetaData.From))    \r\n    | extend SubjectDoc = tostring(iff(isempty(SharePointMetaData.FileName), ExchangeMetaData.Subject, SharePointMetaData.FileName))\r\n    | extend Recipients = strcat("To:", ExchangeMetaData.To, " CC:", ExchangeMetaData.CC, " BCC:", ExchangeMetaData.BCC) \r\n    | extend MatchCount = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(PolicyDetails[0].Rules))[0].ConditionsMatched)).SensitiveInformation))[0].Count)\r\n    | extend MatchConfidence = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(PolicyDetails[0].Rules))[0].ConditionsMatched)).SensitiveInformation))[0].Confidence)\r\n    | extend accountsplit = split(UserId, "@")\r\n    | extend SensitiveLabelIdnew = tostring(parse_json(SharePointMetaData.SensitivityLabelIds)[0])\r\n    | extend path = parse_path(SharePointMetaData_FilePathUrl_s)\r\n    | extend OfficeObjectId = tostring(path.DirectoryPath)\r\n    | join kind = leftouter\r\n        (\r\n        _GetWatchlist(\'SensitivityLabels\')\r\n        | extend SensitiveLabelIdnew = tostring(id)\r\n        | extend Label = tostring(name)\r\n        )\r\n        on SensitiveLabelIdnew);\r\nlet folder = (dlpmain\r\n    | join kind = leftouter\r\n        (officedata\r\n        | summarize\r\n            by\r\n            SharePointMetaData_SiteCollectionUrl_s,\r\n            SharePointMetaData_FileName_s,\r\n            TargetUserOrGroupName,\r\n            OfficeObjectId\r\n        | summarize TargetUserOrGroupName = make_list(strcat(TargetUserOrGroupName))\r\n            by\r\n            OfficeObjectId,\r\n            SharePointMetaData_SiteCollectionUrl_s,\r\n            SharePointMetaData_FileName_s\r\n        | summarize take_any(TargetUserOrGroupName)\r\n            by\r\n            OfficeObjectId,\r\n            SharePointMetaData_SiteCollectionUrl_s,\r\n            SharePointMetaData_FileName_s\r\n        | join kind = leftouter\r\n            (\r\n            officedata\r\n            | summarize\r\n                by\r\n                SharePointMetaData_SiteCollectionUrl_s,\r\n                SharePointMetaData_FileName_s,\r\n                TargetUserOrGroupName,\r\n                OfficeObjectId\r\n            | extend Domsplit = split(TargetUserOrGroupName, "@")\r\n            | extend domain = Domsplit[1]\r\n            | summarize TargetDomain = make_list(strcat(domain)) by SharePointMetaData_FileName_s, OfficeObjectId\r\n            | summarize take_any(TargetDomain) by SharePointMetaData_FileName_s, OfficeObjectId\r\n            )\r\n            on OfficeObjectId\r\n        )\r\n        on OfficeObjectId\r\n    );\r\nlet files = (folder\r\n    //| where TargetUserOrGroupName == ""\r\n    | join kind = leftouter\r\n        (officedata\r\n        | summarize TargetUserOrGroupName = make_list(strcat(TargetUserOrGroupName)) by SharePointMetaData_FileName_s, SharePointMetaData_SiteCollectionUrl_s\r\n        | summarize take_any(TargetUserOrGroupName) by SharePointMetaData_FileName_s, SharePointMetaData_SiteCollectionUrl_s   \r\n        | join kind = leftouter\r\n            (\r\n            officedata\r\n            | summarize\r\n                by\r\n                SharePointMetaData_SiteCollectionUrl_s,\r\n                SharePointMetaData_FileName_s,\r\n                TargetUserOrGroupName\r\n            | extend Domsplit = split(TargetUserOrGroupName, "@")\r\n            | extend domain = Domsplit[1]\r\n            | summarize TargetDomain = make_list(strcat(domain)) by SharePointMetaData_FileName_s\r\n            | summarize take_any(TargetDomain) by SharePointMetaData_FileName_s\r\n            )\r\n            on SharePointMetaData_FileName_s\r\n        )\r\n        on SharePointMetaData_FileName_s, SharePointMetaData_SiteCollectionUrl_s\r\n    | extend TargetUserOrGroupName = TargetUserOrGroupName1\r\n    | extend TargetDomain = TargetDomain1\r\n    | where TargetUserOrGroupName != ""\r\n    );\r\nunion folder, files\r\n| summarize arg_max(TimeGenerated, *) by SubjectDoc, UserId, Identifier\r\n| join kind = leftouter\r\n    (\r\n    officedata\r\n    | extend Domsplit = split(TargetUserOrGroupName, "@")\r\n    | extend domain = Domsplit[1]\r\n    | where tolower(domain) in (domains)\r\n    | summarize TargetDomain = make_list(strcat(domain)) by tostring(SharePointMetaData_SiteCollectionUrl_s)\r\n    )\r\n    on SharePointMetaData_SiteCollectionUrl_s\r\n| extend HighRiskDomain = iff(isempty(TargetDomain), "", "HighRiskDomain")\r\n| extend Policy = strcat(tostring(PolicyDetails[0].PolicyName), " ", HighRiskDomain)\r\n| extend RuleName = strcat(tostring(parse_json(tostring(PolicyDetails[0].Rules))[0].RuleName), " ", HighRiskDomain)\r\n| extend SITLocation = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(PolicyDetails[0].Rules))[0].ConditionsMatched)).SensitiveInformation))[0].Location)\r\n| extend OtherMatch = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(PolicyDetails[0].Rules))[0].ConditionsMatched)).OtherConditions))[0])\r\n| extend severity = tostring(PolicyDetails[0].Rules[0].Severity)\r\n| extend Deeplink = strcat("https://compliance.microsoft.com/datalossprevention/alerts/eventdeeplink?eventid=", Identifier, "&creationtime=", CreationTime)\r\n| summarize\r\n    by\r\n    Account,\r\n    Workload,\r\n    SensitiveInformationTypeName,\r\n    tostring(Detected),\r\n    linkoriginal,\r\n    Recipients,\r\n    SubjectDoc,\r\n    TimeGenerated,\r\n    manager,\r\n    department,\r\n    Actions,\r\n    Policy,\r\n    MatchConfidence,\r\n    MatchCount,\r\n    tostring(ExchangeMetaData.MessageID),\r\n    tostring(accountsplit[0]),\r\n    tostring(accountsplit[1]),\r\n    UserId,\r\n    Identifier,\r\n    Label,\r\n    tostring(SharePointMetaData.ExceptionInfo.Reason),\r\n    RuleName,\r\n    SITLocation,\r\n    OtherMatch,\r\n    tostring(severity),\r\n    jobTitle,\r\n    tostring(ExceptionInfo.Justification),\r\n    Deeplink,\r\n    tostring(TargetUserOrGroupName),\r\n    HighRiskDomain'
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
      alertDynamicProperties: []
    }
    customDetails: {
      User: 'Account'
      JobTitle: 'jobTitle'
      SharedWith: 'TargetUserOrGroupName'
      SensitiveData: 'SensitiveInformationTypeName'
      Document: 'SubjectDoc'
      DataShared: 'Detected'
      LocationofDetection: 'SITLocation'
      RuleMatchOther: 'OtherMatch'
      Actions: 'Actions'
      NumberofMatches: 'MatchCount'
      Manager: 'manager'
      Department: 'department'
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
