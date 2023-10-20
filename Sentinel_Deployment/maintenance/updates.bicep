@description('Name for Data Collection Endpoint used to ingest data into Log Analytics workspace.')
param DataCollectionEndpointName string
@description('Name for Data Collection Rule used to ingest data into Log Analytics workspace.')
param DataCollectionRuleName string
@description('Azure Resource Id of the Log Analytics Workspace where you like the data and optional Function App Application Insights data to reside. The format is: "/subscriptions/xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx/resourcegroups/xxxxxxxx/providers/microsoft.operationalinsights/workspaces/xxxxxxxx"')
param LogAnalyticsWorkspaceResourceId string
@description('Azure location/region of the Log Analytics Workspace referenced in the LogAnalyticsWorkspaceResourceId parameter.')
@allowed(
  [
    'asia'
    'asiapacific'
    'australia'
    'australiacentral'
    'australiacentral2'
    'australiaeast'
    'australiasoutheast'
    'brazil'
    'brazilsouth'
    'brazilsoutheast'
    'canada'
    'canadacentral'
    'canadaeast'
    'centralindia'
    'centralus'
    'centraluseuap'
    'eastasia'
    'eastus'
    'eastus2'
    'eastus2euap'
    'europe'
    'france'
    'francecentral'
    'francesouth'
    'germany'
    'germanynorth'
    'germanywestcentral'
    'global'
    'india'
    'japan'
    'japaneast'
    'japanwest'
    'korea'
    'koreacentral'
    'koreasouth'
    'northcentralus'
    'northeurope'
    'norway'
    'norwayeast'
    'norwaywest'
    'qatarcentral'
    'southafrica'
    'southafricanorth'
    'southafricawest'
    'southcentralus'
    'southeastasia'
    'southindia'
    'swedencentral'
    'switzerland'
    'switzerlandnorth'
    'switzerlandwest'
    'uaecentral'
    'uaenorth'
    'uksouth'
    'ukwest'
    'unitedstates'
    'westcentralus'
    'westeurope'
    'westindia'
    'westus'
    'westus2'
    'westus3'
  ]
)
param LogAnalyticsWorkspaceLocation string
param EndpointSeverityInRuleName bool = true

var endpointSeverityInRuleName = EndpointSeverityInRuleName == true ? 'true' : 'false'

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2021-09-01-preview' existing = {
  name: DataCollectionEndpointName
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

module tablePurviewDLP '../modules/lawCustomTable.bicep' = {
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

module tablePurviewDLPSIT '../modules/lawCustomTable.bicep' = {
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

module tablePurviewDLPDetections '../modules/lawCustomTable.bicep' = {
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

module purviewDLPFunction '../modules/lawFunction.bicep' = {
  scope: resourceGroup(split(LogAnalyticsWorkspaceResourceId, '/')[2], split(LogAnalyticsWorkspaceResourceId, '/')[4])
  name: 'purviewDLPFunction'
  dependsOn: [
    dcr
    dce
    tablePurviewDLP
    tablePurviewDLPDetections
    tablePurviewDLPSIT 
  ] 
  params: {
    category: 'DLP' 
    displayName: 'Microsoft Purview DLP' 
    functionName: 'PurviewDLP' 
    lawName: split(LogAnalyticsWorkspaceResourceId, '/')[8]
    functionAlias: 'PurviewDLP' 
    functionParams: 'WorkloadNames:dynamic = dynamic([\'Exchange\', \'MicrosoftTeams\', \'SharePoint\', \'OneDrive\', \'Endpoint\']), EndpointSeverityInRuleName:bool = ${endpointSeverityInRuleName}, EndpointHighSeverityMatchCountTrigger:int = 50, EndpointSeverityDelimiter:string = \' \''
    query: 'let _DetectionsMax = 5;\nlet _SITMax = 30;\nlet _EndpointSeverityInRuleName = EndpointSeverityInRuleName;\nlet _EndpointHighSeverityMatchCountTrigger = EndpointHighSeverityMatchCountTrigger;\nlet _EndpointSeverityDelimiter = EndpointSeverityDelimiter;\nlet _WorkloadNames = WorkloadNames;\n\n//Get DLP data elements that are shared across all workloads.\nlet DLPCommon = PurviewDLP_CL\n| where Workload in (_WorkloadNames) and Workload != \'Endpoint\' and Operation =~ \'DLPRuleMatch\'\n| summarize arg_max(TimeGenerated, *) by Identifier\n| mv-expand PolicyDetails\n| where PolicyDetails.PolicyName != \'\'\n| mv-expand Rules = PolicyDetails.Rules\n| summarize TotalMatchCount = toint(sum(toint(Rules.ConditionsMatched.TotalCount))), arg_max(TimeGenerated, *) by Identifier\n| join kind=leftouter (PurviewDLPSIT_CL\n    | summarize arg_max(TimeGenerated, *) by Identifier, SensitiveInformationTypeName\n    | join kind=leftouter (PurviewDLPDetections_CL\n        | summarize arg_max(TimeGenerated, *) by Identifier, Name, Value, SensitiveInfoId\n        | extend Detections = bag_pack(\'Name\', Name, \'Value\', Value)\n        | summarize Detections = make_list(Detections, _DetectionsMax), arg_max(TimeGenerated, *) by SensitiveInfoId\n        ) on SensitiveInfoId\n    ) on Identifier\n| extend SensitiveInfoType = bag_pack(\'Name\', SensitiveInformationTypeName, \'Count\', toint(SITCount), \'Confidence\', toint(Confidence), \'Location\', Location, \'Detections\', Detections)\n| extend ActionsTaken = strcat_array(Rules.Actions, \', \')\n| extend SensitiveInfoTypeString = iff(SensitiveInfoType.Count > 0, strcat(SensitiveInfoType.Name, \' (\', SensitiveInfoType.Count, \', \', SensitiveInfoType.Confidence, \'%)\'), \'\')\n| summarize SensitiveInfoTypesArray = make_list(SensitiveInfoType, _SITMax), SensitiveInfoTypes = make_list(SensitiveInfoTypeString), arg_max(TimeGenerated, *) by Identifier\n| extend\n    PolicyName = tostring(PolicyDetails.PolicyName),\n    RuleName = tostring(Rules.RuleName),\n    RuleSeverity = tostring(Rules.Severity),\n    UserPrincipalName = tolower(UserId),\n    UserObjectId = UserKey,\n    Deeplink = strcat(\'https://compliance.microsoft.com/datalossprevention/alerts/eventdeeplink?eventid=\', Identifier, \'&creationtime=\', CreationTime);\n\n//Get Sharepoint and OneDrive specific data elements from common datatable defined above.\nlet DLPSPOD = DLPCommon\n| where Workload in (\'SharePoint\', \'OneDrive\')\n| extend SensitivityLabelIds = todynamic(iff(array_length(SharePointMetaData.SensitivityLabelIds) == 0, \'\', SharePointMetaData.SensitivityLabelIds))\n| mv-expand SensitivityLabelId = SensitivityLabelIds\n| extend SensitivityLabelId = tostring(SensitivityLabelId)\n| join kind = leftouter (_GetWatchlist(\'SensitivityLabels\')\n    | extend SensitivityLabelId = tostring(column_ifexists(\'id\', \'\')),\n        SensitivityLabelName = tostring(column_ifexists(\'name\', \'\'))) on SensitivityLabelId\n| extend OfficeObjectId = url_decode(tostring(SharePointMetaData.FilePathUrl))\n| join kind = leftouter (OfficeActivity\n    | where TimeGenerated > ago(30m)\n    | where Operation == "AddedToSecureLink" or Operation == "SecureLinkUsed"\n    | extend UserId = tolower(UserId),\n        TargetUserOrGroupName = tolower(iff(isempty(TargetUserOrGroupName), split(UserId, "#")[1], TargetUserOrGroupName))\n    ) on $left.UserPrincipalName == $right.UserId, OfficeObjectId\n| extend Filename = tostring(SharePointMetaData.FileName),\n    FilePath = tostring(SharePointMetaData.FilePathUrl),\n    SiteUrl = tostring(SharePointMetaData.SiteCollectionUrl),\n    ExceptionReason = tostring(SharePointMetaData.ExceptionInfo.Reason)\n| summarize SensitivityLabels = make_list(SensitivityLabelName), arg_max(TimeGenerated, *) by Identifier;\n\n//Get Exchange and Teams specific data elements from common datatable defined above.\nlet DLPEXOT = DLPCommon\n| where Workload in (\'Exchange\', \'MicrosoftTeams\')\n| extend Recipients = iff(Workload == \'Exchange\', tostring(strcat(array_strcat(ExchangeMetaData.To, \', \'), iff(array_length(ExchangeMetaData.CC) == 0, \'\', ", "), array_strcat(ExchangeMetaData.CC, \', \'), iff(array_length(ExchangeMetaData.BCC) == 0, \'\', ", "))), tostring(strcat_array(ExchangeMetaData.To, \', \'))),\n    InternetMessageId = replace_string(replace_string(tostring(ExchangeMetaData.MessageID), \'<\', \'\'), \'>\',\'\'),\n    EmailSubject = tostring(ExchangeMetaData.Subject),\n    Sender = UserPrincipalName,\n    ExceptionReason = tostring(ExchangeMetaData.ExceptionInfo.Reason),\n    ExceptionJustification = tostring(ExchangeMetaData.ExceptionInfo.Justification)\n| summarize DetectedLocations = make_set(SensitiveInfoType.Location), arg_max(TimeGenerated, *) by Identifier;\n\n//Define datatable so we can lookup Endpoint DLP action names from their Id.\nlet EndpointAction = datatable(ActionName: string, ActionId: int) [\n    "None", "0",\n    "Audit", "1",\n    "Warn", "2",\n    "WarnAndBypass", "3",\n    "Block", "4",\n    "Allow", "5"\n];\n//Array to match severity as the last word in rule name if present.\nlet EndpointSeverities = dynamic([\'Low\', \'Medium\', \'High\']);\n\n//Get Endpoint specific data elements from common datatable defined above.\nlet DLPEndpoint = PurviewDLP_CL\n| where Workload in (\'Endpoint\') and \'Endpoint\' in (_WorkloadNames) and  Operation =~ \'DLPRuleMatch\'\n| summarize arg_max(TimeGenerated, *) by Identifier\n| extend IngestionTime = ingestion_time()\n| mv-expand PolicyDetails\n| where PolicyDetails.PolicyName != \'\'\n| mv-expand Rules = PolicyDetails.Rules\n| join kind=leftouter (PurviewDLPSIT_CL\n    | summarize arg_max(TimeGenerated, *) by Identifier, SensitiveInformationTypeName\n    | join kind=leftouter (PurviewDLPDetections_CL\n        | summarize arg_max(TimeGenerated, *) by Identifier, Name, Value\n        | extend Detections = bag_pack(\'Name\', Name, \'Value\', Value)\n        | summarize Detections = make_list(Detections, _DetectionsMax), arg_max(TimeGenerated, *) by SensitiveInfoId\n        ) on SensitiveInfoId\n    ) on Identifier\n| extend SensitiveInfoType = bag_pack(\'Name\', SensitiveInformationTypeName, \'Count\', toint(SITCount), \'Confidence\', toint(Confidence), \'Location\', Location, \'Detections\', Detections)\n| extend SensitiveInfoType = bag_pack(\'Name\', SensitiveInformationTypeName, \'Count\', toint(SITCount), \'Confidence\', toint(Confidence)),\n    DeviceFullName = tostring(EndpointMetaData.DeviceName)\n| extend TotalMatchCount = toint(EndpointMetaData.SensitiveInfoTypeTotalCount)\n| extend RuleSplit = split(tostring(Rules.RuleName), _EndpointSeverityDelimiter)\n| extend RuleLength = array_length(RuleSplit)\n| extend RuleSeverity = iff(RuleSplit[RuleLength - 1] in (EndpointSeverities) and _EndpointSeverityInRuleName == true, RuleSplit[RuleLength - 1], iff(TotalMatchCount >= _EndpointHighSeverityMatchCountTrigger and _EndpointSeverityInRuleName == false, \'High\', \'Medium\'))\n| extend Exception = tostring(EndpointMetaData.Justification)\n| extend ExceptionReason = substring(Exception, indexof(Exception, \'_\') + 1)\n| extend ExceptionReason = substring(ExceptionReason, 0, indexof(ExceptionReason, \':\'))\n| extend ExceptionJustification = substring(Exception, indexof(Exception, \':\') + 1)\n| extend SensitiveInfoTypeString = iff(SensitiveInfoType.Count > 0, strcat(SensitiveInfoType.Name, \' (\', SensitiveInfoType.Count, \', \', SensitiveInfoType.Confidence, \'%)\'), \'\'),\n    ActionId = toint(EndpointMetaData.EnforcementMode),\n    ClientIP = tostring(EndpointMetaData.ClientIP),\n    DeviceHostName = tostring(split(DeviceFullName, \'.\')[0]), \n    DeviceDNSName = tostring(substring(DeviceFullName, indexof(DeviceFullName, \'.\')+1)),\n    Filename = DocumentName,\n    FilePath = ObjectId,\n    FileHash = tostring(EndpointMetaData.Sha256),\n    FileHashAlgorithm = \'SHA256\',\n    RMSEncrypted = tostring(EndpointMetaData.RMSEncrypted),\n    EvidenceFileUrl = tostring(EvidenceFile.FullUrl),\n    SourceLocationType = tostring(EndpointMetaData.SourceLocationType), \n    EndpointOperation = tostring(EndpointMetaData.EndpointOperation),\n    EndpointApplication = tostring(EndpointMetaData.Application),\n    EndpointClientIp = tostring(EndpointMetaData.ClientIP),\n    PolicyName = tostring(PolicyDetails.PolicyName),\n    RuleName = tostring(Rules.RuleName),\n    UserPrincipalName = tolower(UserId),\n    UserObjectId = UserKey,\n    Deeplink = strcat(\'https://compliance.microsoft.com/datalossprevention/alerts/eventdeeplink?eventid=\', Identifier, \'&creationtime=\', CreationTime)\n| join kind = inner(EndpointAction) on ActionId\n| extend ActionsTaken = ActionName\n| summarize SensitiveInfoTypesArray = make_list(SensitiveInfoType, _SITMax), SensitiveInfoTypes = make_list(SensitiveInfoTypeString), arg_max(TimeGenerated, *) by Identifier;\n\n//Merge all the SharePoint/OneDrive, Exchange/Teams, and Endpoints results together.\nunion DLPSPOD, DLPEXOT, DLPEndpoint\n| extend FileDirectory = parse_path(FilePath).DirectoryPath\n| project \n//Common attributes\nTimeGenerated, CreationTime, \nCreationTimeString = strcat(format_datetime(CreationTime,\'M/d/yyyy, H:mm:ss tt\'), \' (UTC)\'),\nIdentifier, Workload, Deeplink, usageLocation, UserPrincipalName, UserObjectId, department, manager, jobTitle, PolicyName, RuleName, ActionsTaken, SensitiveInfoTypesArray, TotalMatchCount, \nUsername = split(UserPrincipalName, \'@\')[0], UPNSuffix =split(UserPrincipalName, \'@\')[1],\nRuleSeverity,\nSensitiveInfoTypes = iff(array_length(SensitiveInfoTypes) > 1, strcat(SensitiveInfoTypes[0], \' +\', array_length(SensitiveInfoTypes) - 1, \' more\'), strcat_array(SensitiveInfoTypes, \', \')),\n//Endpoint specific attributes\nDeviceFullName, DeviceHostName, DeviceDNSName, Filename, FilePath, FileDirectory, FileHash, FileHashAlgorithm, RMSEncrypted, EvidenceFileUrl, SourceLocationType, EndpointOperation, EndpointApplication, EndpointClientIp, Operation,\n//Exchange and Teams specific attributes\nRecipients, InternetMessageId, EmailSubject, Sender, ExceptionReason, ExceptionJustification,\n//SharePoint and OneDrive specific attributes\nSiteUrl, TargetUserOrGroupName,\nDetectedLocations = strcat_array(DetectedLocations, \', \'), SensitivityLabels = strcat_array(SensitivityLabels, \', \')\n| order by CreationTime'
  }
}
