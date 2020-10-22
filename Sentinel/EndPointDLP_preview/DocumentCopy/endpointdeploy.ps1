# Deployment of scheduler for the endpoint script
$logfile = "$env:temp\EndpointTask.log"
if (!(test-path $logfile)) {
    new-item -path $logfile -ItemType File
}
Start-Transcript $logfile
$taskName = "DLPAlert"
$Path = 'PowerShell.exe'
$Arguments = "C:\program files\microsoft\endpointscr.ps1"

$Service = new-object -ComObject ("Schedule.Service")
$Service.Connect()
$RootFolder = $Service.GetFolder("\")
$TaskDefinition = $Service.NewTask(0) # TaskDefinition object https://msdn.microsoft.com/en-us/library/windows/desktop/aa382542(v=vs.85).aspx
$TaskDefinition.RegistrationInfo.Description = ''
$TaskDefinition.Settings.Enabled = $True
$TaskDefinition.Settings.AllowDemandStart = $True
$TaskDefinition.Settings.DisallowStartIfOnBatteries = $False
$Triggers = $TaskDefinition.Triggers
$Trigger = $Triggers.Create(0) ## 0 is an event trigger https://msdn.microsoft.com/en-us/library/windows/desktop/aa383898(v=vs.85).aspx
$Trigger.Enabled = $true
$Trigger.Id = '1134' # 8003 is for disconnections and 8001 is for connections
$Trigger.Subscription = "<QueryList><Query Id='0' Path='Microsoft-Windows-Windows Defender/Operational'><Select Path='Microsoft-Windows-Windows Defender/Operational'>*[System[EventID=1134]]</Select></Query></QueryList>"
$Trigger = $Triggers.Create(0)
$Trigger.Enabled = $true
$Trigger.Id = '1133' # 8003 is for disconnections and 8001 is for connections
$Trigger.Subscription = "<QueryList><Query Id='0' Path='Microsoft-Windows-Windows Defender/Operational'><Select Path='Microsoft-Windows-Windows Defender/Operational'>*[System[EventID=1133]]</Select></Query></QueryList>"
$Action = $TaskDefinition.Actions.Create(0)
$Action.Path = $Path
$action.Arguments = $Arguments
$RootFolder.RegisterTaskDefinition($taskName, $TaskDefinition, 6, "System", $null, 5)

Stop-Transcript
