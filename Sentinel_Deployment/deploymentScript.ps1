param([string] $PackageUri, [string] $SubscriptionId, [string] $ResourceGroupName, [string] $FunctionAppName, [string] $FAScope, [string] $VnetScope, [string] $UAMIPrincipalId, [string] $RestrictedIPs)

Set-AzContext -Subscription $SubscriptionId

#Give Function App some time to fully finish provisioning.
Start-Sleep -Seconds 60

#Download Function App package and publish.
Invoke-WebRequest -Uri $PackageUri -OutFile functionPackage.zip
Publish-AzWebapp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -ArchivePath functionPackage.zip -Force

Start-Sleep -Seconds 10

#Run Enablement function.
$functionApp = Get-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName
$hostname = $functionApp.DefaultHostName
$key = ((Invoke-AzRestMethod -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -ResourceProviderName Microsoft.Web -ResourceType sites -Name ("$FunctionAppName/host/default/listkeys") -ApiVersion 2022-03-01 -Method POST).Content | ConvertFrom-Json).masterKey
Invoke-RestMethod -Method Post -Uri ("https://$hostname/admin/functions/Enablement") -Headers (@{"Content-Type" = "application/json"; "x-functions-key" = $key}) -Body '{}'

#Add IP restrictions on Function App if specified.
if ($RestrictedIPs -eq 'None') {
    $resource = Get-AzResource -ResourceType Microsoft.Web/sites -ResourceGroupName $ResourceGroupName -ResourceName $FunctionAppName
    $resource.Properties.publicNetworkAccess = 'Disabled'
    $resource | Set-AzResource -Force
}
elseif ($RestrictedIPs -ne '') {
    Add-AzWebAppAccessRestrictionRule -ResourceGroupName $ResourceGroupName -WebAppName $FunctionAppName `
        -Name "Allowed" -IpAddress $RestrictedIPs.Replace(' ', ',') -Priority 100 -Action Allow

    Add-AzWebAppAccessRestrictionRule -ResourceGroupName $ResourceGroupName -WebAppName $FunctionAppName `
        -Name "Allowed" -IpAddress $RestrictedIPs.Replace(' ', ',') -Priority 100 -Action Allow -TargetScmSite
}

#Cleanup the Service Principal Owner role assignments now that access is no longer needed.
Remove-AzRoleAssignment -ObjectId $UAMIPrincipalId -RoleDefinitionName Owner -Scope $FAScope
if ($VnetScope -ne '') { Remove-AzRoleAssignment -ObjectId $UAMIPrincipalId -RoleDefinitionName Owner -Scope $VnetScope }