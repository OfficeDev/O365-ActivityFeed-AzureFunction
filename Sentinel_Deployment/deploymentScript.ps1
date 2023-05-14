param([string] $PackageUri, [string] $SubscriptionId, [string] $ResourceGroupName, [string] $FunctionAppName, [string] $FAScope, [string] $ClientId, [string] $TenantId, [string] $KeyVaultName, [string] $VnetScope, [string] $UAMIPrincipalId, [string] $RestrictedIPs)

Set-AzContext -Subscription $SubscriptionId

#Give Function App some time to fully finish provisioning.
Start-Sleep -Seconds 60

$clientSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "ClientSecret" -AsPlainText
$loginURL = "https://login.microsoftonline.com"
$resource = "https://manage.office.com"

#Get an Oauth 2 access token based on client id, secret and tenant domain
$body = @{grant_type="client_credentials";resource=$resource;client_id=$ClientId;client_secret=$clientSecret}
$oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$TenantId/oauth2/token?api-version=1.0 -Body $body

#Let's put the oauth token in the header
$headerParams  = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}

#Enable auditing subscriptions if needed.
$subs = Invoke-RestMethod -Headers $headerParams -Uri "https://manage.office.com/api/v1.0/$TenantId/activity/feed/subscriptions/list"
if (($subs | Where-Object contentType -eq DLP.All).status -ne 'enabled') {
    Invoke-RestMethod -Method Post -Headers $headerParams -Uri "https://manage.office.com/api/v1.0/$TenantId/activity/feed/subscriptions/start?contentType=DLP.All"
}

#Download Function App package and publish.
Invoke-WebRequest -Uri $PackageUri -OutFile functionPackage.zip
Publish-AzWebapp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -ArchivePath functionPackage.zip -Force

Start-Sleep -Seconds 10

<#Run Enablement function.
$functionApp = Get-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName
$hostname = $functionApp.DefaultHostName
$key = ((Invoke-AzRestMethod -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -ResourceProviderName Microsoft.Web -ResourceType sites -Name ("$FunctionAppName/host/default/listkeys") -ApiVersion 2022-03-01 -Method POST).Content | ConvertFrom-Json).masterKey
Invoke-RestMethod -Method Post -Uri ("https://$hostname/admin/functions/Enablement") -Headers (@{"Content-Type" = "application/json"; "x-functions-key" = $key}) -Body '{}'
#>

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