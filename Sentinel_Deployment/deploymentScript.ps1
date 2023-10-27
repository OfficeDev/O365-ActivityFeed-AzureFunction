param([string] $PackageUri, [string] $SubscriptionId, [string] $ResourceGroupName, [string] $FunctionAppName, [string] $FAScope, [string] $VnetScope, [string] $UAMIPrincipalId, [string] $RestrictedIPs)

Set-AzContext -Subscription $SubscriptionId

$tenantId = $env:TenantId
$clientId = $env:ClientId
$clientSecret = $env:ClientSecret
$loginURL = "https://login.microsoftonline.com"
$resource = "https://manage.office.com"

#Get an Oauth 2 access token based on client id, secret and tenant domain
$body = @{grant_type = "client_credentials"; resource = $resource; client_id = $clientId; client_secret = $clientSecret }
$oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantId/oauth2/token?api-version=1.0 -Body $body
$token = $oauth.access_token | ConvertTo-SecureString -AsPlainText

#Enable auditing subscriptions if needed.
try { 
    $subs = Invoke-RestMethod -Authentication Bearer -Token $token -Uri "https://manage.office.com/api/v1.0/$tenantId/activity/feed/subscriptions/list" -RetryIntervalSec 2 -MaximumRetryCount 5 
    if (($subs | Where-Object contentType -eq DLP.All).status -ne 'enabled') {
        Invoke-RestMethod -Method Post -Authentication Bearer -Token $token -Uri "https://manage.office.com/api/v1.0/$tenantId/activity/feed/subscriptions/start?contentType=DLP.All" -RetryIntervalSec 2 -MaximumRetryCount 5
        Write-Host "Enabled DLP.ALL subscription."
    }
    else {
        Write-Host "DLP.ALL subscription already enabled."
    }
}
catch { Write-Error ("Error calling Office 365 Management API. " + $_.Exception) -ErrorAction Continue }

#Download Function App package and publish.
Invoke-WebRequest -Uri $PackageUri -OutFile functionPackage.zip
Publish-AzWebapp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -ArchivePath functionPackage.zip -Force

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