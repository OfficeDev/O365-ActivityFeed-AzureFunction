#Download latest Function App package.
Invoke-WebRequest -Uri "https://github.com/anders-alex/O365-ActivityFeed-AzureFunction/raw/Sentinel_Deployment3/Sentinel_Deployment/functionPackage.zip" -OutFile "functionPackage.zip"

#Select the subscription that contains the Function App to be updated.
Set-AzContext -Subscription '[Subscription name]'

#Update Function App with the new package.
Publish-AzWebapp -ResourceGroupName "[Resource group name]" -Name "[Function App name]" -ArchivePath functionPackage.zip -Force