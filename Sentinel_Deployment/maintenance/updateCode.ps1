Invoke-WebRequest -Uri "https://github.com/anders-alex/O365-ActivityFeed-AzureFunction/raw/Sentinel_Deployment3/Sentinel_Deployment/functionPackage.zip" -OutFile "functionPackage.zip"

Publish-AzWebapp -ResourceGroupName " " -Name " " -ArchivePath .\functionPackage.zip -Force -Restart