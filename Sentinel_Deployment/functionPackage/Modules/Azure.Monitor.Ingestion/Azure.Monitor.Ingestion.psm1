function Send-DataToAzureMonitorBatched {
    param ($Data, $BatchSize = 0, $TableName, $JsonDepth, $UamiClientId, $DceURI, $DcrImmutableId, $DataAlreadyGZipEncoded = $false, $SortBySize = $true, $Delay = 0, $MaxRetries = 5, $EventIdPropertyName)
    $skip = 0
    $errorCount = 0
    if ($BatchSize -eq 0) { $BatchSize = $Data.Count }
    #Sort data by size, smallest to largest to get optimal batching.
    if ($SortBySize -eq $true) { 
        Write-Host "Sorting data..."
        $getSize = { ($_ | ConvertTo-Json -Depth $JsonDepth).Length }
        $Data = $Data | Sort-Object -Property $getSize 
    }
    #Enter error handling loop to send data.
    Write-Host "Sending data to Azure Monitor..."
    do {
        try {
            do {
                if ($Data.Count -lt $BatchSize) { $BatchSize = $Data.Count }
                $batchedData = $Data | Select-Object -Skip $skip -First $BatchSize
                if ($batchedData.Count -eq 0) { return }
                Send-DataToAzureMonitor -Data $batchedData -TableName $TableName -JsonDepth $JsonDepth -UamiClientId $UamiClientId -DceUri $DceURI -DcrImmutableId $DcrImmutableId -DataAlreadyGZipEncoded $DataAlreadyGZipEncoded | Out-Null
                $skip += $BatchSize
                Start-Sleep -Milliseconds $Delay
            } until ($skip -ge $Data.Count)
            return
        }
        catch {
            if ($_.Exception.InnerException.Message -like "*ErrorCode: ContentLengthLimitExceeded*") { 
                if ($BatchSize -eq 1) {
                    Write-Error ("Event ID: " + $batchedData[0].$EventIdPropertyName + " is too large to submit to Azure Monitor. JSON Length: " + ($batchedData[0] | ConvertTo-Json -Depth $JsonDepth).Length + ". $_") -ErrorAction Continue
                    if ($skip -lt ($Data.Count - 1 )) {
                        $skip++
                    } 
                    else {
                        $errorCount = $MaxRetries
                    }
                }
                else {
                    $BatchSize = [math]::Round($BatchSize / 2)
                    if ($BatchSize -lt 1) { $BatchSize = 1 }
                    Write-Host ("Data too large, reducing batch size to: $BatchSize.")
                }
            }
            else { 
                Write-Error $_ -ErrorAction Continue
                $errorCount++
            }
        }
    } while ($errorCount -lt $MaxRetries)
}

function Send-DataToAzureMonitor {
    param ($Data, $TableName, $JsonDepth, $UamiClientId, $DceUri, $DcrImmutableId, $DataAlreadyGZipEncoded = $false)
    #Create Azure.Identity credential via User Assigned Managed Identity.
    $credential = New-Object Azure.Identity.ManagedIdentityCredential($UamiClientId)
    #Create LogsIngestionClient to handle sending data to Azure Monitor.
    $logIngestionClient = New-Object Azure.Monitor.Ingestion.LogsIngestionClient($DceURI, $credential)
    #Send data to Azure Monitor.
    if ($DataAlreadyGZipEncoded -eq $false) { $logIngestionClient.Upload($DcrImmutableId, $TableName, ($Data | ConvertTo-Json -Depth $JsonDepth -AsArray)) | Out-Null }
    else { $logIngestionClient.Upload($dcrImmutableId, $TableName, ($Data | ConvertTo-Json -Depth $JsonDepth -AsArray), 'gzip') | Out-Null }
}

Export-ModuleMember -Function Send-DataToAzureMonitor
Export-ModuleMember -Function Send-DataToAzureMonitorBatched