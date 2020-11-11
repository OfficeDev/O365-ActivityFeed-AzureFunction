$logfile = "$env:temp\enpointdlpUL.log"
$storedtimepath = "$env:temp\endpointtime.log"
if (!(test-path $logfile)) {
    new-item -path $logfile -ItemType File
}
if (!(test-path $storedtimepath)) {
    new-item -path $storedtimepath -itemtype File
}
Start-Transcript -path $logfile -Append
$info = @{}
$storedtime = Get-Content $storedtimepath
$now = (get-date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
if ($null -eq $storedtime) {
    (get-date $now) | Out-File $storedtimepath
    $storedtime = Get-Content $storedtimepath
}

#Function to store content to Azure Storage Blob
Function copy-toazblob {
    param(
        $copypath,
        $policy,
        $computername,
        $timestamp,
        $storedtimepath
    )
    $file = $copypath

    #Get the File-Name without path
    $name = $policy + "--" + $computername + "-" + $timestamp + "-" + ((Get-Item $file).Name)

    Copy-Item $file $env:Temp
    $upload = $env:Temp + "\" + ((Get-Item $file).Name)

    #The target URL wit SAS Token, consider using Azure Key vault and rotate the token. This is poc code.
    $uri = "Https://sampleblob.blob.core.windows.net/endpoint/documents/$($name)? SAS Token"

    #Define required Headers
    $headers = @{'x-ms-blob-type' = 'BlockBlob' }

    #Upload File...
    $response = Invoke-WebRequest -Uri $uri -Method Put -Headers $headers -InFile $upload -UseBasicParsing
    $name
    $StatusCode = $Response.StatusCode
    $StatusCode = 201
    $StatusCode | Out-File "$env:temp\endpointstatus.log"
    if ($StatusCode -eq '201') { $now | Out-file $storedtimepath }
    Remove-Item $upload
    return $StatusCode
}

Try {
    #Get the eventlog$eventlog and then resolve the actual path to pass to the upload function
    $eventlog = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | Where-Object { (($_.message -like "*AccessByUnallowedApp*") -or ($_.message -like "*FileCopiedToRemovableMedia*") -or ($_.message -like "*FileUploadedToCloud*") -or ($_.message -like "*Print*") -or ($_.message -like "*CopyToNetworkShare*") -and ($_.id -in (1134, 1133))) }
    foreach ($event in $eventlog) {
        $entry = ([Xml]$event.ToXml()).event
        $entry.EventData.data | ForEach-Object { $info[$_.Name] = $_."#text" }
        if ((get-date $event.timecreated).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") -gt $storedtime) {

            # Build System Assembly in order to call Kernel32:QueryDosDevice, sample from https://morgantechspace.com/2014/11/Get-Volume-Path-from-Drive-Name-using-Powershell.html
            $DynAssembly = New-Object System.Reflection.AssemblyName('SysUtils')
            $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('SysUtils', $False)

            # Define [Kernel32]::QueryDosDevice method
            $TypeBuilder = $ModuleBuilder.DefineType('Kernel32', 'Public, Class')
            $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('QueryDosDevice', 'kernel32.dll', ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static), [Reflection.CallingConventions]::Standard, [UInt32], [Type[]]@([String], [Text.StringBuilder], [UInt32]), [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
            $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
            $SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
            $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, @('kernel32.dll'), [Reflection.FieldInfo[]]@($SetLastError), @($true))
            $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
            $Kernel32 = $TypeBuilder.CreateType()

            $Max = 65536
            $StringBuilder = New-Object System.Text.StringBuilder($Max)

            $volumes = Get-WmiObject Win32_Volume | Where-Object { $_.DriveLetter }

            ForEach ($vol in $volumes) {
                $ReturnLength = $Kernel32::QueryDosDevice($vol.DriveLetter, $StringBuilder, $Max)
                if ($ReturnLength) {
                    $DriveMapping = @{
                        DriveLetter = $vol.DriveLetter
                        DevicePath  = $StringBuilder.ToString()
                    }
                    New-Object PSObject -Property $DriveMapping
                }
                if ($DriveMapping.DevicePath -eq "\Device\" + $info.source.Split("\")[2]) {
                    $replace = "\Device\" + $info.source.Split("\")[2]
                    $copypath = $info.source.replace($replace, $DriveMapping.DriveLetter)
                    $policy = $info.'Policy Rule Id'
                    $policy
                    $timestamp = (Get-Date $info.'Event Timestamp').ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss")
                    copy-toazblob -copypath $copypath -policy $policy -computername $env:COMPUTERNAME -timestamp $timestamp -storedtimepath $storedtimepath
                }
            }
        }
    }
    stop-transcript
}
catch {
    $_ | Out-File "$env:temp\endpointerror.log"
    Stop-Transcript
}
