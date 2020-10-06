$info = @{}
$storedtime = Get-Content "$env:TEMP\endpointtime.log"  
$now = (get-date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

if ($storedtime -eq $null) {
    (get-date $now).AddHours(-24) | Out-File "$env:TEMP\endpointtime.log"
    $storedtime = Get-Content "$env:TEMP\endpointtime.log" 
                           }

#Function to store content to Azure Storage Blob
Function Post-toazblob($copypath, $policy)  {
$file = $copypath

#Get the File-Name without path
$name = $policy + "--" + $eventlog[0].System.Computer + "-" + ((Get-Item $file).Name)

Copy-Item $file $env:Temp
$upload = $env:Temp + "\" + ((Get-Item $file).Name)

#The target URL wit SAS Token, consider using Azure Key vault and rotate the token. This is poc code.
$uri = "https://sampleblob.blob.core.windows.net/endpoint/documents/$($name)? SAS Token"

#Define required Headers
$headers = @{'x-ms-blob-type' = 'BlockBlob'}

#Upload File...
$response = Invoke-WebRequest -Uri $uri -Method Put -Headers $headers -InFile $upload 
   $StatusCode = $Response.StatusCode
    if ($StatusCode -eq '201') {$now | Out-file "$env:Temp\endpointtime.log"}
Remove-Item $upload            
                }

#Get the eventlog$eventlog and then resolve the actual path to pass to the upload function
$eventlog =Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |  %{([xml]$_.ToXml()).Event} | Where-Object {(($_.EventData.data."#text" -contains "AccessByUnallowedApp") -or ($_.EventData.Data."#text" -contains "FileCopiedToRemovableMedia") -or ($_.EventData.data."#text" -contains "FileUploadedToCloud") -or ($_.EventData.data."#text" -contains "Print") -or ($_.EventData.data."#text" -contains "FileCopiedToNetworkShare"))}
foreach ($entry in $eventlog) { $entry.EventData.data | foreach {$info[$_.Name] = $_."#text"}
                
if ((get-date $info.'Event Timestamp').ToString("yyyy-MM-ddTHH:mm:ss.fffZ") -gt $storedtime) {

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
 
   Get-WmiObject Win32_Volume | ? { $_.DriveLetter } | % {
       $ReturnLength = $Kernel32::QueryDosDevice($_.DriveLetter, $StringBuilder, $Max)
 
       if ($ReturnLength)
       {
           $DriveMapping = @{
               DriveLetter = $_.DriveLetter
               DevicePath = $StringBuilder.ToString()
           }
 
           New-Object PSObject -Property $DriveMapping
       
          }
   
   if ($DriveMapping.DevicePath -eq "\Device\" + $info.source.Split("\")[2]) 
      {
   $replace = "\Device\" + $info.source.Split("\")[2]
   $copypath = $info.source.replace($replace, $DriveMapping.DriveLetter)
   $policy = $info.'Policy Rule Id'

   Post-toazblob $copypath $policy
      }
    }
  }
}
