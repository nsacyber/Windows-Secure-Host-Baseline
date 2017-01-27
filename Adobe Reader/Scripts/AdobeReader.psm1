#requires -version 4
Set-StrictMode -Version 4

Function Get-AdobeReaderManifest() {
    <#
    .SYNOPSIS
    Gets the Adobe Reader manifest file.

    .DESCRIPTION
    Gets the Adobe Reader manifest file.

    .PARAMETER ManifestType
    The type of manifest.

    .PARAMETER Path
    The folder path to save the manifest to.

    .PARAMETER UseHTTP
    Use HTTP instead of HTTPS.

    .EXAMPLE
    Get-AdobeReaderManifest -ManifestType 'ARM'

    .EXAMPLE
    Get-AdobeReaderManifest -ManifestType 'Reader'

    .EXAMPLE
    Get-AdobeReaderManifest -ManifestType 'ReaderServices' -Path 'C:\AdobeReader'

    .EXAMPLE
    Get-AdobeReaderManifest -ManifestType 'ReaderServices' -Path 'C:\AdobeReader' -UseHTTP
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The type of manifest')]
        [ValidateSet('ARM','Reader','ReaderServices', IgnoreCase = $true)]
        [string]$ManifestType,

        [Parameter(Mandatory=$false, HelpMessage='The folder path to save the manifest to')]
        [string]$Path,

        [Parameter(Mandatory=$false, HelpMessage='Use HTTP instead of HTTPS')]
        [switch]$UseHTTP
    )

    # force PSBoundParameters to exist during debugging https://technet.microsoft.com/en-us/library/dd347652.aspx 
    $parameters = $PSBoundParameters

    $installerFolder = $env:USERPROFILE,'Downloads' -join '\'

    if ($parameters.ContainsKey('Path')) {
        $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        $installerFolder = $Path
    }
    
    if (-not(Test-Path -Path $installerFolder -PathType Container)) {
        throw "$installerFolder does not exist"
    }

    $protocol = 'https'

    if($UseHTTP) {
        $protocol = 'http'
    }

    $baseUri = ''
    
    $installer = ''

    switch($ManifestType.ToLower()) {
        'arm' { $installer = 'ArmManifest.msi' ; $baseUri = '{0}://armmf.adobe.com/arm-manifests/win/{1}' ; break }
        'reader' { $installer = 'ReaderDCManifest.msi' ;  $baseUri = '{0}://armmf.adobe.com/arm-manifests/win/{1}'; break }
        'readerservices' { $installer = 'RdrManifest.msi' ; $baseUri = '{0}://armmf.adobe.com/arm-manifests/win/ServicesUpdater/DC/{1}' ; break }
        default { $installer = '' }
    }

    $uri = ($baseUri -f $protocol,$installer)
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
        UserAgent = 'ARM WinINet Downloader'
    }

    $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($uri)

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    if(([string]$proxyUri) -ne $uri) {
        $response = Invoke-WebRequest @params -Proxy $proxyUri -ProxyUseDefaultCredentials -UseBasicParsing
    } else {
        $response = Invoke-WebRequest @params -UseBasicParsing
    }

    $statusCode = $response.StatusCode 

    if ($statusCode -eq 200) {
        $bytes = $response.Content

        $installerFile = ($installerFolder,$installer) -join '\'

        Set-Content -Path $installerFile -Value $bytes -Encoding Byte -Force -NoNewline
    } else {
        throw 'Request failed with status code $statusCode'
    }
}

Function Get-AdobeReaderOfflineInstaller() {
    <#
    .SYNOPSIS
    Gets the Adobe Reader offline installer file.

    .DESCRIPTION
    Gets the Adobe Reader offline installer file.

    .PARAMETER Version
    Specifies an Adobe Reader version.

    .PARAMETER Multilingual
    Get the Multilingual User Interface (MUI) version of Adobe Reader.

    .PARAMETER Path
    The folder path to save the installer to.

    .PARAMETER UseHTTP
    Use HTTP instead of HTTPS.

    .EXAMPLE
    Get-AdobeReaderOfflineInstaller -Version '15.010.20060.0'

    .EXAMPLE
    Get-AdobeReaderOfflineInstaller -Version '2015.010.20060' -Multilingual

    .EXAMPLE
    Get-AdobeReaderOfflineInstaller -Version '2015.10.20060.0' -Path 'C:\AdobeReader'

    .EXAMPLE
    Get-AdobeReaderOfflineInstaller -Version '2015.10.20060.0' -Path 'C:\AdobeReader' -UseHTTP
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The Adobe Reader version')]
        [System.Version]$Version,

        [Parameter(Mandatory=$false, HelpMessage='Get the Multilingual User Interface (MUI) version of Adobe Reader')]
        [switch]$Multilingual,     

        [Parameter(Mandatory=$false, HelpMessage='The folder path to save the installer to')]
        [string]$Path,

        [Parameter(Mandatory=$false, HelpMessage='Use HTTP instead of HTTPS')]
        [switch]$UseHTTP
    )

    # force PSBoundParameters to exist during debugging https://technet.microsoft.com/en-us/library/dd347652.aspx 
    $parameters = $PSBoundParameters

    $installerFolder = $env:USERPROFILE,'Downloads' -join '\'

    if ($parameters.ContainsKey('Path')) {
        $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        $installerFolder = $Path
    }
    
    if (-not(Test-Path -Path $installerFolder -PathType Container)) {
        throw "$installerFolder does not exist"
    }

    $major = [string]$Version.Major

    if ($major.Length -gt 2) {
        $major = $major[-2,-1] -join '' # we only want the last 2 numbers
    }

    $minor = [string]$Version.Minor

    if ($minor.Length -lt 3) {
        $minor = '{0:000}' -f [Int32]$minor # force 0 padding to work
    }

    $build = [string]$Version.Build

    $formattedVersion = '{0}{1:000}{2}' -f $major,$minor,$build

    $installer = 'AcroRdrDC{0}_en_US.exe' -f $formattedVersion

    if ($Multilingual) {
        $installer = 'AcroRdrDC{0}_MUI.exe' -f $formattedVersion
    }

    $protocol = 'https'

    if($UseHTTP) {
        $protocol = 'http'
    }

    $uri = ('{0}://ardownload.adobe.com/pub/adobe/reader/win/AcrobatDC/{1}/{2}' -f $protocol,$formattedVersion,$installer)
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
        UserAgent = 'ARM WinINet Downloader'
    }

    $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($uri)

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    if(([string]$proxyUri) -ne $uri) {
        $response = Invoke-WebRequest @params -Proxy $proxyUri -ProxyUseDefaultCredentials -UseBasicParsing
    } else {
        $response = Invoke-WebRequest @params -UseBasicParsing
    }

    $statusCode = $response.StatusCode 

    if ($statusCode -eq 200) {
        $bytes = $response.Content

        $installerFile = ($installerFolder,$installer) -join '\'

        Set-Content -Path $installerFile -Value $bytes -Encoding Byte -Force -NoNewline
    } else {
        throw 'Request failed with status code $statusCode'
    }
}

#todo: investigate incremental updates: http://ardownload2.adobe.com/pub/adobe/reader/win/AcrobatDC/1501720053/AcroRdrDCUpd1501720053_incr.msp
Function Get-AdobeReaderPatch() {
    <#
    .SYNOPSIS
    Gets the Adobe Reader .msp patch file.

    .DESCRIPTION
    Gets the Adobe Reader .msp patch file.

    .PARAMETER Version
    Specifies an Adobe Reader version.

    .PARAMETER Multilingual
    Get the Multilingual User Interface (MUI) version of Adobe Reader.

    .PARAMETER Path
    The folder path to save the patch file to.

    .PARAMETER UseHTTP
    Use HTTP instead of HTTPS.

    .EXAMPLE
    Get-AdobeReaderPatch -Version '15.010.20060.0'

    .EXAMPLE
    Get-AdobeReaderPatch -Version '2015.010.20060' -Multilingual

    .EXAMPLE
    Get-AdobeReaderPatch -Version '2015.10.20060.0' -Path 'C:\AdobeReader'

    .EXAMPLE
    Get-AdobeReaderPatch -Version '2015.10.20060.0' -Path 'C:\AdobeReader' -UseHTTP
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The Adobe Reader version')]
        [System.Version]$Version,

        [Parameter(Mandatory=$false, HelpMessage='Get the Multilingual User Interface (MUI) version of Adobe Reader')]
        [switch]$Multilingual,     

        [Parameter(Mandatory=$false, HelpMessage='The folder path to save the patch file to')]
        [string]$Path,

        [Parameter(Mandatory=$false, HelpMessage='Use HTTP instead of HTTPS')]
        [switch]$UseHTTP
    )

    # force PSBoundParameters to exist during debugging https://technet.microsoft.com/en-us/library/dd347652.aspx 
    $parameters = $PSBoundParameters

    $installerFolder = $env:USERPROFILE,'Downloads' -join '\'

    if ($parameters.ContainsKey('Path')) {
        $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        $installerFolder = $Path
    }
    
    if (-not(Test-Path -Path $installerFolder -PathType Container)) {
        throw "$installerFolder does not exist"
    }

    $major = [string]$Version.Major

    if ($major.Length -gt 2) {
        $major = $major[-2,-1] -join '' # we only want the last 2 numbers
    }

    $minor = [string]$Version.Minor

    if ($minor.Length -lt 3) {
        $minor = '{0:000}' -f [Int32]$minor # force 0 padding to work
    }

    $build = [string]$Version.Build

    $formattedVersion = '{0}{1:000}{2}' -f $major,$minor,$build

    $installer = 'AcroRdrDCUpd{0}.msp' -f $formattedVersion

    if ($Multilingual) {
        $installer = 'AcroRdrDCUpd{0}_MUI.msp' -f $formattedVersion
    }

    $protocol = 'https'

    if($UseHTTP) {
        $protocol = 'http'
    }

    $uri = ('{0}://ardownload.adobe.com/pub/adobe/reader/win/AcrobatDC/{1}/{2}' -f $protocol,$formattedVersion,$installer)
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
        UserAgent = 'ARM WinINet Downloader'
    }

    $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($uri)

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    if(([string]$proxyUri) -ne $uri) {
        $response = Invoke-WebRequest @params -Proxy $proxyUri -ProxyUseDefaultCredentials -UseBasicParsing
    } else {
        $response = Invoke-WebRequest @params -UseBasicParsing
    }

    $statusCode = $response.StatusCode 

    if ($statusCode -eq 200) {
        $bytes = $response.Content

        $installerFile = ($installerFolder,$installer) -join '\'

        Set-Content -Path $installerFile -Value $bytes -Encoding Byte -Force -NoNewline
    } else {
        throw 'Request failed with status code $statusCode'
    }
}

Function Install-AdobeUpdateTask() {
    <#
    .SYNOPSIS
    Installs a scheduled task that will trigger the Adobe Reader updater.

    .DESCRIPTION
    Installs a scheduled task that will trigger the Adobe Reader updater. The task installed by Adobe Reader does not work on Windows 10.

    .PARAMETER Force
    Force the task installation to occur even if Adobe Reader is not installed on the system.

    .PARAMETER Update
    Update the existing task.

    .EXAMPLE
    Install-AdobeUpdateTask

    .EXAMPLE
    Install-AdobeUpdateTask -Update

    .EXAMPLE
    Install-AdobeUpdateTask -Force

    .EXAMPLE
    Install-AdobeUpdateTask -Force -Update
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$false, HelpMessage='Force the task installation to occur even if Adobe Reader is not installed on the system')]
        [switch]$Force,
        
        [Parameter(Mandatory=$false, HelpMessage='Update the existing task')]
        [switch]$Update  
    )

    $xml = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2016-07-14T14:26:25.9610162</Date>
    <Author></Author>
    <URI>\Adobe Reader x64 Update Task</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <GroupId>S-1-5-4</GroupId> <!-- S-1-5-32-545 -->
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"%ProgramFiles(x86)%\Common Files\Adobe\ARM\1.0\AdobeARM.exe"</Command>
    </Exec>
  </Actions>
</Task>
'@

    $paths = [string[]]@("$env:ProgramFiles\Common Files\Adobe\ARM\1.0","${env:ProgramFiles(x86)}\Common Files\Adobe\ARM\1.0","$env:ProgramW6432\Common Files\Adobe\ARM\1.0")
    $executable = 'AdobeARM.exe'

    $files = [System.IO.FileInfo[]]@(Get-ChildItem -Path $paths -Filter $executable -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.PsIsContainer -eq $false } | Get-Unique)

    if($Force -or ($files.Count -ne 0)) {
        $taskName = 'Adobe Reader x64 Update Task'

        if (-not([System.Environment]::Is64BitOperatingSystem)) {
            $xml = $xml -replace $taskName,'Adobe Reader x86 Update Task'
            $xml = $xml -replace '%ProgramFiles\(x86\)%','%ProgramFiles%'
            $taskName = 'Adobe Reader x86 Update Task'
        }

        if ($Update -or ((Get-ScheduledTask -TaskName  $taskName -ErrorAction SilentlyContinue) -eq $null)) {
            Register-ScheduledTask -Xml $xml -TaskName $taskName -Force | Out-Null
        }
    }
}

Function Invoke-AdobeUpdate() {
    <#
    .SYNOPSIS
    Invokes the Adobe Reader update mechanism.

    .DESCRIPTION
    Invokes the Adobe Reader update mechanism.

    .PARAMETER Force
    Force the update to occur even if the update waiting time period has not elapsed and the EULA has not been accepted.

    .EXAMPLE
    Invoke-AdobeUpdate

    .EXAMPLE
    Invoke-AdobeUpdate -Force
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$false, HelpMessage='Force the update to occur even if the update waiting time period has not elapsed')]
        [switch]$Force  
    )

    $paths = [string[]]@("$env:ProgramFiles\Common Files\Adobe\ARM\1.0","${env:ProgramFiles(x86)}\Common Files\Adobe\ARM\1.0","$env:ProgramW6432\Common Files\Adobe\ARM\1.0")
    $executable = 'AdobeARM.exe'

    $files = [System.IO.FileInfo[]]@(Get-ChildItem -Path $paths -Filter $executable -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.PsIsContainer -eq $false } | Get-Unique)

    if($files.Count -ne 0) {
        $file = $files[0]

        $armRegistryPath = 'hkcu:\Software\Adobe\Adobe ARM\1.0\ARM'

        if($Force -and (Test-Path -Path $armRegistryPath)) {
            $armDataPath = "$env:ProgramData\Adobe\ARM"

            if (Test-Path -Path $armDataPath) {
                $folders = [System.IO.DirectoryInfo[]]@(Get-ChildItem -Path $armDataPath | Where-Object {$_.Name.StartsWith('{')})

                if($folders.Count -ne 0) {
                    $folder = $folders[0]
                    $guid = $folder.Name

                    Remove-ItemProperty -Path $armRegistryPath -Name "tLastT_$guid" -Force -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $armRegistryPath -Name "tTimeWaitedFilesInUse_$guid" -Force -ErrorAction SilentlyContinue
                } 
            }

            Remove-ItemProperty -Path $armRegistryPath -Name 'tLastT_AdobeARM' -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $armRegistryPath -Name 'tLastT_Reader' -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $armRegistryPath -Name 'tTimeWaitedFilesInUse_AdobeARM' -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $armRegistryPath -Name 'tTimeWaitedFilesInUse_Reader' -Force -ErrorAction SilentlyContinue
            
            if([System.Environment]::Is64BitOperatingSystem) {
                $armPath = 'hklm:\Software\WOW6432Node\Adobe\Adobe ARM\1.0\ARM'
            } else {
                $armPath = 'hklm:\Software\Adobe\Adobe ARM\1.0\ARM'
            }

            # make sure systems where the user hasn't accepted the EULA will update
            # if running as a regular user then suppress the access denied error since this is in HKLM unlike the other values above
            Set-ItemProperty -Path $armPath -Name 'iDisableCheckEula' -Value 1 -Type DWORD -Force -ErrorAction SilentlyContinue
        }

        Start-Process -FilePath $file.FullName -NoNewWindow
    }
}