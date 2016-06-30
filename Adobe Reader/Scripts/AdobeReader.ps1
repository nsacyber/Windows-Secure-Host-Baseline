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

    .EXAMPLE
    Get-AdobeReaderManifest -ManifestType 'ARM'

    .EXAMPLE
    Get-AdobeReaderManifest -ManifestType 'Reader'

    .EXAMPLE
    Get-AdobeReaderManifest -ManifestType 'ReaderServices' -Path 'C:\AdobeReader'
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='The type of manifest')]
        [ValidateSet('ARM','Reader','ReaderServices', IgnoreCase = $true)]
        [string]$ManifestType,

        [Parameter(Position=1, Mandatory=$false, HelpMessage='The folder path to save the manifest to')]
        [string]$Path
    )

    # force PSBoundParameters to exist during debugging https://technet.microsoft.com/en-us/library/dd347652.aspx 
    $parameters = $PSBoundParameters

    $installerFolder = $env:USERPROFILE,'Downloads' -join '\'

    if ($parameters.ContainsKey('Path')) {
        $installerFolder = $Path
    }
    
    if (-not(Test-Path -Path $installerFolder -PathType Container)) {
        throw "$installerFolder does not exist"
    }

    $baseUri = ''
    
    $installer = ''

    switch($ManifestType.ToLower()) {
        'arm' { $installer = 'ArmManifest.msi' ; $baseUri = ' http://armmf.adobe.com/arm-manifests/win/{0}' ; break }
        'reader' { $installer = 'ReaderDCManifest.msi' ;  $baseUri = ' http://armmf.adobe.com/arm-manifests/win/{0}'; break }
        'readerservices' { $installer = 'RdrManifest.msi' ; $baseUri = 'http://armmf.adobe.com/arm-manifests/win/ServicesUpdater/DC/{0}' ; break }
        default { $installer = '' }
    }

    $uri = ($baseUri -f $installer)
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
        UserAgent = 'ARM WinINet Downloader'
    }

    $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($uri)

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    if(([string]$proxyUri) -ne $uri) {
        $response = Invoke-WebRequest @params -Proxy $proxyUri -ProxyUseDefaultCredentials 
    } else {
        $response = Invoke-WebRequest @params 
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

Function Get-AdobeReaderInstaller() {
    <#
    .SYNOPSIS
    Gets the Adobe Reader installer file.

    .DESCRIPTION
    Gets the Adobe Reader installer file.

    .PARAMETER ReaderVersion
    Specifies a Adobe Reader version.

    .PARAMETER Multilingual
    Get the Multilingual User Intrace (MUI) version of Adobe Reader.

    .PARAMETER Path
    The folder path to save the installer to.

    .EXAMPLE
    Get-AdobeReaderInstaller -ReaderVersion '15.010.20060.0'

    .EXAMPLE
    Get-AdobeReaderInstaller -ReaderVersion '2015.010.20060' -Multi

    .EXAMPLE
    Get-AdobeReaderInstaller -ReaderVersion '2015.10.20060.0' -Path 'C:\AdobeReader'
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='The Adobe Reader version')]
        [System.Version]$ReaderVersion,

        [Parameter(Position=1, Mandatory=$false, HelpMessage='Get the Multilingual User Intrace (MUI) version of Adobe Reader')]
        [switch]$Multi,     

        [Parameter(Position=2, Mandatory=$false, HelpMessage='The folder path to save the installer to')]
        [string]$Path
    )

    # force PSBoundParameters to exist during debugging https://technet.microsoft.com/en-us/library/dd347652.aspx 
    $parameters = $PSBoundParameters

    $installerFolder = $env:USERPROFILE,'Downloads' -join '\'

    if ($parameters.ContainsKey('Path')) {
        $installerFolder = $Path
    }
    
    if (-not(Test-Path -Path $installerFolder -PathType Container)) {
        throw "$installerFolder does not exist"
    }

    $major = [string]$ReaderVersion.Major

    if ($major.Length -gt 2) {
        $major = $major[-2,-1] -join '' # we only want the last 2 numbers
    }

    $minor = [string]$ReaderVersion.Minor

    if ($minor.Length -lt 3) {
        $minor = '{0:000}' -f [Int32]$minor # force 0 padding to work
    }

    $build = [string]$ReaderVersion.Build

    $formattedVersion = '{0}{1:000}{2}' -f $major,$minor,$build

    $installer = 'AcroRdrDCUpd{0}.msp' -f $formattedVersion

    if ($Multilingual) {
        $installer = 'AcroRdrDCUpd{0}_MUI.msp' -f $formattedVersion
    }

    $uri = ('http://ardownload.adobe.com/pub/adobe/reader/win/AcrobatDC/{0}/{1}' -f $formattedVersion,$installer)
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
        UserAgent = 'ARM WinINet Downloader'
    }

    $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($uri)

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    if(([string]$proxyUri) -ne $uri) {
        $response = Invoke-WebRequest @params -Proxy $proxyUri -ProxyUseDefaultCredentials 
    } else {
        $response = Invoke-WebRequest @params 
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