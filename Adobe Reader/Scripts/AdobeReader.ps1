#requires -version 4
Set-StrictMode -Version 4

Function Get-AdobeReaderInstaller() {
    <#
    .SYNOPSIS
    Gets the Adobe Reader installer file.

    .DESCRIPTION
    Gets the Adobe Reader installer file.

    .PARAMETER ReaderVersion
    Specifies a Adobe Reader version.

    .PARAMETER Path
    The folder path to save the installer to.

    .EXAMPLE
    Get-AdobeReaderInstaller -ReaderVersion '15.010.20060.0'

    .EXAMPLE
    Get-AdobeReaderInstaller -ReaderVersion '15.010.20060.0'

    .EXAMPLE
    Get-AdobeReaderInstaller -ReaderVersion '15.010.20060.0' -Path 'C:\AdobeReader'
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='The Adobe Reader version')]
        [System.Version]$ReaderVersion,

        [Parameter(Position=1, Mandatory=$false, HelpMessage='The folder path to save the installer to')]
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

    $formattedVersion = '{0}{1:000}{2}' -f $ReaderVersion.Major,$ReaderVersion.Minor,$ReaderVersion.Build

    $installer = 'AcroRdrDCUpd{0}.msp' -f $formattedVersion

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