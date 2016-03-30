#requires -Version 3
Set-StrictMode -Version 3

Function Get-ChromeExtension() {
    <#
    .SYNOPSIS
    Gets a Chrome extension from the Chrome Web Store.

    .DESCRIPTION
    Gets a Chrome extension from the Chrome Web Store.

    .PARAMETER ExtensionID
    The Chrome extension ID.

    .PARAMETER ExtensionTitle
    The Chrome extension title.

    .PARAMETER ExtensionVersion
    The Chrome extension version.

    .PARAMETER ChromeVersion
    The Chrome browser version.

    .EXAMPLE
    Get-ChromeExtension -ExtensionID 'djflhoibgkdhkhhcedjiklpkjnoahfmg' -ExtensionTitle 'User-Agent Switcher for Chrome' -ExtensionVersion '1.0.43'

    .EXAMPLE
    Get-ChromeExtension -ExtensionID 'djflhoibgkdhkhhcedjiklpkjnoahfmg' -ExtensionTitle 'User-Agent Switcher for Chrome' -ExtensionVersion '1.0.43' -ChromeVersion '49.0.2623.110'
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="The Chrome extension ID")]
        [string]$ExtensionID,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="The Chrome extension title")]
        [string]$ExtensionTitle,

        [Parameter(Position=2, Mandatory=$true, HelpMessage="The Chrome extension version")]
        [string]$ExtensionVersion,

        [Parameter(Position=3, Mandatory=$false, HelpMessage="The Chrome browser version")]
        [string]$ChromeVersion = '49.0.2623.110'
    )

    #(New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials | Out-Null

    $extensionUri = ('https://clients2.google.com/service/update2/crx?response=redirect&prodversion={0}&x=id%3D{1}%26uc' -f $ChromeVersion,$ExtensionID)
  
    $params = @{
        Uri = $extensionUri;
        Method = 'Get';
        ContentType = 'application/x-chrome-extension' # 'application/octet-stream' also works
        UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/$ChromeVersion Safari/537.36"; # Chrome 49.0.2623.110 64-bit on Windows 10 64-bit
    }

    $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($extensionUri)

    if(([string]$proxyUri) -ne $extensionUri) {
        $response = Invoke-WebRequest @params -ProxyUri $proxyUri -ProxyUseDefaultCredentials 
    } else {
        $response = Invoke-WebRequest @params 
    }

    $statusCode = $response.StatusCode 

    if ($statusCode -eq 200) {
        $bytes = $response.Content

        $extensionFile = $env:USERPROFILE,'Desktop',('{0}-{1}.crx' -f $ExtensionTitle,$ExtensionVersion) -join '\'

        Set-Content -Path $extensionFile -Value $bytes -Encoding Byte -Force -NoNewline
    } else {
        throw 'Request failed with status code $statusCode'
    }
}