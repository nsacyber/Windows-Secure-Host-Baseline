#requires -Version 3
Set-StrictMode -Version 3

Function Get-ChromeVersion() {
    <#
    .SYNOPSIS
    Gets the latest Chrome version.

    .DESCRIPTION
    Gets the latest Chrome version for a specific release channel.

    .PARAMETER Channel
    The Chrome release channel. Defaults to 'stable'. Valid values are 'dev', 'canary', 'beta', 'stable'.

    .EXAMPLE
    Get-ChromeVersion

    .EXAMPLE
    Get-ChromeVersion -Channel 'dev'
    #>
    [CmdletBinding()] 
    [OutputType([System.Version])]
    Param(
        [Parameter(Position=0, Mandatory=$false, HelpMessage="The Chrome release channel")]
        [ValidateSet('dev', 'canary', 'beta', 'stable', IgnoreCase = $true)]
        [string]$Channel = 'stable'
    )

    #(New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials | Out-Null

    $uri = ('https://omahaproxy.appspot.com/win?channel={0}' -f $Channel.ToLower())
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
    }

    $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($uri)

    if(([string]$proxyUri) -ne $uri) {
        $response = Invoke-WebRequest @params -Proxy $proxyUri -ProxyUseDefaultCredentials 
    } else {
        $response = Invoke-WebRequest @params 
    }

    $statusCode = $response.StatusCode 

    if ($statusCode -eq 200) {
        $version = $response.Content

        return [System.Version]$version
    } else {
        throw 'Request failed with status code $statusCode'
    }
}

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
        [SYstem.Version]$ChromeVersion
    )

    #(New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials | Out-Null

    if ($ChromeVersion -eq $null) {
        $ChromeVersion = Get-ChromeVersion
    }

    $uri = ('https://clients2.google.com/service/update2/crx?response=redirect&prodversion={0}&x=id%3D{1}%26uc' -f $ChromeVersion,$ExtensionID)
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
        ContentType = 'application/x-chrome-extension' # 'application/octet-stream' also works
        UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/$ChromeVersion Safari/537.36"; # Chrome 49.0.2623.110 64-bit on Windows 10 64-bit
    }

    $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($uri)

    if(([string]$proxyUri) -ne $uri) {
        $response = Invoke-WebRequest @params -Proxy $proxyUri -ProxyUseDefaultCredentials 
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

Function Get-ChromeInstaller() {
    <#
    .SYNOPSIS
    Gets the Chrome installer file.

    .DESCRIPTION
    Gets he Chrome installer file for a specific architecture and release channel.

    .PARAMETER Architecture
    The architecture of Chrome to get the installer for. Valid values are '32' and '64'.

    .PARAMETER ChromeVersion
    Specifies a Chrome version rather than automatically retrieving the version online.

    .PARAMETER Channel
    The Chrome release channel to get the installer for. Defaults to 'stable'. Valid values are 'dev', 'canary', 'beta', 'stable'.

    .EXAMPLE
    Get-ChromeInstaller -Architecture 32

    .EXAMPLE
    Get-ChromeInstaller -Architecture 64

    .EXAMPLE
    Get-ChromeInstaller -Architecture 64 -Channel 'beta'

    .EXAMPLE
    Get-ChromeInstaller -Architecture 64 -Channel 'beta' -ChromeVersion '49.0.2623.110'
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="The Chrome architecture")]
        [ValidateSet('64','32', IgnoreCase = $true)]
        [string]$Architecture,

        [Parameter(Position=1, Mandatory=$false, HelpMessage="The Chrome browser version")]
        [System.Version]$ChromeVersion,

        [Parameter(Position=2, Mandatory=$false, HelpMessage="The Chrome release channel")]
        [ValidateSet('dev', 'canary', 'beta', 'stable', IgnoreCase = $true)]
        [string]$Channel = 'stable'
    )

    #(New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials | Out-Null

    if ($ChromeVersion -eq $null) {
        $ChromeVersion = Get-ChromeVersion -Channel $Channel
    }

    $installer = 'GoogleChromeStandaloneEnterprise.msi'

    if ($Architecture -ieq '64') {
        $installer = 'GoogleChromeStandaloneEnterprise64.msi'
    }

    $uri = ('https://dl.google.com/edgedl/chrome/install/{0}' -f $installer)
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
    }

    $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($uri)

    if(([string]$proxyUri) -ne $uri) {
        $response = Invoke-WebRequest @params -Proxy $proxyUri -ProxyUseDefaultCredentials 
    } else {
        $response = Invoke-WebRequest @params 
    }

    $statusCode = $response.StatusCode 

    if ($statusCode -eq 200) {
        $bytes = $response.Content

        $installerFile = $env:USERPROFILE,'Desktop',('{0}{1}_{2}.msi' -f 'GoogleChromeStandaloneEnterprise',$Architecture,$ChromeVersion) -join '\'

        Set-Content -Path $installerFile -Value $bytes -Encoding Byte -Force -NoNewline
    } else {
        throw 'Request failed with status code $statusCode'
    }
}

Function Get-ChromeGroupPolicyTemplate() {
    <#
    .SYNOPSIS
    Gets the Chrome Group Policy template zip file.

    .DESCRIPTION
    Gets the Chrome Group Policy template zip file.

    .PARAMETER ChromeVersion
    Specifies a Chrome version rather than automatically retrieving the version online.

    .EXAMPLE
    Get-ChromeGroupPolicyTemplate

    .EXAMPLE
    Get-ChromeGroupPolicyTemplate -ChromeVersion '49.0.2623.110'
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$false, HelpMessage="The Chrome browser version")]
        [System.Version]$ChromeVersion
    )

    #(New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials | Out-Null

    if ($ChromeVersion -eq $null) {
        $ChromeVersion = Get-ChromeVersion
    }

    $uri = 'http://dl.google.com/dl/edgedl/chrome/policy/policy_templates.zip'
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
    }

    $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($uri)

    if(([string]$proxyUri) -ne $uri) {
        $response = Invoke-WebRequest @params -Proxy $proxyUri -ProxyUseDefaultCredentials 
    } else {
        $response = Invoke-WebRequest @params 
    }

    $statusCode = $response.StatusCode 

    if ($statusCode -eq 200) {
        $bytes = $response.Content

        $zipFile = $env:USERPROFILE,'Desktop',('{0}_{1}.zip' -f 'ChromeGroupPolicyTemplate',$ChromeVersion) -join '\'

        Set-Content -Path $zipFile -Value $bytes -Encoding Byte -Force -NoNewline
    } else {
        throw 'Request failed with status code $statusCode'
    }
}

Function Get-GoogleUpdateGroupPolicyTemplate() {
    <#
    .SYNOPSIS
    Gets the Google Update Group Policy template file.

    .DESCRIPTION
    Gets the Google Update Group Policy template file.

    .EXAMPLE
    Get-GoogleUpdateGroupPolicyTemplate
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param()

    #(New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials | Out-Null

    $uri = 'http://dl.google.com/update2/enterprise/GoogleUpdate.adm'
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
    }

    $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($uri)

    if(([string]$proxyUri) -ne $uri) {
        $response = Invoke-WebRequest @params -Proxy $proxyUri -ProxyUseDefaultCredentials 
    } else {
        $response = Invoke-WebRequest @params 
    }

    $statusCode = $response.StatusCode 

    if ($statusCode -eq 200) {
        $bytes = $response.Content

        $admFile = $env:USERPROFILE,'Desktop','GoogleUpdate.adm' -join '\'

        Set-Content -Path $admFile -Value $bytes -Encoding Byte -Force -NoNewline
    } else {
        throw 'Request failed with status code $statusCode'
    }
}