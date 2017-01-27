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

    .PARAMETER UseHTTP
    Use HTTP instead of HTTPS.

    .EXAMPLE
    Get-ChromeVersion

    .EXAMPLE
    Get-ChromeVersion -Channel 'dev'

    .EXAMPLE
    Get-ChromeVersion -UseHTTP
    #>
    [CmdletBinding()] 
    [OutputType([System.Version])]
    Param(
        [Parameter(Mandatory=$false, HelpMessage='The Chrome release channel')]
        [ValidateSet('dev', 'canary', 'beta', 'stable', IgnoreCase = $true)]
        [string]$Channel = 'stable',

        [Parameter(Mandatory=$false, HelpMessage='Use HTTP instead of HTTPS')]
        [switch]$UseHTTP
    )

    $protocol = 'https'

    if($UseHTTP) {
        $protocol = 'http'
    }

    $uri = ('{0}://omahaproxy.appspot.com/win?channel={1}' -f $protocol,$Channel.ToLower())
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
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

    .PARAMETER Path
    The folder path to save the extension to.

    .PARAMETER UseHTTP
    Use HTTP instead of HTTPS.

    .EXAMPLE
    Get-ChromeExtension -ExtensionID 'djflhoibgkdhkhhcedjiklpkjnoahfmg' -ExtensionTitle 'User-Agent Switcher for Chrome' -ExtensionVersion '1.0.43'

    .EXAMPLE
    Get-ChromeExtension -ExtensionID 'djflhoibgkdhkhhcedjiklpkjnoahfmg' -ExtensionTitle 'User-Agent Switcher for Chrome' -ExtensionVersion '1.0.43' -UseHTTP

    .EXAMPLE
    Get-ChromeExtension -ExtensionID 'djflhoibgkdhkhhcedjiklpkjnoahfmg' -ExtensionTitle 'User-Agent Switcher for Chrome' -ExtensionVersion '1.0.43' -ChromeVersion '49.0.2623.110'

    .EXAMPLE
    Get-ChromeExtension -ExtensionID 'djflhoibgkdhkhhcedjiklpkjnoahfmg' -ExtensionTitle 'User-Agent Switcher for Chrome' -ExtensionVersion '1.0.43' -ChromeVersion '49.0.2623.110' -Path 'C:\Chrome'
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The Chrome extension ID')]
        [string]$ExtensionID,

        [Parameter(Mandatory=$true, HelpMessage='The Chrome extension title')]
        [string]$ExtensionTitle,

        [Parameter(Mandatory=$true, HelpMessage='The Chrome extension version')]
        [string]$ExtensionVersion,

        [Parameter(Mandatory=$false, HelpMessage='The Chrome browser version')]
        [SYstem.Version]$ChromeVersion,

        [Parameter(Mandatory=$false, HelpMessage='The folder path to save the extension to')]
        [string]$Path,

        [Parameter(Mandatory=$false, HelpMessage='Use HTTP instead of HTTPS')]
        [switch]$UseHTTP
    )

    # force PSBoundParameters to exist during debugging https://technet.microsoft.com/en-us/library/dd347652.aspx 
    $parameters = $PSBoundParameters

    if (-not($parameters.ContainsKey('ChromeVersion'))) {
        if($UseHTTP) {
            $ChromeVersion = Get-ChromeVersion -UseHTTP
        } else {
            $ChromeVersion = Get-ChromeVersion 
        }
    }
    
    $extensionFolder = $env:USERPROFILE,'Downloads' -join '\'

    if ($parameters.ContainsKey('Path')) {
        $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        $extensionFolder = $Path
    }
    
    if (-not(Test-Path -Path $extensionFolder -PathType Container)) {
        throw "$extensionFolder does not exist"
    }

    $protocol = 'https'

    if($UseHTTP) {
        $protocol = 'http'
    }

    $uri = ('{0}://clients2.google.com/service/update2/crx?response=redirect&prodversion={1}&x=id%3D{2}%26uc' -f $protocol,$ChromeVersion,$ExtensionID)
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
        ContentType = 'application/x-chrome-extension' # 'application/octet-stream' also works
        UserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/$ChromeVersion Safari/537.36"; # Chrome 64-bit on Windows 10 64-bit
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

        $extensionFile = $extensionFolder,('{0}-{1}.crx' -f $ExtensionTitle,$ExtensionVersion) -join '\'     

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

    .PARAMETER Path
    The folder path to save the installer to.

    .PARAMETER UseHTTP
    Use HTTP instead of HTTPS.

    .EXAMPLE
    Get-ChromeInstaller -Architecture 32

    .EXAMPLE
    Get-ChromeInstaller -Architecture 64

    .EXAMPLE
    Get-ChromeInstaller -Architecture 64 -UseHTTP

    .EXAMPLE
    Get-ChromeInstaller -Architecture 64 -Channel 'beta'

    .EXAMPLE
    Get-ChromeInstaller -Architecture 64 -Channel 'beta' -ChromeVersion '49.0.2623.110'

    .EXAMPLE
    Get-ChromeInstaller -Architecture 64 -Channel 'beta' -ChromeVersion '49.0.2623.110' -Path 'C:\Chrome'
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The Chrome architecture')]
        [ValidateSet('64','32', IgnoreCase = $true)]
        [string]$Architecture,

        [Parameter(Mandatory=$false, HelpMessage='The Chrome browser version')]
        [System.Version]$ChromeVersion,

        [Parameter(Mandatory=$false, HelpMessage='The Chrome release channel')]
        [ValidateSet('dev', 'canary', 'beta', 'stable', IgnoreCase = $true)]
        [string]$Channel = 'stable',

        [Parameter(Mandatory=$false, HelpMessage='The folder path to save the installer to')]
        [string]$Path,

        [Parameter(Mandatory=$false, HelpMessage='Use HTTP instead of HTTPS')]
        [switch]$UseHTTP
    )

    # force PSBoundParameters to exist during debugging https://technet.microsoft.com/en-us/library/dd347652.aspx 
    $parameters = $PSBoundParameters

    if (-not($parameters.ContainsKey('ChromeVersion'))) {
        if ($UseHTTP) {
            $ChromeVersion = Get-ChromeVersion -Channel $Channel -UseHTTP
        } else {
            $ChromeVersion = Get-ChromeVersion -Channel $Channel
        }
    }
    
    $installerFolder = $env:USERPROFILE,'Downloads' -join '\'

    if ($parameters.ContainsKey('Path')) {
        $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        $installerFolder = $Path
    }
    
    if (-not(Test-Path -Path $installerFolder -PathType Container)) {
        throw "$installerFolder does not exist"
    }

    $installer = 'GoogleChromeStandaloneEnterprise.msi'

    if ($Architecture -ieq '64') {
        $installer = 'GoogleChromeStandaloneEnterprise64.msi'
    }

    $protocol = 'https'

    if($UseHTTP) {
        $protocol = 'http'
    }

    $uri = ('{0}://dl.google.com/edgedl/chrome/install/{1}' -f $protocol,$installer)
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
        UserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/$ChromeVersion Safari/537.36"; # Chrome 64-bit on Windows 10 64-bit
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

        $installerFile = $installerFolder,('{0}{1}_{2}.msi' -f 'GoogleChromeStandaloneEnterprise',$Architecture,$ChromeVersion) -join '\'

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

    .PARAMETER Path
    The folder path to save the template zip file to.

    .PARAMETER UseHTTP
    Use HTTP instead of HTTPS.

    .EXAMPLE
    Get-ChromeGroupPolicyTemplate

    .EXAMPLE
    Get-ChromeGroupPolicyTemplate -UseHTTP

    .EXAMPLE
    Get-ChromeGroupPolicyTemplate -ChromeVersion '49.0.2623.110'

    .EXAMPLE
    Get-ChromeGroupPolicyTemplate -ChromeVersion '49.0.2623.110' -Path 'C:\Chrome'
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$false, HelpMessage='The Chrome browser version')]
        [System.Version]$ChromeVersion,

        [Parameter(Mandatory=$false, HelpMessage='The folder path to save the template zip file to')]
        [string]$Path,

        [Parameter(Mandatory=$false, HelpMessage='Use HTTP instead of HTTPS')]
        [switch]$UseHTTP
    )

    # force PSBoundParameters to exist during debugging https://technet.microsoft.com/en-us/library/dd347652.aspx 
    $parameters = $PSBoundParameters

    if (-not($parameters.ContainsKey('ChromeVersion'))) {
        if ($UseHTTP) {
            $ChromeVersion = Get-ChromeVersion -UseHTTP
        } else {
            $ChromeVersion = Get-ChromeVersion
        }
    }
    
    $templateFolder = $env:USERPROFILE,'Downloads' -join '\'

    if ($parameters.ContainsKey('Path')) {
        $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        $templateFolder = $Path
    }
    
    if (-not(Test-Path -Path $templateFolder -PathType Container)) {
        throw "$templateFolder does not exist"
    }

    $protocol = 'https'

    if($UseHTTP) {
        $protocol = 'http'
    }

    $uri = '{0}://dl.google.com/dl/edgedl/chrome/policy/policy_templates.zip' -f $protocol
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
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

        $zipFile = $templateFolder,('{0}_{1}.zip' -f 'ChromeGroupPolicyTemplate',$ChromeVersion) -join '\'

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

    .PARAMETER Path
    The folder path to save the template file to.

    .PARAMETER UseHTTP
    Use HTTP instead of HTTPS.

    .EXAMPLE
    Get-GoogleUpdateGroupPolicyTemplate

    .EXAMPLE
    Get-GoogleUpdateGroupPolicyTemplate -UseHTTP

    .EXAMPLE
    Get-GoogleUpdateGroupPolicyTemplate -Path 'C:\Chrome'
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$false, HelpMessage='The folder path to save the template file to')]
        [string]$Path,

        [Parameter(Mandatory=$false, HelpMessage='Use HTTP instead of HTTPS')]
        [switch]$UseHTTP
    )

    # force PSBoundParameters to exist during debugging https://technet.microsoft.com/en-us/library/dd347652.aspx 
    $parameters = $PSBoundParameters

    $templateFolder = $env:USERPROFILE,'Downloads' -join '\'

    if ($parameters.ContainsKey('Path')) {
        $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        $templateFolder = $Path
    }
    
    if (-not(Test-Path -Path $templateFolder -PathType Container)) {
        throw "$templateFolder does not exist"
    }

    $protocol = 'https'

    if($UseHTTP) {
        $protocol = 'http'
    }

    $uri = '{0}://dl.google.com/update2/enterprise/googleupdateadmx.zip' -f $protocol
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
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

        $zipFile = $templateFolder,'GoogleUpdatePolicyTemplate.zip' -join '\'

        Set-Content -Path $zipFile -Value $bytes -Encoding Byte -Force -NoNewline
    } else {
        throw 'Request failed with status code $statusCode'
    }
}