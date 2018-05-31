#requires -version 4
Set-StrictMode -Version 4

Function Invoke-FileDownload() {
    [CmdletBinding()]
    [OutputType([void])]
    Param (
        [Parameter(Mandatory=$true, HelpMessage='URL of a file to download')]
        [ValidateNotNullOrEmpty()]
        [System.Uri]$Url,

        [Parameter(Mandatory=$true, HelpMessage='The path to download the file to')]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $uri = $Url

    $params = @{
        Uri = $uri;
        Method = 'GET';
        ContentType = 'text/plain';
    }

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($uri)

    if(([string]$proxyUri) -ne $uri) {
        $response = Invoke-WebRequest @params -Proxy $proxyUri -ProxyUseDefaultCredentials -UseBasicParsing
    } else {
        $response = Invoke-WebRequest @params -UseBasicParsing
    }

    $statusCode = $response.StatusCode 

    if ($statusCode -eq 200) {
        $bytes = $response.Content
    } else {
        throw "Request failed with status code $statusCode"
    }

    Set-Content -Path $Path -Value $bytes -Encoding Byte -Force

    if(-not(Test-Path -Path $Path)) {
        throw "failed to download to $Path"
    }
}

Function Test-AssemblyAvailable() {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '', Scope='Function')]
    [CmdletBinding()]
    [OutputType([bool])]
    Param (
        [Parameter(Mandatory=$true, HelpMessage='The assembly name')]
        [ValidateNotNullOrEmpty()]
        [string]$AssemblyName
    )
    
    $available = $false
    
    try {
        Add-Type -AssemblyName $AssemblyName -ErrorAction SilentlyContinue
        $available = $true
    } catch {
    }
    
    return $available
}

Function Expand-ZipFile() {
    [CmdletBinding()]
    [OutputType([void])]
    Param (
        [Parameter(Mandatory=$true, HelpMessage='The zip file path')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.zip$')]
        [System.IO.FileInfo]$File,

        [Parameter(Mandatory=$true, HelpMessage='The directory path to expand the zip file to')]
        [ValidateNotNullOrEmpty()]
        [System.IO.DirectoryInfo]$Directory
    )

    if(-not(Test-AssemblyAvailable -AssemblyName 'System.IO.Compression.FileSystem')) {
        throw 'Unable to expand zip file due to missing required assembly'
    }

    if(-not(Test-Path -Path $File -PathType Leaf)) {
        throw "$File did not exist"
    }

    if(Test-Path -Path $Directory -PathType Container) {
        Remove-Item -Path $Directory -Force -Recurse -ErrorAction Stop | Out-Null
    }

    New-Item -Path $Directory.FullName -ItemType Container -ErrorAction Stop | Out-Null

    [System.IO.Compression.ZipFile]::ExtractToDirectory($File.FullName, $Directory.FullName)
}

Function Invoke-XslTransform() {
    [CmdletBinding()]
    [OutputType([void])]
    Param (
        [Parameter(Mandatory=$true, HelpMessage='The XML file path')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.xml$')]
        [System.IO.FileInfo]$XmlPath,

        [Parameter(Mandatory=$true, HelpMessage='The XSL file path')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.xsl$')]
        [System.IO.FileInfo]$XslPath,

        [Parameter(Mandatory=$true, HelpMessage='The HTML file path')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.html$')]
        [System.IO.FileInfo]$HtmlPath

    )

    if(-not(Test-Path -Path $XmlPath -PathType Leaf)) {
        throw "$XmlPath not found"
    }

    if(-not(Test-Path -Path $XslPath -PathType Leaf)) {
        throw "$XslPath not found"
    }

    $xslt = New-Object System.Xml.Xsl.XslCompiledTransform
    $xslt.Load($XslPath)
    $xslt.Transform($XmlPath, $HtmlPath)

    if(-not(Test-Path -Path $HtmlPath)) {
       throw "transform of $XmlPath with $XslPath failed to created $htmlPath"
    }
}

Function Get-StigProfiles() {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Scope='Function')]
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[psobject]])]
    Param (
        [Parameter(Mandatory=$true, HelpMessage='The XML file path')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.xml$')]
        [System.IO.FileInfo]$XmlPath
    )
    $profiles = New-Object System.Collections.Generic.List[psobject]

    if(-not(Test-Path -Path $XmlPath -PathType Leaf)) {
        throw "$XmlPath not found"
    }

    $xml = [xml](Get-Content -Path $XmlPath)

    $xml.Benchmark.Profile | ForEach-Object {
        $rawCount = $_.select.Count

        $selectCount = ($_.Select | Where-Object { $_.selected -ieq "$true"}).Count

        $profile = [pscustomobject]@{
            'ID' = $_.id;
            'Title' = $_.title
            'RuleCount' = $rawCount
            'SelectedRuleCount' = $selectCount
        }

        $profiles.Add($profile)
    }

    return $profiles
}

Function Get-StigRules() {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Scope='Function')]
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[psobject]])]
    Param (
        [Parameter(Mandatory=$true, HelpMessage='The XML file path')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.xml$')]
        [System.IO.FileInfo]$XmlPath
    )

    $rules = New-Object System.Collections.Generic.List[psobject]

    if(-not(Test-Path -Path $XmlPath -PathType Leaf)) {
        throw "$XmlPath not found"
    }

    $xml = [xml](Get-Content -Path $XmlPath)

    $xml.Benchmark.Group | ForEach-Object {
        $description = $_.Rule.description

        $description = $description -replace "$([char]0x0A)",'' -replace "$([char]0x0D)",''
        $description = [System.Security.SecurityElement]::Escape($description)
        $vuln = Select-Xml -Content "<root>$description</root>" -XPath './/VulnDiscussion'

        $discussion = ''

        if($null -ne $vuln) {
            if($null -ne $vuln.Node.InnerText) {
                $discussion = $vuln.Node.InnerText
            }
        }

        $title = $_.Rule.title -replace "$([char]0x0A)",'' -replace "$([char]0x0D)",''

        $cci = @()

        # Outlook 2013 does not have ident property on most items, appears to only have it on 2
        if($_.Rule.PSObject.Properties.Name -contains 'ident') {
            $cci = @($_.Rule.ident | ForEach-Object { $_.'#text' }) -join ', '
        }

        $rule = [pscustomobject]@{
            'GroupID'=$_.id; # aka VulID
            'GroupTitle'=$_.title; # same as RuleVersion
            'RuleID'=$_.Rule.id; 
            'Severity'=$_.Rule.severity; 
            'RuleVersion' = $_.Rule.version; # aka STIG-ID, same as GroupTitle
            'Title'=$title; 
            'VulnerabilityDiscussion'= $discussion;
            'CheckContent' = $_.Rule.check.'check-content';
            'FixText' = $_.Rule.fixtext.'#text';
            'CCI' = $cci
        }
        
        $rules.Add($rule)
    }

    return $rules
}

Function Start-Browser() {
    [CmdletBinding()]
    [OutputType([void])]
    Param (
        [Parameter(Mandatory=$true, HelpMessage='The HTML file path')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.html$')]
        [string]$HtmlPath
    )

    $HtmlPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($HtmlPath)

    New-PSDrive -Name HKCR -PSProvider registry -Root HKEY_CLASSES_ROOT | Out-Null

    $browserPath = ((Get-ItemProperty 'HKCR:\http\shell\open\command').'(Default)').Split('"')[1]

    Start-Process -FilePath $browserPath -ArgumentList $HtmlPath -Verb Open
}

Function Get-Stig() {
    <#
    .SYNOPSIS
    Gets a STIG.

    .DESCRIPTION
    Gets a STIG.

    .PARAMETER Url
    The STIG zip file URL. Cannot be used with the File parameter.

    .PARAMETER File
    The STIG zip file path. Cannot be used with the Url parameter.

    .PARAMETER Open
    Optional switch that opens the transformed STIG HTML in the default browser.

    .PARAMETER Csv
    Optional switch that creates a CSV file with STIG rules in it

    .EXAMPLE
    Get-Stig -Url 'http://iasecontent.disa.mil/stigs/zip/U_Windows_10_V1R2_STIG.ZIP'

    .EXAMPLE
    Get-Stig -Url 'http://iasecontent.disa.mil/stigs/zip/U_Windows_10_V1R2_STIG.ZIP' -Open

    .EXAMPLE
    Get-Stig -File "$env:USERPROFILE\Downloads\U_Windows_10_V1R2_STIG.ZIP"

    .EXAMPLE
    Get-Stig -Url 'http://iasecontent.disa.mil/stigs/zip/U_Windows_10_V1R2_STIG.ZIP' -Csv

    .EXAMPLE
    Get-Stig -File "$env:USERPROFILE\Downloads\U_Windows_10_V1R2_STIG.ZIP" -Csv
    #>
    [CmdletBinding(DefaultParameterSetName='All')]
    [OutputType([void])]
    Param (
        [Parameter(Mandatory=$true, HelpMessage='The STIG zip file URL', ParameterSetName='URL')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.zip$')]
        [System.Uri]$Url,

        [Parameter(Mandatory=$true, HelpMessage='The STIG zip file path', ParameterSetName='File')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.zip$')]
        [System.IO.FileInfo]$File,

        [Parameter(Mandatory=$false, HelpMessage='Open the transformed STIG HTML in the default browser')]
        [switch]$Open,

        [Parameter(Mandatory=$false, HelpMessage='Create a CSV file with STIG rules in it')]
        [switch]$Csv
    )

    $rules = New-Object System.Collections.Generic.List[psobject]
    $profiles = New-Object System.Collections.Generic.List[psobject]

    if ($Url -ne $null) {
        $zip = $Url.Segments[-1]
        $fileName = $zip.Split('.')[0]

        $zipPath = "$env:USERPROFILE\Downloads\$zip"
        $extractPath = "$env:USERPROFILE\Downloads\$fileName"

        Invoke-FileDownload -Url $Url -Path $zipPath 
    }

    if ($File -ne $null) {
        $zip = $File.Name
        $fileName = $zip.Split('.')[0]

        $zipPath = $File.FullName
        $extractPath = "$env:USERPROFILE\Downloads\$fileName"
    }

    if(-not(Test-Path -Path $zipPath)) {
       throw "zip path did not exist $zipPath"
    }

    Expand-ZipFile -File $zipPath -Directory $extractPath

    # find path of the zip inside the zip since it changes based on the STIG
    # some zips are in the direct folder while others are in sub folders

    if(@(Get-ChildItem -Path "$extractPath\*.zip" -Recurse).Count -eq 0) {
        $extractPath2 = $extractPath
    } else {
        $t = @(Get-ChildItem -Path "$extractPath\*.zip" -Recurse)[0]
        $zip2 = $t.Name
        $file2 = $zip2.Split('.')[0]
        $zipPath2 = $t.FullName
        $extractPath2 = "{0}\$file2" -f $t.DirectoryName

        if(-not(Test-Path -Path $zipPath2)) {
            throw "missing $zipPath2"
        }

        Expand-ZipFile -File $zipPath2 -Directory $extractPath2

        if(-not(Test-Path -Path $zipPath2)) {
            throw "failed to extract, missing $zipPath2"
        }
    }

    # again, find the XML and XSL files no matter where they are since it changes based on the STIG
    # some files are in the direct folder while others are in sub folders

    $xmlPath = @(Get-ChildItem -Path "$extractPath2\*.xml" -Recurse | Where-Object {$_.Name -like '*STIG*'})[0].FullName 
    $xslPath = @(Get-ChildItem -Path "$extractPath2\*.xsl" -Recurse | Where-Object {$_.Name -like '*STIG*'})[0].FullName  
    $htmlPath =  $xmlPath.Replace('.xml','.html')

    Invoke-XslTransform -XmlPath $xmlPath -XslPath $xslPath -HtmlPath $htmlPath

    $xml = [xml](Get-Content -Path $xmlPath)

    Write-Verbose -Message ('Title: {0}' -f $xml.Benchmark.title)
    Write-Verbose -Message ('ID: {0}' -f $xml.Benchmark.id)
    Write-Verbose -Message ('Description: {0}' -f $xml.Benchmark.description)
    Write-Verbose -Message ($xml.Benchmark.'plain-text'.'#text')
    Write-Verbose -Message ('Version: {0}' -f $xml.Benchmark.version)

    $profiles = Get-StigProfiles -XmlPath $xmlPath

    if($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue) {
        $profiles | ForEach-Object { Write-Verbose -Message ('Profile ID: {0,-20} Title: {1,-35} Total: {2,-4} Selected: {3,-4}' -f $_.ID,$_.Title,$_.RuleCount,$_.SelectedRuleCount) }
    }

    $rules = Get-StigRules -XmlPath $xmlPath

    $lowCount = @($rules | Where-Object { $_.Severity -ieq 'low'}).Count
    $mediumCount = @($rules | Where-Object { $_.Severity -ieq 'medium'}).Count
    $highCount = @($rules | Where-Object { $_.Severity -ieq 'high'}).Count
    $totalCount = $rules.Count

    if($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue) {
        Write-Verbose -Message ('Total: {0,-3} Low: {1,-2} Medium: {2,-3} High: {3,-2}' -f $totalCount,$lowCount,$mediumCount,$highCount)
    }

    $addedCount = $lowCount + $mediumCount + $highCount

    if($addedCount -ne $totalCount) {
        Write-Warning -Message ('{0} did not match total of {1}' -f $addedCount,$totalCount)
    }

    if($Open) {
        Start-Browser $htmlPath 
    }

    if($Csv) {
        $csvPath = $htmlPath.Replace('.html', '.csv')
        $rules | Select-Object -Property GroupID,GroupTitle,RuleID,Severity,RuleVersion,Title,VulnerabilityDiscussion,CheckContent,FixText,CCI | Export-Csv -Path $csvPath -NoTypeInformation #Force columns to be in a certain order
    }
}