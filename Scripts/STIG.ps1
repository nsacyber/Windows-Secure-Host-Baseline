#requires -version 4
Set-StrictMode -Version 4

Function Invoke-FileDownload() {
    [CmdletBinding()]
    [OutputType([void])]
    Param (
        [Parameter(Position=0, Mandatory=$true, HelpMessage='URL of a file to download')]
        [ValidateNotNullOrEmpty()]
        [System.Uri]$Url,

        [Parameter(Position=1, Mandatory=$true, HelpMessage='The path to download the file to')]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $uri = $Url

    $params = @{
        Uri = $uri;
        Method = 'GET';
        ContentType = 'text/plain';
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
    } else {
        throw "Request failed with status code $statusCode"
    }

    Set-Content -Path $Path -Value $bytes -Encoding Byte -Force

    if(-not(Test-Path -Path $Path)) {
        throw "failed to download to $Path"
    }
}

Function Test-AssemblyAvailable() {
    [CmdletBinding()]
    [OutputType([bool])]
    Param (
        [Parameter(Position=0, Mandatory=$true, HelpMessage='The assembly name')]
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
        [Parameter(Position=0, Mandatory=$true, HelpMessage='The zip file path')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.zip$')]
        [System.IO.FileInfo]$File,

        [Parameter(Position=1, Mandatory=$true, HelpMessage='The directory path to expand the zip file to')]
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
        [Parameter(Position=0, Mandatory=$true, HelpMessage='The XML file path')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.xml$')]
        [System.IO.FileInfo]$XmlPath,

        [Parameter(Position=1, Mandatory=$true, HelpMessage='The XSL file path')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.xsl$')]
        [System.IO.FileInfo]$XslPath,

        [Parameter(Position=2, Mandatory=$true, HelpMessage='The HTML file path')]
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
    #>
    [CmdletBinding(DefaultParameterSetName='All')]
    [OutputType([void])]
    Param (
        [Parameter(Position=0, Mandatory=$true, HelpMessage='The STIG zip file URL', ParameterSetName='URL')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.zip$')]
        [System.Uri]$Url,

        [Parameter(Position=0,Mandatory=$true, HelpMessage='The STIG zip file path', ParameterSetName='File')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.*\.zip$')]
        [System.IO.FileInfo]$File,

        [Parameter(Position=1, Mandatory=$false, HelpMessage='Open the transformed STIG HTML in the default browser')]
        [switch]$Open,

        [Parameter(Position=2, Mandatory=$false, HelpMessage='Create a CSV file with STIG rules in it')]
        [switch]$Csv
    )

    $rules = New-Object System.Collections.Generic.List[psobject]

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

    $xmlPath = @(Get-ChildItem -Path "$extractPath2\*.xml" -Recurse)[0].FullName 
    $xslPath = @(Get-ChildItem -Path "$extractPath2\*.xsl" -Recurse)[0].FullName  
    $htmlPath =  (@(Get-ChildItem -Path "$extractPath2\*.xml" -Recurse)[0].FullName).Replace('.xml','.html')

    Invoke-XslTransform -XmlPath $xmlPath -XslPath $xslPath -HtmlPath $htmlPath

    $xml = [xml](Get-Content -Path $xmlPath)

    Write-Host $xml.Benchmark.title

    $xml.Benchmark.Profile | ForEach {
        $rawCount = $_.select.Count

        $selectCount = ($_.Select | Where-Object { $_.selected -ieq "$true"}).Count

        $result = 'Profile ID: {0,-20} Title: {1,-35} Total: {2,-4} Selected: {3,-4}' -f $_.id,$_.title,$rawCount,$selectCount
        Write-Host $result
    }

    $xml.Benchmark.Group | ForEach {
        $description = $_.Rule.description

        $description = $description -replace "$([char]0x0A)",'' -replace "$([char]0x0D)",''
        $vuln = Select-Xml -Content "<root>$description</root>" -XPath './/VulnDiscussion'

        $text = ''

        if($vuln -ne $null) {
            if($vuln.Node.InnerText -ne $null) {
                $text = $vuln.Node.InnerText
            }
        }

        #$props = @{}
        #$props.GroupID = $_.id
        #$props.RuleID = $_.Rule.id
        #$props.Severity = $_.Rule.severity
        $title = $_.Rule.title -replace "$([char]0x0A)",'' -replace "$([char]0x0D)",''
        #$props.Discussion = $text
        #$obj = New-Object -TypeName psobject -Prop $props

        $obj = [pscustomobject]@{'GroupID'=$_.id; 'GroupTitle'=$_.title; 'RuleID'=$_.Rule.id; 'Severity'=$_.Rule.severity; 'Title'=$title; 'Discussion'=$text}
        $rules.Add($obj)

        #Write-Host Group ID: $_.id Rule: $_.Rule.id Severity: $_.Rule.severity $_.Rule.title $text
    }

    $lowCount = @($xml.Benchmark.Group | Where-Object { $_.Rule.severity -ieq 'low'}).Count
    $mediumCount = @($xml.Benchmark.Group | Where-Object { $_.Rule.severity -ieq 'medium'}).Count
    $highCount = @($xml.Benchmark.Group | Where-Object { $_.Rule.severity -ieq 'high'}).Count
    $totalCount = $xml.Benchmark.Group.Count

    $result = 'Total: {0,-3} Low: {1,-2} Medium: {2,-3} High: {3,-2}' -f $totalCount,$lowCount,$mediumCount,$highCount
    Write-Host $result

    $addedCount = $lowCount + $mediumCount + $highCount

    if($addedCount -ne $totalCount) {
        Write-Warning -Message ('{0} did not match total of {1}' -f $addedCount,$totalCount)
    }

    if($Open) {
        New-PSDrive -Name HKCR -PSProvider registry -Root HKEY_CLASSES_ROOT | Out-Null
        $browserPath = ((Get-ItemProperty 'HKCR:\http\shell\open\command').'(Default)').Split('"')[1]
        Start-Process -FilePath $browserPath -ArgumentList $htmlPath -Verb Open
    }

    if($Csv) {
        $csvPath = $htmlPath.Replace('.html', '.csv')
        $rules | Select-Object -Property GroupID,GroupTitle,RuleID,Severity,Title,Discussion | Export-Csv -Path $csvPath -NoTypeInformation #Force columns to be in a certain order
    }
}