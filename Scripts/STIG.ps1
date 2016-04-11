#requires -version 4
Set-StrictMode -Version 4


Function Get-Stig() {
    <#
    .SYNOPSIS
    Gets a STIG.

    .DESCRIPTION
    Gets a STIG, either from online or the file system and transforms it to HTML. Optionally options HTML in browser. Optionally converts STIG rules to CSV file.

    .PARAMETER Url
    A path to the STIG zip file on the internet.

    .PARAMETER File
    A path to the STIG zip file on the local system.

    .PARAMETER Open
    Open the transformed STIG HTML in the default browser.

    .PARAMETER Csv
    Create a CSV file with STIG rules in it.

    .EXAMPLE
    Get-Stig -Url 'http://iasecontent.disa.mil/stigs/zip/U_Windows_10_V1R2_STIG.ZIP'

    .EXAMPLE
    Get-Stig -File '$env:USERPROFILE\Desktop\U_Windows_10_V1R2_STIG.ZIP'

    .EXAMPLE
    Get-Stig -Url 'http://iasecontent.disa.mil/stigs/zip/U_Windows_10_V1R2_STIG.ZIP' -Open

    .EXAMPLE
    Get-Stig -Url 'http://iasecontent.disa.mil/stigs/zip/U_Windows_10_V1R2_STIG.ZIP' -Csv
    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    [OutputType([void])]
    Param (
        [Parameter(Position=0,Mandatory=$true,HelpMessage="The STIG zip file URL",ParameterSetName="URL")]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^.*\.zip$")]
        [System.Uri]$Url,

        [Parameter(Position=0,Mandatory=$true,HelpMessage="The STIG zip file",ParameterSetName="File")]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^.*\.zip$")]
        [System.IO.FileInfo]$File,

        [Parameter(Position=1,Mandatory=$false,HelpMessage="Open the transformed STIG HTML in the default browser")]
        [switch]$Open,

        [Parameter(Position=2,Mandatory=$false,HelpMessage="Create a CSV file with STIG rules in it")]
        [switch]$Csv
    )

    $rules = New-Object System.Collections.Generic.List[psobject]

    if ($Url -ne $null) {
        $zip = $Url.Segments[-1]
        $fileName = $zip.Split(".")[0]

        $zipPath = "$env:USERPROFILE\Downloads\$zip"
        $extractPath = "$env:USERPROFILE\Downloads\$fileName"

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
            throw 'Request failed with status code $statusCode'
        }

        Set-Content -Path $zipPath -Value $bytes -Encoding Byte -Force

        if(-not(Test-Path -Path $zipPath)) {
            throw "failed to download to $zipPath"
        }
    }

    if ($File -ne $null) {
        $zip = $File.Name
        $fileName = $zip.Split(".")[0]

        $zipPath = $File.FullName
        $extractPath = "$env:USERPROFILE\Downloads\$fileName"

        if(-not(Test-Path -Path $zipPath)) {
           throw "zip path did not exist $zipPath"
        }
    }

    if(Test-Path -Path $extractPath) {
        Remove-Item -Path $extractPath -Force -Recurse -ErrorAction Stop | Out-Null
    }

    New-Item -Path $extractPath -ItemType Container -ErrorAction Stop | Out-Null

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractPath)

    # find path of the zip inside the zip since it changes based on the STIG
    # some zips are in the direct folder while others are in sub folders

    if(@(Get-ChildItem -Path "$extractPath\*.zip" -Recurse).Count -eq 0) {
        $extractPath2 = $extractPath
    } else {
        $t = @(Get-ChildItem -Path "$extractPath\*.zip" -Recurse)[0]
        $zip2 = $t.Name
        $file2 = $zip2.Split(".")[0]
        $zipPath2 = $t.FullName
        $extractPath2 = "{0}\$file2" -f $t.DirectoryName

        if(-not(Test-Path -Path $zipPath2)) {
            throw "missing $zipPath2"
        }

        if(Test-Path -Path $extractPath2) {
            Remove-Item -Path $extractPath2 -Force -Recurse -ErrorAction Stop | Out-Null
        }

        New-Item -Path $extractPath2 -ItemType Container -ErrorAction Stop | Out-Null

        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath2, $extractPath2)

        if(-not(Test-Path -Path $zipPath2)) {
            throw "failed to extract, missing $zipPath2"
        }
    }

    # again, find the XML and XSL files no matter where they are since it changes based on the STIG
    # some files are in the direct folder while others are in sub folders

    $xmlPath = @(Get-ChildItem -Path "$extractPath2\*.xml" -Recurse)[0].FullName 
    $xslPath = @(Get-ChildItem -Path "$extractPath2\*.xsl" -Recurse)[0].FullName  
    $htmlPath =  (@(Get-ChildItem -Path "$extractPath2\*.xml" -Recurse)[0].FullName).Replace(".xml",".html")

    if(-not(Test-Path -Path $xmlPath)) {
        throw "missing $xmlPath"
    }

    if(-not(Test-Path -Path $xslPath)) {
        throw "missing $xslPath"
    }

    $xslt = New-Object System.Xml.Xsl.XslCompiledTransform
    $xslt.Load($xslPath)
    $xslt.Transform($xmlPath, $htmlPath)

    if(-not(Test-Path -Path $htmlPath)) {
        throw "failed transform $htmlPath"
    }

    $xml = [xml](Get-Content -Path $xmlPath)

    Write-Verbose -Message ($xml.Benchmark.title)

    $xml.Benchmark.Profile | ForEach-Object {
        $rawCount = $_.select.Count

        $selectCount = ($_.Select | Where-Object { $_.selected -ieq "$true"}).Count

        $result = "Profile ID: {0,-20} Title: {1,-35} Total: {2,-4} Selected: {3,-4}" -f $_.id,$_.title,$rawCount,$selectCount
        Write-Verbose -Message $result
    }

    $xml.Benchmark.Group | ForEach-Object {
        $description = $_.Rule.description

        $description = $description -replace "$([char]0x0A)","" -replace "$([char]0x0D)",""
        $vuln = Select-Xml -Content "<root>$description</root>" -XPath ".//VulnDiscussion"

        $text = ""

        if($null -ne $vuln) {
            if($null -ne $vuln.Node.InnerText) {
                $text = $vuln.Node.InnerText
            }
        }

        #$props = @{}
        #$props.GroupID = $_.id
        #$props.RuleID = $_.Rule.id
        #$props.Severity = $_.Rule.severity
        $title = $_.Rule.title -replace "$([char]0x0A)","" -replace "$([char]0x0D)",""
        #$props.Discussion = $text
        #$obj = New-Object -TypeName psobject -Prop $props

        $obj = [pscustomobject]@{"GroupID"=$_.id; "GroupTitle"=$_.title; "RuleID"=$_.Rule.id; "Severity"=$_.Rule.severity; "Title"=$title; "Discussion"=$text}
        $rules.Add($obj)

        #Write-Host Group ID: $_.id Rule: $_.Rule.id Severity: $_.Rule.severity $_.Rule.title $text
    }

    $lowCount = @($xml.Benchmark.Group | Where-Object { $_.Rule.severity -ieq "low"}).Count
    $mediumCount = @($xml.Benchmark.Group | Where-Object { $_.Rule.severity -ieq "medium"}).Count
    $highCount = @($xml.Benchmark.Group | Where-Object { $_.Rule.severity -ieq "high"}).Count
    $totalCount = $xml.Benchmark.Group.Count

    $result = "Total: {0,-3} Low: {1,-2} Medium: {2,-3} High: {3,-2}" -f $totalCount,$lowCount,$mediumCount,$highCount
    Write-Verbose -Message $result

    $addedCount = $lowCount + $mediumCount + $highCount

    if($addedCount -ne $totalCount) {
        Write-Warning -Message ("{0} did not match total of {1}" -f $addedCount,$totalCount)
    }

    if($Open) {
        New-PSDrive -Name HKCR -PSProvider registry -Root HKEY_CLASSES_ROOT | Out-Null
        $browserPath = ((Get-ItemProperty "HKCR:\http\shell\open\command")."(Default)").Split('"')[1]
        Start-Process -FilePath $browserPath -ArgumentList $htmlPath -Verb Open
    }

    if($Csv) {
        $csvPath = $htmlPath.Replace(".html", ".csv")
        $rules | Select-Object -Property GroupID,GroupTitle,RuleID,Severity,Title,Discussion | Export-Csv -Path $csvPath -NoTypeInformation #Force columns to be in a certain order
    }
}


# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/July2015/U_Windows_Firewall_V1R3_STIG.zip" -Open #Total: 30  Low: 15 Medium: 12  High: 3
 
# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/U_Windows_10_V1R2_STIG.ZIP" -Open # Total: 272 Low: 16 Medium: 228 High: 28
# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/U_Windows_10_V1R1_STIG.zip" -Open # Total: 272 Low: 16 Medium: 228 High: 28
# Get-Stig -File "$env:USERPROFILE\Desktop\U_Windows_10_V1R0-2_FDraftSTIG.zip" -Open # Total: 272 Low: 17 Medium: 229 High: 26
# Get-Stig -URL "http://iasecontent.disa.mil/stigs/zip/U_Windows_10_V1R0-1_Draft_STIG.zip" -Open #Total: 285 Low: 29 Medium: 227 High: 28

# Get-Stig -URL "http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Windows_8_and_8-1_V1R11_STIG.zip" # Total: 427 Low: 79 Medium: 309 High: 39
# Get-Stig -URL "http://iasecontent.disa.mil/stigs/zip/July2015/U_Windows_8_and_8-1_V1R10_STIG.zip" # Total: 430 Low: 82 Medium: 310 High: 38
# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/Apr2015/U_Windows_8_and_8-1_V1R9_STIG.zip" # Total: 429 Low: 81 Medium: 310 High: 38

# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Windows_7_V1R21_STIG.zip" # Total: 331 Low: 67 Medium: 230 High: 34
# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/Apr2015/U_Windows_7_V1R19_STIG.zip" # Total: 333 Low: 68 Medium: 232 High: 33
# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Windows_7_V1R21_STIG.zip" # Total: 331 Low: 67 Medium: 230 High: 34

# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/Apr2015/U_Windows_Vista_V6R36_STIG.zip" # Total: 261 Low: 56 Medium: 173 High: 32

# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/Jan2016/U_Microsoft_IE11_V1R7_STIG.zip" # Total: 137 Low: 2  Medium: 135 High: 0
# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/July2015/U_Microsoft_IE11_V1R6_STIG.zip" # Total: 153 Low: 3  Medium: 150 High: 0
# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/Apr2015/U_Microsoft_IE11_V1R5_STIG.zip" # Total: 153 Low: 3  Medium: 150 High: 0

# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/Jan2016/U_Microsoft_IE10_V1R12_STIG.zip" # Total: 147 Low: 3  Medium: 143 High: 1
# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Microsoft_IE10_V1R11_STIG.zip" # Total: 146 Low: 3  Medium: 143 High: 0
# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/Apr2015/U_Microsoft_IE10_V1R9_STIG.zip" # Total: 146 Low: 3  Medium: 143 High: 0

# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/Apr2015/U_Microsoft_IE9_V1R13_STIG.zip" # Total: 134 Low: 3  Medium: 131 High: 0

# Get-STIG -Url "http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Google_Chrome_Browser_V1R3_STIG.zip" # Total: 37  Low: 2  Medium: 33  High: 2
# Get-Stig -Url "http://iase.disa.mil/stigs/Documents/u_google_chrome_browser_v1r2_stig.zip" # Total: 37  Low: 2  Medium: 33  High: 2

# Get-Stig -Url "https://powhatan.iiie.disa.mil/stigs/downloads/zip/fouo_hbss_hip_8_v4r11_stig.zip" -Open

# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/Apr2015/U_McAfee_VirusScan88_Local_Client_V5R5_STIG.zip" -Open
# Get-Stig -Url "http://iasecontent.disa.mil/stigs/zip/Apr2015/U_McAfee_VirusScan88_Managed_Client_V5R6_STIG.zip" -Open

# Get-Stig -URL "http://iasecontent.disa.mil/stigs/zip/July2015/U_MicrosoftOutlook2007_V4R14_STIG.zip" -Open
# Get-Stig -URL "http://iase.disa.mil/stigs/Documents/U_MicrosoftOutlook2010_V1R10_STIG.zip" -Open
# Get-Stig -URL "http://iasecontent.disa.mil/stigs/zip/July2015/U_MicrosoftOutlook2013_V1R4_STIG.zip" -Open


# Get-Stig -URL "http://iasecontent.disa.mil/stigs/zip/July2015/U_Exchange_2010_Mailbox_V1R6_STIG.zip" -Open
# Get-STIG -URL "http://iasecontent.disa.mil/stigs/zip/July2015/U_Exchange_2010_Hub_V1R9_STIG.zip" -Open
# Get-STIG -URL "http://iasecontent.disa.mil/stigs/zip/July2015/U_Exchange_2010_Edge_V1R9_STIG.zip" -Open
# Get-STIG -URL "http://iasecontent.disa.mil/stigs/zip/July2015/U_Exchange_2010_Client_Access_V1R7_STIG.zip" -Open
