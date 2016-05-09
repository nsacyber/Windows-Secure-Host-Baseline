#requires -Version 3
Set-StrictMode -Version 3

$script:GitHubBaseUri = 'https://api.github.com'

Function Get-GitHubRateLimit() {
    <#
    .SYNOPSIS
    Gets the GitHub rate limit information for API access.

    .DESCRIPTION
    Gets the GitHub rate limit information for API access for search or core APIs.

    .PARAMETER Api
    The type of API to get the rate limit for. Defaults to 'core'.

    .EXAMPLE
    Get-GitHubRateLimit

    .EXAMPLE
    Get-GitHubRateLimit -API 'core'

    .EXAMPLE
    Get-GitHubRateLimit -API 'search'
    #>
    [CmdletBinding()] 
    [OutputType([string])]
    Param(
        [Parameter(Position=0, Mandatory=$false, HelpMessage='The raw markdown')]
        [ValidateSet('Core','Search', IgnoreCase=$true)]
        [string]$API = 'core'
    )

    $API = $API.ToLower()

    $uri = ($script:GitHubBaseUri,'rate_limit' -join '/')

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
        $rate = $response.Content | ConvertFrom-Json

        $unixEpochUtc = New-Object System.DateTime -Args @(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
        $resetSecondUtc = $rate.resources.$($API).reset
        $limitExpireDate = $unixEpochUtc.AddSeconds($resetSecondUtc).ToLocalTime()

        $limit = [pscustomobject]@{
            Limit = $rate.resources.$($API).limit;
            Remaining = $rate.resources.$($API).remaining;
            ResetTime = $limitExpireDate;
        }

        return $limit
    } else {
        throw 'Request failed with status code $statusCode'
    }
}

Function Get-GitHubMarkdownStylesheet() {
    <#
    .SYNOPSIS
    Gets a stylesheet used to apply styles to GitHub markdown that has been converted to HTML.

    .DESCRIPTION
    Gets a stylesheet from a GitHub user repository used to apply styles to GitHub markdown that has been converted to HTML.

    .EXAMPLE
    Get-GitHubMarkdownStylesheet
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param()

    $uri = 'https://raw.githubusercontent.com/sindresorhus/github-markdown-css/gh-pages/github-markdown.css'

    $params = @{
        Uri = $uri;
        Method = 'Get';
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
        $returnedStylesheet = $response.Content

        return ($returnedStylesheet | Out-String)
    } else {
        throw 'Request failed with status code $statusCode'
    }
}

Function Get-GitHubHtmlTemplate() {
    <#
    .SYNOPSIS
    Gets a custom HTML template used for GitHub markdown that has been converted to HTML.

    .DESCRIPTION
    Gets a custom HTML template used for GitHub markdown that has been converted to HTML.

    .EXAMPLE
     Get-GitHubHtmlTemplate
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param()
        $htmlTemplate = @"
<!DOCTYPE HTML>
<html lang="en-US">
    <head>
        <meta charset="UTF-8">
        <title>{0}</title>
        <style>
            {1}
        </style>
    </head>
    <body class='markdown-body'>
        {2}
    </body>
</html>
"@

    $stylesheet = Get-GitHubMarkdownStylesheet

    # minimize line breaks and spaces, have to use double quotes to replace the line feed character 
    $stylesheet = ($stylesheet -replace "`n",' ') -replace '   ',' ' -replace '  ', ' '

    # replace main markdown-body style
    $orignalBodyStyle = '.markdown-body { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; color: #333; font-family: "Helvetica Neue", Helvetica, "Segoe UI", Arial, freesans, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol"; font-size: 16px; line-height: 1.6; word-wrap: break-word; }'
    $customBodyStyle =  '.markdown-body { padding: 45px; word-wrap: break-word; background-color: #fff; border: 1px solid #ddd; border-bottom-right-radius: 3px; border-bottom-left-radius: 3px; font-family: "Helvetica Neue", Helvetica, "Segoe UI", Arial, freesans, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol"; font-size: 16px; line-height: 1.6; display: block; box-sizing: border-box; color: #333; background-color: #fff; }'

    $stylesheet = $stylesheet.Replace($orignalBodyStyle, $customBodyStyle)
    
    if($stylesheet.Length -ne 12419) {
        throw 'GitHub stylesheet changed so style replacement was not successful'
    }

    # carry forward two substitutions
    $template =  $htmlTemplate -f '{0}',$stylesheet,'{1}'
    return $template
}

Function Get-GitHubHtmlFromRawMarkdown() {
    <#
    .SYNOPSIS
    Converts raw GitHub markdown to HTML.

    .DESCRIPTION
    Converts raw GitHub markdown to HTML using the GitHub markdown API.

    .PARAMETER Markdown
    The raw GitHub markdown.

    .PARAMETER Title
    The title to use for the HTML page.

    .PARAMETER Template
    The HTML template to use.

    .EXAMPLE
    Get-GitHubHtmlFromRawMarkdown -Markdown "#Markdown`ntesting **123**" -Title 'Page Title' -Template '<html><head><title>{0}</title></head><body>{1}</body></html>'
    #>
    [CmdletBinding()] 
    [OutputType([string])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='The raw markdown')]
        [AllowEmptyString()]
        [string]$Markdown,

        [Parameter(Position=1, Mandatory=$true, HelpMessage='The title for the HTML page')]
        [AllowEmptyString()]
        [string]$Title,

        [Parameter(Position=2, Mandatory=$true, HelpMessage='The template for the HTML page')]
        [AllowEmptyString()]
        [string]$Template
    )
    Begin {   
        # escape all the left and right brackets, then replace the escaped format specifier with an unescaped version
        $htmlTemplate = $Template.Replace('{','{{').Replace('}','}}').Replace('{{0}}','{0}').Replace('{{1}}','{1}')
    }
    Process {
        $requestBody = $markdown | Out-String

        $html = ''

        $uri = ($script:GitHubBaseUri,'markdown','raw' -join '/')

        $params = @{
            Uri = $uri;
            Method = 'POST';
            ContentType = 'text/plain';
            Body =  $requestBody;
        }

        $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($uri)

        if(([string]$proxyUri) -ne $uri) {
            $response = Invoke-WebRequest @params -Proxy $proxyUri -ProxyUseDefaultCredentials 
        } else {
            $response = Invoke-WebRequest @params 
        }

        $statusCode = $response.StatusCode 

        if ($statusCode -eq 200) {
            $returnedHtml = $response.Content
      
            $html = $htmlTemplate -f $Title,$returnedHtml # this throws an error 'input string was not in a correct format' if brackets are not escaped in the template
        } else {
            throw 'Request failed with status code $statusCode'
        }

        return $html
    }
}

Function Convert-MarkdownToHtml() {
    <#
    .SYNOPSIS
    Converts raw GitHub markdown to HTML.

    .DESCRIPTION
    Converts raw GitHub markdown to HTML using the GitHub markdown API.

    .PARAMETER Files
    Markdown files to convert to HTML.

    .EXAMPLE
    Convert-MarkdownToHtml -Files '.\Secure-Host-Baseline\Hardware\README.md'

    .EXAMPLE
    Convert-MarkdownToHtml -Files @(Get-ChildItem -Path '.\Secure-Host-Baseline\' -Recurse -Include '*.md')
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='The path of a folder containing markdown files')]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo[]]$Files
    )
    Begin {
        $limit = Get-GitHubRateLimit
        $remaining =[UInt32] $limit.Remaining
    }
    Process {
        $markdownFiles = [System.IO.FileInfo[]]@($Files | ForEach-Object { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_) })
        $markdownFiles = [System.IO.FileInfo[]]@($markdownFiles | Where-Object {$_.Length -gt 0 })

        if($markdownFiles.Count -gt $remaining) {
            throw '$($markdownFiles.Count) files to convert but only $remaining conversions allowed until limit is reached'
        }

        if($markdownFiles.Count -gt 0) {
            $htmlTemplate = Get-GitHubHtmlTemplate # only want to do this once say it calls out to the internet and the content won't change often

            $markdownFiles | ForEach-Object {
                $markdownFile = $_.FullName

                if(Test-Path -Path $markdownFile -PathType Leaf) {
                    $htmlFile = $markdownFile.Replace('.md','.html')
                    $markdown = Get-Content -Path $markdownFile -Raw
                    $html = Get-GitHubHtmlFromRawMarkdown -Markdown $markdown -Title $_.BaseName -Template $htmlTemplate
                    $html = $html.Replace('.md','.html') # update links to point to the converted HTML page
                    Set-Content -Path $htmlFile -Value $html -Force
                }
            }
        }
    }   
}

Function Convert-CsvToMarkdownTable() {
    <#
    .SYNOPSIS
    Converts a CSV file to markdown table syntax.

    .DESCRIPTION
    Converts a CSV file to markdown table syntax.

    .PARAMETER Path
    Path to the CSV file.

    .EXAMPLE
    Convert-CsvToMarkdownTable -Path '.\Secure-Host-Baseline\Hardware\Template.csv'
    #>
    [CmdletBinding()] 
    [OutputType([string])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='Path to CSV file')]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]$Path
    )

    $table = ''

    $rows = [object[]]@(Get-Content -Path $Path | ConvertFrom-Csv)

    if($rows.Count -ge 1) {

        $columnHeaderRow = ($rows[0].psobject.Properties | Select-Object -ExpandProperty Name) -join ' | '
        $columnHeaderRow = '| {0} |' -f $columnHeaderRow

        $table = $table,$columnHeaderRow -join [System.Environment]::NewLine

        $columnCount = @($rows[0] | Get-Member -MemberType NoteProperty).Count

        $seperatorRow = ('| --- ' * $columnCount)
        $seperatorRow = '{0}|' -f $seperatorRow 

        $table = $table,$seperatorRow -join [System.Environment]::NewLine

        $rows | ForEach-Object {
            $valueRow = ''

            # $_| Get-Member -MemberType NoteProperty changes the order of the properties (sorts alphabetical) so use Select instead
            $values = ($_.psobject.Properties | Select-Object -ExpandProperty Value) -join ' | '
            $valueRow = '| {0} |' -f $values

            $table = $table,$valueRow -join [System.Environment]::NewLine
        }
    }

    return $table
}

<#
Function Convert-MarkdownTableToCsv() {
    <#
    .SYNOPSIS
    Converts a markdown table to a CSV file.

    .DESCRIPTION
    Converts a markdown table to a CSV file. 

    .PARAMETER Path
    Path to the CSV file.

    .EXAMPLE
    Convert-MarkdownTableToCsv -Path '.\Secure-Host-Baseline\Hardware\Template.csv'
    
    [CmdletBinding()] 
    [OutputType([string])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='Path to CSV file')]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]$Path
    )

}
#>
Function New-GitConfiguration() {
    <#
    .SYNOPSIS
    Creates text for a new .gitconfig file.

    .DESCRIPTION
    Creates text for a new .gitconfig file.

    .PARAMETER Username
    GitHub account username.

    .PARAMETER Email
    GitHub account email address.

    .PARAMETER Public
    Optional switch that when specified prevents converting the email address to a GitHub private email address so the real email address will be exposed in commit logs.

    .PARAMETER DiffMergeTool
    Specifies the diff/merge tool to use.

    .PARAMETER Proxy
    Specifies the proxy URL and port to use.

    .EXAMPLE
    New-GitConfiguration -Username iadgovuser1 -Email iadgovuser1@iad.gov

    .EXAMPLE
    New-GitConfiguration -Username iadgovuser1 -Email iadgovuser1@iad.gov -DiffMergeTool 'SourceGear'

    .EXAMPLE
    New-GitConfiguration -Username iadgovuser1 -Email iadgovuser1@iad.gov -DiffMergeTool 'Perforce' -Public

    .EXAMPLE
    New-GitConfiguration -Username iadgovuser1 -Email iadgovuser1@iad.gov -DiffMergeTool 'SourceGear' -Proxy '123.456.789.0:80'

    .EXAMPLE
    New-GitConfiguration -Username iadgovuser1 -Email iadgovuser1@iad.gov -DiffMergeTool 'SourceGear' -Proxy '123.456.789.0:80' -CredentialManager 'manager'

    .EXAMPLE
    New-GitConfiguration -Username iadgovuser1 -Email iadgovuser1@iad.gov -DiffMergeTool 'SourceGear' -Proxy '123.456.789.0:80' -CredentialManager 'manager' -SigningKey 'AAABB1234'
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Scope='Function')] # this function does not change system state
    [CmdletBinding()] 
    [OutputType([string])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='GitHub account username')]
        [ValidateNotNullOrEmpty()]
        [string]$Username,

        [Parameter(Position=1, Mandatory=$true, HelpMessage='GitHub account email address')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_.Contains('@')})]
        [ValidateLength(3,254)]
        [string]$Email,

        [Parameter(Position=2, Mandatory=$false, HelpMessage='Prevents converting the email address to a GitHub private email address so the real email address will be exposed in commit logs')]
        [switch]$Public,

        [Parameter(Position=3, Mandatory=$false, HelpMessage='Specifies the diff/merge tool to use')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('SourceGear','Perforce',IgnoreCase=$true)]
        [string]$DiffMergeTool,

        [Parameter(Position=4, Mandatory=$true, HelpMessage='Proxy URL and port')]
        [ValidateNotNullOrEmpty()]
        [string]$Proxy,

        [Parameter(Position=5, Mandatory=$false, HelpMessage='Specifies the credential manager to use')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('manager','winstore','wincred', IgnoreCase=$true)]
        [string]$CredentialManager,

        [Parameter(Position=6, Mandatory=$false, HelpMessage='First 8 numbers/letters of your signing key')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[A-Za-z0-9]{8}$')]
        [string]$SigningKey
    )
    Begin {
    $userTemplate = @"
[user]
`tname = {0}
`temail = {1}
`tuseconfigonly = true
"@

    $signTemplate = @"
`tsigning = {0}
"@

    $proxyTemplate = @"
[http]
`tproxy = {0}
"@

    # two factor auth uses HTTP, not SSH, so disable SSH prompts
    $coreTemplate = @"
[core]
`taskpass = 
"@

    $diffTemplate = @"
[diff]
`ttool = {0}
`tguitool = {0}
"@

    # path does not appear to work so make cmd have the full path of the executable
    $diffToolTemplate = @"
[difftool "{0}"]
`tpath = \"{1}\"
`tcmd = \"{1}/{2}\" {3}
[difftool]
`tprompt = false
"@

    # path does not appear to work so make cmd have the full path of the executable
    $mergeToolTemplate = @"
[mergetool "{0}"]
`tpath = \"{1}\"
`tcmd = \"{1}/{2}\" {3}
`ttrustExitCode = {4}
[mergetool]
`tprompt = false
"@

    $credManTemplate = @"
[credential]
`thelper = {0}
"@

    }
    Process {
        # force PSBoundParameters to existing during debugging https://technet.microsoft.com/en-us/library/dd347652.aspx 
        $params = $PSBoundParameters

        $config = ''

        $userSection = ''

        if($Public) {
            $userSection = $userTemplate -f $Username,$Email
        } else {
            $user = @($Email -split '@')[0]
            $privateEmail = '{0}@{1}' -f $user,'users.noreply.github.com'

            $userSection = $userTemplate -f $Username,$privateEmail
        }

        if($params.ContainsKey('SigningKey')) {
            $signSection = $signTemplate -f $SigningKey
            $userSection = $userSection,$signSection -join [System.Environment]::NewLine
        }

        $coreSection = $coreTemplate

        $config = $userSection,$coreSection -join [System.Environment]::NewLine

        if ($params.ContainsKey('Proxy')) {
            $proxySection = $proxyTemplate -f $Proxy
            $config = $config,$proxySection -join [System.Environment]::NewLine
        }

        if ($params.ContainsKey('DiffMergeTool')) {
            $toolName = $DiffMergeTool.ToLower()

            if($toolName -ieq 'SourceGear') {
                $executable = 'sgdm.exe'
                $diffArgs = '--nosplash \"$LOCAL\" \"$REMOTE\"'
                $mergeArgs = '--nosplash --merge --result=\"$MERGED\" \"$LOCAL\" \"$BASE\" \"$REMOTE\"'
                $trustExitCode = 'true'
            } elseif($DiffMergeTool -ieq 'Perforce') {
                $executable = 'p4merge.exe'
                $diffArgs = '\"$LOCAL\" \"$REMOTE\"'
                $mergeArgs = '\"$BASE\" \"$LOCAL\" \"$REMOTE\" \"$MERGED\"'
                $trustExitCode = 'false'
            }

            $files = [System.IO.FileInfo[]]@(Get-ChildItem @($env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramW6432) -Filter $executable -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.PsIsContainer -eq $false } | Get-Unique)

            if($files.Count -eq 0) {
                throw '$executable not found in Program Files'
            }

            $file = $files[0]
            $filePath = $file.Directory.FullName.Replace('\','/')

            $diffSection = $diffTemplate -f $toolName
            $diffToolSection = $diffToolTemplate -f $toolName,$filePath,$file.Name,$diffArgs
            $mergeToolSection = $mergeToolTemplate -f $toolName,$filePath,$file.Name,$mergeArgs,$trustExitCode
            $diffMergeSection = $diffSection,$diffToolSection,$mergeToolSection -join [System.Environment]::NewLine

            $config = $config,$diffMergeSection -join [System.Environment]::NewLine
        }

        if($params.ContainsKey('CredentialManager')) {
            $credManSection = $credManTemplate -f $CredentialManager.ToLower()
            $config = $config,$credManSection -join [System.Environment]::NewLine
        }

        $config = $config -replace [System.Environment]::NewLine,"`n" # "real" generated gitconfig uses line feeds only
        
        return ($config,"`n" -join '') # a "real" generated .gitconfig ends with line feed only
    }
}

Function New-GitConfigurationFile() {
    <#
    .SYNOPSIS
    Creates a new .gitconfig file.

    .DESCRIPTION
    Creates a new .gitconfig file. Your existing .gitconfig file will be overwritten.

    .PARAMETER Username
    GitHub account username.

    .PARAMETER Email
    GitHub account email address.

    .PARAMETER Public
    Optional switch that when specified prevents converting the email address to a GitHub private email address so the real email address will be exposed in commit logs.

    .PARAMETER DiffMergeTool
    Specifies the diff/merge tool to use.

    .PARAMETER Proxy
    Specifies the proxy URL and port to use.

    .EXAMPLE
    New-GitConfigurationFile -Username iadgovuser1 -Email iadgovuser1@iad.gov

    .EXAMPLE
    New-GitConfigurationFile -Username iadgovuser1 -Email iadgovuser1@iad.gov -DiffMergeTool 'SourceGear'

    .EXAMPLE
    New-GitConfigurationFile -Username iadgovuser1 -Email iadgovuser1@iad.gov -DiffMergeTool 'Perforce' -Public

    .EXAMPLE
    New-GitConfigurationFile -Username iadgovuser1 -Email iadgovuser1@iad.gov -DiffMergeTool 'SourceGear' -Proxy '123.456.789.0:80'

    .EXAMPLE
    New-GitConfigurationFile -Username iadgovuser1 -Email iadgovuser1@iad.gov -DiffMergeTool 'SourceGear' -Proxy '123.456.789.0:80' -CredentialManager 'manager'

    .EXAMPLE
    New-GitConfigurationFile -Username iadgovuser1 -Email iadgovuser1@iad.gov -DiffMergeTool 'SourceGear' -Proxy '123.456.789.0:80' -CredentialManager 'manager' -SigningKey 'AAABB1234'
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='GitHub account username')]
        [ValidateNotNullOrEmpty()]
        [string]$Username,

        [Parameter(Position=1, Mandatory=$true, HelpMessage='GitHub account email address')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_.Contains('@')})]
        [ValidateLength(3,254)]
        [string]$Email,

        [Parameter(Position=2, Mandatory=$false, HelpMessage='Prevents converting the email address to a GitHub private email address so the real email address will be exposed in commit logs')]
        [switch]$Public,

        [Parameter(Position=3, Mandatory=$false, HelpMessage='Specifies the diff/merge tool to use')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('SourceGear','Perforce',IgnoreCase=$true)]
        [string]$DiffMergeTool,

        [Parameter(Position=4, Mandatory=$true, HelpMessage='Proxy URL and port')]
        [ValidateNotNullOrEmpty()]
        [string]$Proxy,

        [Parameter(Position=5, Mandatory=$false, HelpMessage='Specifies the credential manager to use')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('manager','winstore','wincred', IgnoreCase=$true)]
        [string]$CredentialManager,

        [Parameter(Position=6, Mandatory=$false, HelpMessage='First 8 numbers/letters of your signing key')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[A-Za-z0-9]{8}$')]
        [string]$SigningKey
    )

    $path = ($env:HOMEDRIVE,$env:HOMEPATH,'.gitconfig' -join '\').Replace('\\','\') 

    if(Test-Path env\:GIT_CONFIG) {
        $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($env:GIT_CONFIG)
    }

    if(Test-Path -Path $path -PathType Leaf) {
        $pathInfo = [System.IO.FileInfo]$path
        $timestamp = '{0:yyyyMMddHHmmss}' -f $pathInfo.LastWriteTime
        $newName = $pathInfo.Name.Replace($pathInfo.Extension,('{0}.{1}.bak' -f $pathInfo.Extension,$timestamp))
        Rename-Item -Path $path -NewName $newName -Force
    } 
    
    if (-not(Test-Path -Path ([System.IO.FileInfo]$path).Directory.FullName -PathType Container))
    {
        throw "$path not found"
    }

    New-GitConfiguration @PSBoundParameters | Out-File -FilePath $path -NoNewline -Encoding ascii -Force
}
