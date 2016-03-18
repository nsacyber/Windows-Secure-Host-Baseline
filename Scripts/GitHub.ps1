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
        [Parameter(Position=0, Mandatory=$false, HelpMessage="The raw markdown")]
        [ValidateSet('Core','Search', IgnoreCase=$true)]
        [string]$API = 'core'
    )

    $API = $API.ToLower()

    $response = Invoke-WebRequest -Method 'Get' -Uri ($script:GitHubBaseUri,'rate_limit' -join '/')

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

    $markdownStylesheetUri = 'https://raw.githubusercontent.com/sindresorhus/github-markdown-css/gh-pages/github-markdown.css'

    $params = @{
        Uri = 'https://raw.githubusercontent.com/sindresorhus/github-markdown-css/gh-pages/github-markdown.css';
        Method = 'Get';
        ContentType = 'text/plain';
    }

    $response = Invoke-WebRequest @params

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

    # carry forward to substitutions
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
        [Parameter(Position=0, Mandatory=$true, HelpMessage="The raw markdown")]
        [AllowEmptyString()]
        [string]$Markdown,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="The title for the HTML page")]
        [AllowEmptyString()]
        [string]$Title,

        [Parameter(Position=2, Mandatory=$true, HelpMessage="The template for the HTML page")]
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

        $params = @{
            Uri = ($script:GitHubBaseUri,'markdown','raw' -join '/');
            Method = 'POST';
            ContentType = 'text/plain';
            Body =  $requestBody;
        }

        $response = Invoke-WebRequest @params

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
    Convert-MarkdownToHtml -Files @(Get-ChildItem -Path '.\Secure-Host-Baseline\' -Recurse -Include "*.md")
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="The path of a folder containing markdown files")]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo[]]$Files
    )
    Begin {
        # get API rate limit remaing count
        # check against markdownFiles count and warn if conversion will exceed limit

        $limit = Get-GitHubRateLimit
        $remaining =[UInt32] $limit.Remaining
    }
    Process {
        $markdownFiles = [System.IO.FileInfo[]]@($Files | ForEach { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_) })
        $markdownFiles = [System.IO.FileInfo[]]@($markdownFiles | Where {$_.Length -gt 0 })

        if($markdownFiles.Count -gt $remaining) {
            throw '$($markdownFiles.Count) files to convert but only $remaining conversions allowed until limit is reached'
        }

        if($markdownFiles.Count -gt 0) {
            $htmlTemplate = Get-GitHubHtmlTemplate # only want to do this once say it calls out to the internet and the content won't change often

            $markdownFiles | ForEach {
                $markdownFile = $_.FullName

                if(Test-Path -Path $markdownFile -PathType Leaf) {
                    $htmlFile = $markdownFile.Replace('.md','.html')
                    $markdown = Get-Content -Path $markdownFile -Raw
                    #markdown = $markdown.Replace('.md)','.html)')
                    $html = Get-GitHubHtmlFromRawMarkdown -Markdown $markdown -Title $_.BaseName -Template $htmlTemplate
                    $html = $html.Replace('.md">','.html">') # update links to point to the converted HTML page
                    Set-Content -Path $htmlFile -Value $html -Force
                }
            }
        }
    }   
}