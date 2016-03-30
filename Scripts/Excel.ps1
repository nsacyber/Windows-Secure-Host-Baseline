#requires -Version 3
Set-StrictMode -Version 3

Function Convert-CsvToExcel() {
    <#
    .SYNOPSIS
    Converts a CSV file to an Excel file.

    .DESCRIPTION
    Converts a CSV file to an Excel file.

    .PARAMETER CsvPath
    Path to the CSV file.

    .PARAMETER ExcelPath
    Path to the Excel file.

    .EXAMPLE
    Convert-CsvToExcel -CsvPath '.\Secure-Host-Baseline\Hardware\Template.csv' -ExcelPath '.\Secure-Host-Baseline\Hardware\Template.xlsx'
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Path to CSV file")]
        [ValidateNotNullOrEmpty()]
        [string]$CsvPath,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Path to Excel file")]
        [ValidateNotNullOrEmpty()]
        [string]$ExcelPath
    )

    $excelFiles = @(Get-ChildItem @($env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramW6432) -Filter 'excel.exe' -Recurse -Force -ErrorAction SilentlyContinue | Where { $_.PsIsContainer -eq $false } | Get-Unique)

    if($excelFiles.Count -eq 0) {
        throw 'Excel not installed'
    }

    $CsvPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CsvPath)

    if (-not(Test-Path -Path $CsvPath -PathType Leaf)) {
        throw '$CsvPath does not exist'
    }

    $ExcelPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ExcelPath)

    if (Test-Path -Path $ExcelPath -PathType Leaf) {
        Remove-Item -Path $ExcelPath -Force
    }

    $excel = New-Object -ComObject Excel.Application

    $excel.Visible = $false
    $excel.DisplayAlerts = $false

    #[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'

    # 51 = xlOpenXMLWorkbook
    # 60 = xlOpenDocumentSpreadsheet
    # 61 = xlOpenXMLStrictWorkbook
    $excel.Workbooks.Open($CsvPath).SaveAs($ExcelPath,51)
    $excel.Quit()
}

Function Convert-ExcelToCsv() {
    <#
    .SYNOPSIS
    Converts an Excel file to a CSV file.

    .DESCRIPTION
    Converts an Excel file to a CSV file.

    .PARAMETER CsvPath
    Path to the CSV file.

    .PARAMETER ExcelPath
    Path to the Excel file.

    .EXAMPLE
    Convert-ExcelToCsv -CsvPath '.\Secure-Host-Baseline\Hardware\Template.csv' -ExcelPath '.\Secure-Host-Baseline\Hardware\Template.xlsx'
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="Path to CSV file")]
        [ValidateNotNullOrEmpty()]
        [string]$CsvPath,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="Path to Excel file")]
        [ValidateNotNullOrEmpty()]
        [string]$ExcelPath
    )

    $excelFiles = @(Get-ChildItem @($env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramW6432) -Filter 'excel.exe' -Recurse -Force -ErrorAction SilentlyContinue | Where { $_.PsIsContainer -eq $false } | Get-Unique)

    if($excelFiles.Count -eq 0) {
        throw 'Excel not installed'
    }

    $ExcelPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ExcelPath)

    if (-not(Test-Path -Path $ExcelPath -PathType Leaf)) {
        throw '$ExcelPath does not exist'
    }

    $CsvPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CsvPath)

    if (Test-Path -Path $CsvPath -PathType Leaf) {
        Remove-Item -Path $CsvPath -Force
    }

    $excel = New-Object -ComObject Excel.Application

    $excel.Visible = $false
    $excel.DisplayAlerts = $false

    #[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'

    # 6 = xlCSV
    # 23 = xlCSVWindows
    # 24 = xlCSVMSDOS
    $excel.Workbooks.Open($ExcelPath).SaveAs($CsvPath,6)
    $excel.Quit()
}