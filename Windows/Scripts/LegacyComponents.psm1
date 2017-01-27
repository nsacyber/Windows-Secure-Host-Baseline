#requires -Version 5
Set-StrictMode -Version 5




Function Test-WindowsOptionalFeature() {
    <#
    .SYNOPSIS
    Test whether a Windows feature exists.

    .DESCRIPTION
    Tests whether a Windows feature exists.

    .PARAMETER FeatureName
    The feature name to check.

    .EXAMPLE
    Test-WindowsOptionalFeature -FeatureName 'SMB1Protocol'
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The feature name to check.')]
        [ValidateNotNullOrEmpty()]
        [string]$FeatureName
    )

    $present = (Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue) -ne $null

    return $present
}

