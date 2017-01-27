#requires -Version 5
Set-StrictMode -Version 5

Function Test-RegistryValueName() {
<#
    .SYNOPSIS  
    Tests if a registry value name exists.
   
    .DESCRIPTION
    Tests if a registry value name exists in the specified hive at the specified path.
   
    .PARAMETER Path
    The path of the registry key to check, including the hive.
   
    .PARAMETER Name
    The name of the registry value to check.
     
    .EXAMPLE
    Test-RegistryValueName -Path 'hklm:\Software\Microsoft\Windows\CurrentVersion' -Name 'ProgramFilesDir'

    .EXAMPLE
    Test-RegistryValueName 'hklm:\Software\Microsoft\Windows\CurrentVersion' 'ProgramFilesDir'
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    Param(     
        [Parameter(Mandatory=$true, HelpMessage='The path of the registry key, including the hive.')]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
      
        [Parameter(Mandatory=$true, HelpMessage='The name of the registry value to check.')]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
        $exists = $false

    try {
        $value = Get-ItemProperty -Path $Path -ErrorAction stop | Select-Object -ExpandProperty $Name -ErrorAction stop
        $exists = ($value -ne $null) # catch the case where key exists but value name does not
    } catch [System.Management.Automation.PSArgumentException],[System.Management.Automation.ItemNotFoundException],[System.Management.Automation.ActionPreferenceStopException] {
        $exists = $false
    }

    return $exists
}

Function Uninstall-PowerShellEngine() {
    <#
    .SYNOPSIS
    Uninstalls the PowerShell engine.

    .DESCRIPTION
    Uninstalls the PowerShell engine. Only the PowerShell 1.0/2.0 engine can be uninstalled. This prevents downgrading to the PowerShell 2.0 engine which can be used to avoid PowerShell script blocking logging introduced in PowerShell 5.0.

    .PARAMETER
    The PowerShell engine version.

    .EXAMPLE
    Uninstall-PowerShellEngine

    .EXAMPLE
    Uninstall-PowerShellEngine -Version 2
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$false, HelpMessage='The PowerShell engine version')]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,2)]
        [UInt32]$Version = 2      
    )

    $key = 0
    $features = [string[]]@()

    switch ($Version) {
        { $_ -in @(1,2) } { $key = 1 ; $features = [string[]]@('MicrosoftWindowsPowerShellV2','MicrosoftWindowsPowerShellV2Root') ; break }
        default { throw "Unsupported PowerShell engine version $Version" }
    }

    $path = 'hklm:\Software\Microsoft\PowerShell\{0}\PowerShellEngine' -f $key

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    # it is much faster to check the registry to see if the PowerShell 2.0 engine is installed, ref: http://stackoverflow.com/questions/1825585/determine-installed-powershell-version
    # this is slow: if ((Test-WindowsOptionalFeature -FeatureName 'MicrosoftWindowsPowerShellV2') -and (Test-WindowsOptionalFeature -FeatureName 'MicrosoftWindowsPowerShellV2Root')) {
    if (Test-RegistryValueName -Path $path -Name 'PowerShellVersion') {
        Disable-WindowsOptionalFeature -Online -FeatureName $features -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -NoRestart | Out-Null
    }
}



