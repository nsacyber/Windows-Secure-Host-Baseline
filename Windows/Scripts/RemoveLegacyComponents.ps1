#requires -Version 5
Set-StrictMode -Version 5

Function Test-IsDomainJoined() {
    [CmdletBinding()]
    [OutputType([bool])]
    Param()
    #todo: function documentation
    $computer = Get-WmiObject -Class 'Win32_ComputerSystem' | Select-Object PartOfDomain

    return $computer.PartOfDomain
}

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
        [Parameter(Position=0, Mandatory=$true, HelpMessage='The path of the registry key, including the hive.')]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
      
        [Parameter(Position=1, Mandatory=$true, HelpMessage='The name of the registry value to check.')]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
        $exists = $false

    try {
        Get-ItemProperty -Path $Path -ErrorAction stop | Select-Object -ExpandProperty $Name -ErrorAction stop | Out-Null
        $exists = $true
    } catch [System.Management.Automation.PSArgumentException],[System.Management.Automation.ItemNotFoundException],[System.Management.Automation.ActionPreferenceStopException] {
        $exists = $false
    }

    return $exists
}

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
        [Parameter(Position=0, Mandatory=$true, HelpMessage='The feature name to check.')]
        [ValidateNotNullOrEmpty()]
        [string]$FeatureName
    )

    $present = (Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue) -ne $null

    return $present
}

Function Uninstall-Powershell2() {
    <#
    .SYNOPSIS
    Uninstalls PowerShell 2.0 engine.

    .DESCRIPTION
    Uninstalls PowerShell 2.0 engine in order to prevent downgrading to using the PowerShell 2.0 engine which can be used to avoid PowerShell script blocking logging introduced in PowerShell 5.0.

    .EXAMPLE
    Uninstall-PowerShell2
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param()

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    #todo: it is much faster to check the registry to see if the PowerShell 2.0 engine is installed, ref: http://stackoverflow.com/questions/1825585/determine-installed-powershell-version
    if ((Test-WindowsOptionalFeature -FeatureName 'MicrosoftWindowsPowerShellV2') -and (Test-WindowsOptionalFeature -FeatureName 'MicrosoftWindowsPowerShellV2Root')) {
        Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2','MicrosoftWindowsPowerShellV2Root' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -NoRestart -Confirm:$false | Out-Null
    }
}

Function Uninstall-SMB1() {
    <#
    .SYNOPSIS
    Uninstalls SMB 1.0.

    .DESCRIPTION
    Uninstalls Server Message Block 1.0 protocol since SMB 1.0 is only required for communicating with Windows XP and Windows Server 2003 both of which are end of life.

    .EXAMPLE
    Uninstall-SMB1
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param()

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    # it is much faster just to check if the mrxsmb10 registry key value exists or not rather than using Test-WindowsOptionalFeature
    # note that mrxsmb10 still exists when Disable-WindowsOptionalFeature is used. it is not deleted until a reboot, but SMB1 also continues to work until a reboot for that case
    # can't avoid the slowness of Disable-WindowsOptionalFeature, but at least by not using the Test- function, it will be as fast as it can be
    #if (Test-WindowsOptionalFeature -FeatureName 'SMB1Protocol') {
    if (Test-Path -Path 'hklm:\System\CurrentControlSet\Services\mrxsmb10') {
        Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -NoRestart -Confirm:$false | Out-Null
    }
}

Function Disable-NetBIOS() {
    <#
    .SYNOPSIS
    Disable NetBIOS.

    .DESCRIPTION
    Disable NetBIOS on all network interfaces regardless of whether the interface is active or not. NetBIOS is suspectible to man-in-the-middle attacks and is not required in a domain.

    .PARAMETER -IncludeStandalone
    Disable NetBIOS on standalone systems. By default only domain joined systems will have NetBIOS disabled.

    .EXAMPLE
    Disable-NetBIOS

    .EXAMPLE
    Disable-NetBIOS -IncludeStandalone
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$false, HelpMessage='Disable NetBIOS on standalone systems')]
        [switch]$IncludeStandalone    
    )

    # ePO might have issues with disabling NetBIOS: https://kc.mcafee.com/corporate/index?page=content&id=KB76756 and https://kc.mcafee.com/corporate/index?page=content&id=KB56386
    # see also: https://support.microsoft.com/en-us/kb/313314

    if((Test-IsDomainJoined) -or $IncludeStandalone) {
        $interfacePath = 'hklm:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        $valueName = 'NetbiosOptions'
        $previousValueName = 'Previous_NetbiosOptions'

        # https://msdn.microsoft.com/en-us/library/windows/hardware/dn923165(v=vs.85).aspx
        # 0 = Use DHCP server setting, 1 = Enabled, 2 = Disabled
        $disabledValue = 2

        Get-ChildItem -Path $interfacePath -Recurse | Where-Object { $_.GetValue($valueName) -ne $disabledValue } | ForEach-Object { 
            $currentValue = $_.GetValue($valueName)

            # create a backup value, if it doesn't exist, so that we can use it to restore the setting to the previous value
            if (-not(Test-RegistryValueName -Path ('{0}\{1}' -f $interfacePath,$_.PSChildName) -Name $previousValueName)) {        
                Set-ItemProperty -Path ('{0}\{1}' -f $interfacePath,$_.PSChildName) -Name $previousValueName -Value $currentValue
            }

            Set-ItemProperty -Path ('{0}\{1}' -f $interfacePath,$_.PSChildName) -Name $valueName -Value $disabledValue 
        }
    }
}

Function Restore-NetBIOS() {
    <#
    .SYNOPSIS
    Restores NetBIOS to the previously saved state.

    .DESCRIPTION
    Restores NetBIOS to the previously saved state on all network interfaces regardless of whether the interface is active or not.

    .PARAMETER -IncludeStandalone
    Restore NetBIOS on standalone systems. By default only domain joined systems will have NetBIOS restored.

    .EXAMPLE
    Restore-NetBIOS

    .EXAMPLE
    Restore-NetBIOS -IncludeStandalone
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$false, HelpMessage='Restore NetBIOS on standalone systems')]
        [switch]$IncludeStandalone    
    )

    if((Test-IsDomainJoined) -or $IncludeStandalone) {
        $interfacePath = 'hklm:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        $valueName = 'NetbiosOptions'
        $previousValueName = 'Previous_NetbiosOptions'

        Get-ChildItem -Path $interfacePath -Recurse | Where-Object { $_.GetValue($previousValueName) -ne $null } | ForEach-Object { 
            $currentValue = $_.GetValue($valueName)
            $previousValue = $_.GetValue($previousValueName)

            # create a backup value, if it doesn't exist, so that we can use it to restore the setting to the previous value
            if ($currentValue -ne $previousValue) {        
                Set-ItemProperty -Path ('{0}\{1}' -f $interfacePath,$_.PSChildName) -Name $valueName -Value $previousValue
            }

            Remove-ItemProperty -Path ('{0}\{1}' -f $interfacePath,$_.PSChildName) -Name $previousValueName
        }
    }
}

Function Disable-SMB1 {
    <#
    .SYNOPSIS
    Disable the SMB 1.0 protocol.

    .DESCRIPTION
    Disable the SMB 1.0 protocol. Since a system can act as an SMB server and client, SMB is disabled for both. If SMB1 is uninstalled, then the this function does nothing since there is nothing to disable.

    .EXAMPLE
    Disable-SMB1
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$false, HelpMessage='Disable NetBIOS on standalone systems')]
        [switch]$IncludeStandalone    
    )

    $smb1Path = 'hklm:\System\CurrentControlSet\Services\mrxsmb10'
    $smbClientPath = 'hklm:\System\CurrentControlSet\Services\LanmanWorkstation'
    $smbServerPath = 'hklm:\System\CurrentControlSet\Services\LanmanServer\Parameters'

    # checking if the registry key exists MUCH faster than using Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' and checking its State value
    # if using Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' to uninstall SMB1, then the mrxsmb10 value is removed after reboot 
    # technically SMB1 still works until a reboot happens due to the driver still being loaded
    if (Test-Path -Path $smb1Path) {

        # the SMB1 registry value name used below does not exist by default which means SMB1 is enabled (ONLY if the SMB1Protocol feature State is Enabled as returned by Get-WindowsOptionalFeature OR mrxsmb10 exists)
        # SMB1 is disabled when the SMB1 registry value exists AND it is set to 0 (OR if SMB1Protocol feature State is Disabled as returned by Get-WindowsOptionalFeature or mrxsmb10 does not exist) and a reboot has occured 
        # (Get-SmbServerConfiguration).EnableSMB1Protocol merely reflects the regsitry value information (returns $true if not exist OR exists and value is 1. returns $false if exists and value is 0)
        # Get-SmbServerConfiguration does not reflect the Windows feature state which could lead to false positives by solely using that command

        if (Test-RegistryValueName -Path $smbServerPath -Name 'SMB1') {
            $smb1Value = Get-ItemPropertyValue -Path $smbServerPath -Name 'SMB1' 
            Set-ItemProperty -Path $smbServerPath -Name 'Previous_SMB1' -Type DWORD -Value $smb1Value -Force
        }

        Set-ItemProperty -Path $smbServerPath -Name 'SMB1' -Type DWORD -Value 0 -Force # 0 = Disabled, 1 = Enabled

        # technically we don't have to disable the driver but we will anyway to be safe

        $startValue = Get-ItemProperty -Path $smb1Path -Name 'Start'
        Set-ItemProperty -Path $smb1Path  -Name 'Previous_Start' -Type DWORD -Value $startValue -Force

        Set-ItemProperty -Path $smb1Path  -Name 'Start' -Type DWORD -Value 4 -Force # 4 = Disabled, 2 = Automatic (normal value)

        $dependOnValue = Get-ItemPropertyValue -Path $smbClientPath -Name 'DependOnService' 
        Set-ItemPropertyValue -Path $smbClientPath -Name 'Previous_DependOnService' -Type MultiString -Value $dependOnValue -Force

        if ('mrxsmb10' -in $dependOnValue) {
            $newDependOnValue = ((($dependOnValue -join ',') -replace 'mrxsmb10','') -replace ',,',',') -split ',' # remove the dependency on SMB1
            Set-ItemProperty -Path $smbClientPath  -Name 'DependOnService' -Type MultiString -Value $newDependOnValue -Force
        }
    }
}

Function Get-SMBDialect() {
    <#
    .SYNOPSIS
    Gets the highest SMB dialect supported by the system.

    .DESCRIPTION
    Gets the highest SMB dialect supported by the system.

    .EXAMPLE
    Get-SMBDialect
    #>
    [CmdletBinding()]
    [OutputType([System.Version])]
    Param()

    $drive = $env:SystemDrive -replace ':',''

    $drive = '{0}$' -f $drive

    Get-ChildItem -Path "\\localhost\$drive" | Out-Null

    $dialect = Get-SmbConnection -ServerName 'localhost' | Where-Object { $_.ShareName -eq $drive } | Select-Object Dialect -ExpandProperty Dialect

    return [System.Version]$dialect
}

#todo: Get-SMBDialectsInUse function. use Get-SMBConnection for client side and Get-SMBSession for server side. return unique list of dialects in use @([Server,1.1],[Client,2.0])
#Get-SMBConnection is the client side of SMB connections
#Get-SMBSession is the server side of SMB connections