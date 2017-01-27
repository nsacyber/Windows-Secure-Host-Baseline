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

Function Test-IsNetBIOSEnabled() {
    <#
    .SYNOPSIS
    Tests if any network interface has NetBIOS enabled.

    .DESCRIPTION
    Tests if any network interface has NetBIOS enabled.

    .EXAMPLE
    Test-IsNetBIOSEnabled
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    Param()

    $interfacePath = 'hklm:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    $valueName = 'NetbiosOptions'

    # https://msdn.microsoft.com/en-us/library/windows/hardware/dn923165(v=vs.85).aspx
    # 0 = Use DHCP server setting, 1 = Enabled, 2 = Disabled
    $disabledValue = 2

    $enabledInterfaces = @(Get-ChildItem -Path $interfacePath -Recurse | Where-Object { $_.GetValue($valueName) -ne $disabledValue })

    return ($enabledInterfaces.Count -eq 0)
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
        [Parameter(Mandatory=$false, HelpMessage='Disable NetBIOS on standalone systems')]
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
        [Parameter(Mandatory=$false, HelpMessage='Restore NetBIOS on standalone systems')]
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