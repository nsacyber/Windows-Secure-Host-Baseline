#requires -RunAsAdministrator
#requires -Version 5
Set-StrictMode -Version 5

Function Uninstall-Powershell2() {
    <#
    .SYNOPSIS
    Uninstalls PowerShell 2.0.

    .DESCRIPTION
    Uninstalls PowerShell 2.0 to prevent downgrade to avoid PowerShell script blocking logging introduced in PowerShell 5.0.

    .EXAMPLE
    Uninstall-PowerShell2
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param()

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2','MicrosoftWindowsPowerShellV2Root' -ErrorAction SilentlyContinue | Out-Null
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

    Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -NoRestart | Out-Null
}

Function Disable-NetBIOS() {
    <#
    .SYNOPSIS
    Disable NetBIOS.

    .DESCRIPTION
    Disable NetBIOS on all network interfaces regardless of whether the interface is active or not. NetBIOS is suspectible to man-in-the-middle attacks and is not required in a domain.

    .EXAMPLE
    Disable-NetBIOS
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param()

    # ePO might have issues with disabling NetBIOS: https://kc.mcafee.com/corporate/index?page=content&id=KB76756 and https://kc.mcafee.com/corporate/index?page=content&id=KB56386
    # see also: https://support.microsoft.com/en-us/kb/313314

    # this is only active adapters, not all possible ones
    # does not appear to have a method to disable NetBIOS
    #$interfaces = [System.Net.NetworkInformation.NetworkInterface[]]@([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.NetworkInterfaceType -notin @([System.Net.NetworkInformation.NetworkInterfaceType]::Tunnel,[System.Net.NetworkInformation.NetworkInterfaceType]::Loopback) })

    #$adapters =  Get-WmiObject -Class 'Win32_NetworkAdapterConfiguration' 

    # SetTcpipNetbios return 84 for most adapters since most are not real adapters (tunnels or loopback)
    # https://msdn.microsoft.com/en-us/library/aa393601(v=vs.85).aspx
    #$adapters | ForEach-Object {
    #    $result = $_.SetTcpipNetbios($disabledValue)
    #
    #    Write-Verbose -Message ('{0} {1}' -f $_.Description, $_.SettingID)
    #
    #    if ($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue) {
    #        if ($result -in @(0,1)) {
    #         
    #            Write-Verbose -Message ('Disabled Netbios on adapter named {0}' -f $_.Description)
    #        }
    #    }
    #}

    $path = 'hklm:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    $valueName = 'NetbiosOptions'

    # https://msdn.microsoft.com/en-us/library/windows/hardware/dn923165(v=vs.85).aspx
    # 0 = Use DHCP server setting, 1 = Enabled, 2 = Disabled
    $disabledValue = 2

    Get-ChildItem -Path $path -Recurse | Where-Object { $_.GetValue($valueName) -ne $disabledValue } | ForEach { Set-ItemProperty -Path ('{0}\{1}' -f $path,$_.PSChildName) -Name $valueName -Value $disabledValue }
}