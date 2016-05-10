#requires -version 2
Set-StrictMode -Version 2


# guard against re-adding the type when script is reloaded

$script:isTypeAdded = $false

if (-not($script:isTypeAdded)) {
    # moved to global scope so wouldn't have to define a new class for every function that does P\Invoke
    # otherwise would get type already exists error when calling different functions that do P\Invoke due to NativeMethods already existing
    $type = @'
        using System.Runtime.InteropServices;
        using System;

        namespace Kernel32 {                       
            public enum FIRMWARE_TYPE: uint {
                Unknown = 0,
                BIOS = 1,
                UEFI = 2,
                Max = 3
            }

            public class NativeMethods {
                [DllImport("kernel32.dll")]
                public static extern bool GetFirmwareType(out FIRMWARE_TYPE FirmwareType);

                [DllImport("kernel32.dll")]
                public static extern uint GetSystemFirmwareTable(uint FirmwareTableProviderSignature, uint FirmwareTableID, out System.IntPtr pFirmwareTableBuffer, uint BufferSize);
            }
        }
'@

    Add-Type $type

    $script:isTypeAdded = $true

}

Function Test-IsFirmwareTablePresent() {
    <#
    .SYNOPSIS
    Tests if a firmware table is present.

    .DESCRIPTION
    Tests if a firmware table is present.

    .PARAMETER Provider
    The firmware provider name.

    .PARAMETER Table
    The firmware table name.

    .EXAMPLE
    Test-IsFirmwareTablePresent -Provider 'ACPI' -Table 'TPM2'

    .EXAMPLE
    Test-IsFirmwareTablePresent -Provider 'ACPI' -Table 'TCPA'
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param (
        [Parameter(Position=1, Mandatory = $true, HelpMessage = 'The firmware table provider')]
        [ValidateSet('ACPI','FIRM','RSMB', IgnoreCase=$true)] 
        [ValidateNotNullOrEmpty()]
        [string]$Provider,

        [Parameter(Position=2, Mandatory = $true, HelpMessage = 'The firmware table name')]
        [ValidateNotNullOrEmpty()]
        [string]$Table
    )

    $providerName = $Provider.ToUpper()
    $providerSignature = ('0x{0:X8}' -f ([string](@([System.Text.Encoding]::ASCII.GetBytes($providerName.ToUpper()) | ForEach-Object { '{0:X2}' -f $_ }) -join '')) )

    $tableName = $Table.ToUpper().ToCharArray()
    [System.Array]::Reverse($tableName)
    $tableSignature = [uint32]('0x{0}' -f ((@([byte[]]$tableName | ForEach-Object { '{0:X2}' -f $_ })) -join ''))

    $tableBytes = [Kernel32.NativeMethods]::GetSystemFirmwareTable($providerSignature, $tableSignature, [ref] [System.IntPtr]::Zero, 0)

    return $tableBytes -ne 0
}

Function Get-FirmwareType() {
    <#
    .SYNOPSIS
    Gets the firmware type.

    .DESCRIPTION
    Gets the firmware type the operating system sees. UEFI firmware running Compatibility Support Module (CSM) will return 'BIOS' instead of 'UEFI'.

    .EXAMPLE
    Get-FirmwareType
    #>
    [CmdletBinding()]
    [OutputType([System.Enum])] # [Kernel32.FirmwareType] will not exist until after type/script is loaded
    Param ()
    $firmwareType = [Kernel32.FIRMWARE_TYPE]::Unknown

    $success = [Kernel32.NativeMethods]::GetFirmwareType([ref] $firmwareType)

    return $firmwareType
}

Function Test-IsFirmwareUEFI() {
    <#
    .SYNOPSIS
    Tests if the firmware type is UEFI.

    .DESCRIPTION
    Test if the firmware type the operating system sees is UEFI. UEFI firmware running Compatibility Support Module (CSM) will return false instead of true.

    .EXAMPLE
    Test-IsFirmwareUEFI
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param ()

    $firmwareType = [Kernel32.FIRMWARE_TYPE]::Unknown

    $success = [Kernel32.NativeMethods]::GetFirmwareType([ref] $firmwareType)

    return $firmwareType -eq [Kernel32.FIRMWARE_TYPE]::UEFI
}

Function Test-IsFirmwareBIOS() {
    <#
    .SYNOPSIS
    Tests if the firmware type is legacy BIOS.

    .DESCRIPTION
    Test if the firmware type the operating system sees is legacy BIOS. UEFI firmware running Compatibility Support Module (CSM) will return true instead of false.

    .EXAMPLE
    Test-IsFirmwareBIOS
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param()

    $firmwareType = [Kernel32.FIRMWARE_TYPE]::Unknown

    $success = [Kernel32.NativeMethods]::GetFirmwareType([ref] $firmwareType)

    return $firmwareType -eq [Kernel32.FIRMWARE_TYPE]::UEFI
}

Function Test-IsSecureBootEnabled() {
    <#
    .SYNOPSIS
    Tests if Secure Boot is enabled.

    .DESCRIPTION
    Test if Secure Boot is enabled.

    .EXAMPLE
    Test-IsSecureBootEnabled
    #>

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param()

    #Confirm-SecureBootUEFI command also works but it requires administrator privileges
    $value = Get-ItemPropertyValue -Path HKLM:\System\CurrentControlSet\Control\SecureBoot\State -Name UEFISecureBootEnabled -ErrorAction SilentlyContinue
    $enabled = $value -eq 1

    return $enabled
}

Function Test-IsIOMMUEnabled() {
    <#
    .SYNOPSIS
    Tests if an IOMMU is present and enabled.

    .DESCRIPTION
    Tests if an IOMMU is present and enabled. Does not test if an IOMMU is present but disabled.

    .EXAMPLE
    Test-IsIOMMUEnabled
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param()
    
    # DMAR = Intel Vt-d
    # IVRS = AMD-Vi
    # ACPI table is present only when IOMMU is present and enabled
    return (Test-IsFirmwareTablePresent -Provider 'ACPI' -Table 'DMAR') -or (Test-IsFirmwareTablePresent -Provider 'ACPI' -Table 'IVRS')
}

Function Test-IsTPMEnabled() {
    <#
    .SYNOPSIS
    Tests if a TPM is present and enabled.

    .DESCRIPTION
    Tests if a TPM is present and enabled. Does not test if a TPM is present but disabled.

    .EXAMPLE
    Test-IsTPMEnabled
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param()
    
    # TCPA = TPM 1.0,1.1,1.2
    # TPM2 = TPM 2.0
    # ACPI table is present only when TPM is is present and enabled
    return (Test-IsFirmwareTablePresent -Provider 'ACPI' -Table 'TCPA') -or (Test-IsFirmwareTablePresent -Provider 'ACPI' -Table 'TPM2')
}

Function Test-IsWindowsUEFIFirmwareUpdatePlatformSupported() {
    <#
    .SYNOPSIS
    Tests if the firmware supports updates via Windows Update.

    .DESCRIPTION
    Tests if the Windows UEFI Firmware Update Platform specification is supported by the firmware.

    .EXAMPLE
    Test-IsWindowsUEFIFirmwareUpdatePlatformSupported
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param()

    $supported = $false

    if (Test-Path HKLM:\Hardware\UEFI\ESRT) {
        $supported = ((@(Get-ChildItem -Path HKLM:\Hardware\UEFI\ESRT -Recurse -Force -ErrorAction SilentlyContinue| Where-Object {$_.GetValue('Type') -eq 1})).Count -gt 0)
    }
    
    return $supported
}

Function Test-IsCredentialGuardEnabled() {
    <#
    .SYNOPSIS
    Tests if Credential Guard is enabled and running.

    .DESCRIPTION
    Tests if Credential Guard is enabled and running.

    .EXAMPLE
    Test-IsCredentialGuardEnabled
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param()

    $dg = Get-WmiObject -ClassName 'Win32_DeviceGuard' -Namespace 'root\Microsoft\Windows\DeviceGuard'

    return ($dg.VirtualizationBasedSecurityStatus -eq 2 -and $dg.SecurityServicesRunning -contains 1 -and $dg.SecurityServicesConfigured -contains 1)
}