#requires -version 2
Set-StrictMode -Version 2

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

        [Parameter(Position=1, Mandatory = $true, HelpMessage = 'The firmware table name')]
        [ValidateNotNullOrEmpty()]
        [string]$Table
    )
    Begin {
        $type = @'
            using System.Runtime.InteropServices;
            using System;

            namespace Kernel32 {
                public class NativeMethods {
                    [DllImport("kernel32.dll")]
                    public static extern uint GetSystemFirmwareTable(uint FirmwareTableProviderSignature, uint FirmwareTableID, out System.IntPtr pFirmwareTableBuffer, uint BufferSize);
                }
            }
'@

        Add-Type $type
    }
    Process {
        $providerName = $Provider.ToUpper()
        $providerSignature = ('0x{0:X8}' -f ([string](@([System.Text.Encoding]::ASCII.GetBytes($providerName.ToUpper()) | ForEach-Object { '{0:X2}' -f $_ }) -join '')) )

        $tableName = $Table.ToUpper().ToCharArray()
        [System.Array]::Reverse($tableName)
        $tableSignature = [uint32]('0x{0}' -f ((@([byte[]]$tableName | ForEach-Object { '{0:X2}' -f $_ })) -join ''))

        $tableBytes = [Kernel32.NativeMethods]::GetSystemFirmwareTable($providerSignature, $tableSignature, [ref] [System.IntPtr]::Zero, 0)

        return $tableBytes -ne 0
    }

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

Function Test-IsUEFIWindowsUpdateSupported() {
    <#
    .SYNOPSIS
    Tests if the firmware supports updates via Windows Update.

    .DESCRIPTION
    Tests if the Windows UEFI Update Platform specification is supported by the firmware.

    .EXAMPLE
    Test-IsIOMMUEnabled
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