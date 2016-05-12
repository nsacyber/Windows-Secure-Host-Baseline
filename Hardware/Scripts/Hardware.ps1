#requires -version 2
Set-StrictMode -Version 2

# guard against re-adding the type when script is reloaded
# will leave a stale type in memory if the type is changed so will need to close/open editor to load changed type

if ($null -eq ([System.Management.Automation.PSTypeName]'Kernel32.NativeMethods').Type) {
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

            [StructLayout(LayoutKind.Explicit)]
            public struct PROCESSOR_INFO_UNION {
                [FieldOffset(0)]
                public UInt32 dwOemId;

                [FieldOffset(0)]
                public UInt16 wProcessorArchitecture;

                [FieldOffset(2)]
                public UInt16 wReserved;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SYSTEM_INFO {
                public PROCESSOR_INFO_UNION uProcessorInfo;
                public UInt32 dwPageSize;
                public IntPtr lpMinimumApplicationAddress;
                public IntPtr lpMaximumApplicationAddress;
                public UIntPtr dwActiveProcessorMask;
                public UInt32 dwNumberOfProcessors;
                public UInt32 dwProcessorType;
                public UInt32 dwAllocationGranularity;
                public UInt16 wProcessorLevel;
                public UInt16 wProcessorRevision;
            }

            public class NativeMethods {
                [DllImport("kernel32.dll")]
                public static extern bool GetFirmwareType(out FIRMWARE_TYPE FirmwareType);

                [DllImport("kernel32.dll")]
                public static extern uint GetSystemFirmwareTable(uint FirmwareTableProviderSignature, uint FirmwareTableID, out System.IntPtr pFirmwareTableBuffer, uint BufferSize);

                [DllImport("kernel32.dll")]
                public static extern void GetNativeSystemInfo([MarshalAs(UnmanagedType.Struct)] ref SYSTEM_INFO lpSystemInfo);

                [DllImport("kernel32.dll", SetLastError=true)]
                public static extern uint GetFirmwareEnvironmentVariable(string lpName, string lpGuid, IntPtr pBUffer, uint nSize);
            }
        }
'@

    Add-Type $type
}

Function Test-IsFirmwareTablePresent() {
    <#
    .SYNOPSIS
    Tests if a firmware table is present.

    .DESCRIPTION
    Tests if a firmware table is present.

    .PREREQUISITES
    Windows Vista x86/x64 and later, Windows Server 2008 x86/x64 and later, Windows XP X64, Windows Server 2003 SP1.

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
    $providerSignature = [uint32]('0x{0:X8}' -f ([string](@([System.Text.Encoding]::ASCII.GetBytes($providerName.ToUpper()) | ForEach-Object { '{0:X2}' -f $_ }) -join '')) )

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

    .PREREQUISITES
    Windows Vista x86/x64 and later, Windows XP x86 SP1, Windows Server 2003 x86/x64 and later.

    .EXAMPLE
    Get-FirmwareType
    #>
    [CmdletBinding()]
    [OutputType([System.Enum])]
    Param()

    $firmwareType = [Kernel32.FIRMWARE_TYPE]::Unknown

    # don't need SE_SYSTEM_ENVIRONMENT_NAME privilege for this case
    # accessing a real variable will fail with Win32 error 1314 (ERROR_PRIVILEGE_NOT_HELD) if privilege isn't held though
    $result = [Kernel32.NativeMethods]::GetFirmwareEnvironmentVariable('', '{00000000-0000-0000-0000-000000000000}', [System.IntPtr]::Zero, 0)
    $win32Error = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($result -eq 0) {
        switch($win32Error) {
            1 { $firmwareType = [Kernel32.FIRMWARE_TYPE]::BIOS; break } # ERROR_INVALID_FUNCTION
            998 { $firmwareType = [Kernel32.FIRMWARE_TYPE]::UEFI; break } # ERROR_NOACCESS
            default { throw $("Win32 error {0} 0x{1:X8}" -f $win32Error, $win32Error) }
        }
    }

    return $firmwareType
}

Function Get-FirmwareTypeEx() {
    <#
    .SYNOPSIS
    Gets the firmware type.

    .DESCRIPTION
    Gets the firmware type the operating system sees. UEFI firmware running Compatibility Support Module (CSM) will return 'BIOS' instead of 'UEFI'.

    .PREREQUISITES
    Windows 8 x86/x64 and later.

    .EXAMPLE
    Get-FirmwareTypeEx
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssigments', '', Scope='Function')] #success variable doesn't need to be used
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

    .PREREQUISITES
    Windows Vista x86/x64 and later, Windows XP x86 SP1, Windows Server 2003 x86/x64 and later.

    .EXAMPLE
    Test-IsFirmwareUEFI
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param()

    $firmwareType = Get-FirmwareType

    return $firmwareType -eq [Kernel32.FIRMWARE_TYPE]::UEFI
}

Function Test-IsFirmwareBIOS() {
    <#
    .SYNOPSIS
    Tests if the firmware type is legacy BIOS.

    .DESCRIPTION
    Test if the firmware type the operating system sees is legacy BIOS. UEFI firmware running Compatibility Support Module (CSM) will return true instead of false.

    .PREREQUISITES
    Windows Vista x86/x64 and later, Windows XP x86 SP1, Windows Server 2003 x86/x64 and later.

    .EXAMPLE
    Test-IsFirmwareBIOS
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param()

    $firmwareType = Get-FirmwareType

    return $firmwareType -eq [Kernel32.FIRMWARE_TYPE]::BIOS
}

Function Test-IsSecureBootEnabled() {
    <#
    .SYNOPSIS
    Tests if Secure Boot is enabled.

    .DESCRIPTION
    Test if Secure Boot is enabled.

    .PREREQUISITES
    None.

    .EXAMPLE
    Test-IsSecureBootEnabled
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param()

    $enabled = $false

    # Confirm-SecureBootUEFI command also works but it requires administrator privileges and only works on Windows 8 and later
    $value = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'UEFISecureBootEnabled' -ErrorAction SilentlyContinue

    if ($null -ne $value) {
        $enabled = $value -eq 1
    }

    return $enabled
}

Function Test-IsIOMMUEnabled() {
    <#
    .SYNOPSIS
    Tests if an IOMMU is present and enabled.

    .DESCRIPTION
    Tests if an IOMMU is present and enabled. Does not test if an IOMMU is present but disabled.

    .PREREQUISITES
    Windows Vista x86/x64 and later, Windows Server 2008 x86/x64 and later, Windows XP X64, Windows Server 2003 SP1.

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

    .PREREQUISITES
    Windows Vista x86/x64 and later, Windows Server 2008 x86/x64 and later, Windows XP X64, Windows Server 2003 SP1.

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

    .PREREQUISITES
    None.

    .EXAMPLE
    Test-IsWindowsUEFIFirmwareUpdatePlatformSupported
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param()

    $supported = $false

    if (Test-Path -Path 'HKLM:\Hardware\UEFI\ESRT') {
        $supported = ((@(Get-ChildItem -Path 'HKLM:\Hardware\UEFI\ESRT' -Recurse -Force -ErrorAction SilentlyContinue| Where-Object {$_.GetValue('Type') -eq 1})).Count -gt 0)
    }
    
    return $supported
}

Function Test-IsCredentialGuardEnabled() {
    <#
    .SYNOPSIS
    Tests if Credential Guard is enabled and running.

    .DESCRIPTION
    Tests if Credential Guard is enabled and running.

    .PREREQUISITES
    Windows 10 x86/x64 and later.

    .EXAMPLE
    Test-IsCredentialGuardEnabled
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param()

    $enabled = $false

    if ((Test-Path -Path 'HKLM:\Software\Policies\Microsoft\DeviceGuard') -or (Test-Path -Path 'HKLM:\System\CurrentControlSet\Control\DeviceGuard')) {
        $dg = Get-WmiObject -ClassName 'Win32_DeviceGuard' -Namespace 'root\Microsoft\Windows\DeviceGuard'
        $enabled =  ($dg.VirtualizationBasedSecurityStatus -eq 2 -and $dg.SecurityServicesRunning -contains 1 -and $dg.SecurityServicesConfigured -contains 1)
    }

    return $enabled
}

Function Get-ArchitectureName() {
    <#
    .SYNOPSIS
    Gets hardware architecture name.

    .DESCRIPTION
    Gets hardware architecture name based on the architecture of the processor.

    .PREREQUISITES
    None.

    .PARAMETER Architecture
    Architecture value.

    .EXAMPLE
    Get-ArchitectureName
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='Architecture')]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(0,12)]
        [Uint32]$Architecture
    )

    $name = 'unknown'

    switch ($Architecture) {
        0 { $name = 'x86'; break }
        1 { $name = 'Alpha'; break }
        2 { $name = 'MIPS'; break }
        3 { $name = 'PowerPC'; break }
        5 { $name = 'ARM'; break }
        6 { $name = 'Itanium'; break }
        9 { $name = 'x64'; break }
        12{ $name = 'ARM64'; break }
        default { $name = 'unknown' }
    }

    return $name
}

Function Get-HardwareArchitectureName() {
    <#
    .SYNOPSIS
    Gets hardware architecture name.

    .DESCRIPTION
    Gets hardware architecture name based on the architecture of the processor.

    .PREREQUISITES
    None.

    .EXAMPLE
    Get-HardwareArchitectureName
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param()

    $processor = Get-WmiObject -Class 'Win32_Processor' -Filter "DeviceID='CPU0'" | Select-Object 'Architecture'
    $architecture = $processor.Architecture
    $name = Get-ArchitectureName -Architecture $architecture

    return $name
}

Function Get-OperatingSystemArchitectureName() {
    <#
    .SYNOPSIS
    Gets operating system architecture name.

    .DESCRIPTION
    Gets operating system architecture name.

    .PREREQUISITES
    Windows XP x86/x64 and later, Windows Server 2003 x86/x64 and later.

    .EXAMPLE
    Get-OperatingSystemArchitectureName
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param()

    # unintuitive but returns correct results for OS architecture in a virtualized environment

    $systemInfo = New-Object Kernel32.SYSTEM_INFO
    $systemInfo.uProcessorInfo = New-Object Kernel32.PROCESSOR_INFO_UNION
    [Kernel32.NativeMethods]::GetNativeSystemInfo([ref] $systemInfo)
    $architecture = $systemInfo.uProcessorInfo.wProcessorArchitecture

    $name = Get-ArchitectureName -Architecture $architecture

    return $name
}

Function Get-HardwareBitness() {
    <#
    .SYNOPSIS
    Gets hardware bitness.

    .DESCRIPTION
    Gets hardware bitness.

    .PREREQUISITES
    None.

    .EXAMPLE
    Get-HardwareBitness
    #>
    [CmdletBinding()]
    [OutputType([Uint32])]
    Param()

    $processor = Get-WmiObject -Class 'Win32_Processor' -Filter "DeviceID='CPU0'" | Select-Object 'DataWidth'
    $bitness = $processor.DataWidth
    return $bitness
}

Function Get-OperatingSystemBitness() {
    <#
    .SYNOPSIS
    Gets operating system bitness.

    .DESCRIPTION
    Gets operating system bitness.

    .PREREQUISITES
    None.

    .EXAMPLE
    Get-OperatingSystemBitness
    #>
    [CmdletBinding()]
    [OutputType([Uint32])]
    Param()

    $processor = Get-WmiObject -Class 'Win32_Processor' -Filter "DeviceID='CPU0'" | Select-Object 'AddressWidth'
    $bitness = $processor.AddressWidth
    return $bitness
}

Function Test-IsOperatinySystemVirtualized() {
    <#
    .SYNOPSIS
    Tests if the operating system is virtualized.

    .DESCRIPTION
    Tests if the operating system is virtualized.

    .PREREQUISITES
    Windows 8 x86/x64 and later.

    .EXAMPLE
    Test-IsOperatingSystemVirtualized
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param()

    # Windows 8 and later only but that's ok since we assume Windows 10 for now
    # TODO come up with method for Windows 7, prefer not to rely on fingerprinting Model/Manufacturer

    # returns correct result on Hyper-V and VMware Workstation
    # TODO test other virtualization products
    $computer = Get-WmiObject -Class 'Win32_ComputerSystem' | Select-Object 'HypervisorPresent'
    $virtulized = $computer.HypervisorPresent

    return $virtulized
}