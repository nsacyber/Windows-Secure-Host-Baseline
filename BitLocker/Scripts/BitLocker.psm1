#requires -RunAsAdministrator
#requires -version 3
Set-StrictMode -Version 3

Function Get-BitLockerStatus() {
    <#
    .SYNOPSIS
    Starts the BitLocker encryption process for a drive.

    .DESCRIPTION
    Starts the BitLocker encryption process for a drive.

    .PARAMETER Drive
    The drive letter, including : character, to enable BitLocker on.

    .EXAMPLE
    Get-BitLockerStatus -Drive $env:SYSTEMDRIVE
    #>
    [CmdletBinding()] 
    #[OutputType([FveApi.FVE_STATUS])] # throws an error since the type isn't added until the function has executed
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The drive letter, including : character, to get the BitLocker status for')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[A-Z]:$')]
        [string]$Drive
    )
    Begin {
$type = @'
        using System.Runtime.InteropServices;
        using System;

        namespace FveApi {
            [StructLayout(LayoutKind.Sequential)]
            public struct FVE_STATUS {
                public uint Size;
                public uint Version;
                public uint Flags;
                public double ConversionPercent;
                public long ConversionStatus;
            }

            public class NativeMethods {
                [DllImport("fveapi.dll", CharSet=CharSet.Unicode)]
                public static extern int FveGetStatusW(String volume, ref FVE_STATUS status);
            }
        }
'@
        Add-Type $type
    }
    Process {

        $bitlockerDrives = [System.IO.DriveInfo[]]@([System.IO.DriveInfo]::GetDrives()| Where-Object { $_.DriveType -eq [System.IO.DriveType]::Fixed -or $_.DriveType -eq [System.IO.DriveType]::Removable })

        if("$Drive\" -in @($bitlockerDrives | ForEach-Object { $_.Name })) {
            throw "Cannot get BitLocker status for $Drive"
        }

        [FveApi.FVE_STATUS]$status = New-Object FveApi.FVE_STATUS
        $status.Size = [System.Runtime.InteropServices.Marshal]::SizeOf($status)
        $status.Version = 1;

        $value = [FveApi.NativeMethods]::FveGetStatusW("\\.\$Drive", [ref] $status)

        if(0 -ne $value) {
            throw ('Retrieving BitLocker status failed with error 0x{0:X8}' -f $value)
        }

        return $status
    }
}

Function Start-BitLockerEncryption() {
    <#
    .SYNOPSIS
    Starts the BitLocker encryption process for a drive.

    .DESCRIPTION
    Starts the BitLocker encryption process for a drive.

    .PARAMETER Drive
    The drive letter, including : character, to enable BitLocker on.

    .PARAMETER UsePin
    Specifies to use a PIN along with a TPM.

    .PARAMETER Pin
    Specifies the PIN rather than being prompted for it.

    .PARAMETER RecoveryPath
    The path of a folder to store recovery password information.

    .PARAMETER Restart
    Specifies to restart the system, if needed, so the BitLocker encryption process can start.

    .EXAMPLE
    Start-BitLockerEncryption -Drive $env:SYSTEMDRIVE -RecoveryPath ($env:USERPROFILE,'Desktop' -join '\')

    .EXAMPLE
    Start-BitLockerEncryption -Drive $env:SYSTEMDRIVE -RecoveryPath ($env:USERPROFILE,'Desktop' -join '\') -UsePin

    .EXAMPLE
    Start-BitLockerEncryption -Drive $env:SYSTEMDRIVE -RecoveryPath ($env:USERPROFILE,'Desktop' -join '\') -UsePin -Pin ('12345678' | ConvertTo-SecureString -AsPlainText -Force)

    .EXAMPLE
    Start-BitLockerEncryption -Drive $env:SYSTEMDRIVE -RecoveryPath ($env:USERPROFILE,'Desktop' -join '\') -UsePin -Pin  ('12345678' | ConvertTo-SecureString -AsPlainText -Force) -UseActiveDirectory -Restart
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '', Scope='Function')]
    [CmdletBinding()] 
    [OutputType([System.Version])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The drive letter, including : character, to enable BitLocker on')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[A-Z]:$')]
        [string]$Drive,

        [Parameter(Mandatory=$false, HelpMessage='Specifies to use a PIN along with a TPM')]
        [switch]$UsePin,

        [Parameter(Mandatory=$false, HelpMessage='Specifies the PIN rather than being prompted for it')]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]$Pin,

        [Parameter(Mandatory=$false, HelpMessage='The path of a folder to store recovery password information')]
        [ValidateNotNullOrEmpty()]
        [System.IO.DirectoryInfo]$RecoveryPath,

        [Parameter(Mandatory=$false, HelpMessage='Specifies to restart the system so the BitLocker encryption process can start')]
        [switch]$Restart 
    )

    $bitlockerDrives = [System.IO.DriveInfo[]]@([System.IO.DriveInfo]::GetDrives()| Where-Object { $_.DriveType -eq [System.IO.DriveType]::Fixed -or $_.DriveType -eq [System.IO.DriveType]::Removable })

    if("$Drive\" -in @($bitlockerDrives | ForEach-Object { $_.Name })) {
        throw "$Drive cannot be encrypted by BitLocker"
    }

    $tpm = Get-WmiObject -Class 'Win32_Tpm' -Namespace 'root\CIMV2\Security\MicrosoftTpm'

    #if(-not($tpm.IsReady().IsReady)) {
    #    $readyBitmask = $tpm.IsReadyInformation().Information
    #    $message = 'TPM is not ready for use by BitLocker. TPM must be provisioned. ReadyInformation bitmask: 0x{0:X8} See https://msdn.microsoft.com/en-us/library/windows/desktop/jj660284(v=vs.85).aspx for more information.' -f $readyBitmask    
    #    throw $message 
    #}

    if ($RecoveryPath -ne $null) {
        if (-not(Test-Path -Path $RecoveryPath.FullName -PathType Container)) {
            throw "$RecoveryPath not found"
        }
    }

    $isDomainJoined = (Get-WmiObject -Class 'Win32_ComputerSystem').PartOfDomain

    $volume = Get-BitLockerVolume -MountPoint $Drive

    $volumeDetails = Get-WmiObject -Class 'Win32_EncryptableVolume' -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -Filter "DriveLetter='$Drive'"

    if ($volume.ProtectionStatus -eq [Microsoft.BitLocker.Structures.BitLockerVolumeProtectionStatus]::Off -and -not($volumeDetails.IsVolumeInitializedForProtection)) {
        if ($UsePin) {
            if ($Pin -eq $null) {
                $bitlockerPin = Read-Host -AsSecureString -Prompt 'Enter BitLocker PIN'
            } else {
                $bitlockerPin = $Pin            
            }

            try {
                $volume = Enable-BitLocker -MountPoint $Drive -PIN $bitlockerPin -TpmAndPinProtector -ErrorAction Stop -Verbose:$false # 4>$null
            } catch [System.Runtime.InteropServices.COMException] {
                $errorNumber = $_.Exception.HResult

                $message = $_.Exception.Message
                $fix = ''

                switch ($errorNumber) {
                    0x8031005B { $fix = "Change the 'Require additional authentication at startup' policy to configure all 4 dropdown menu options to 'Allow' OR set 1 option to 'Require' and the other 3 options to 'Do not allow'" ; break }
                    0x803100B5 { $fix = "Set the 'Enable use of BitLocker authentication requiring preboot keyboard input on slates' policy to Enabled"; break }
                    default {}
                }

                throw ($message,$fix -join ([System.Environment]::NewLine))
            }

            $bitlockerPin.Dispose()
            $Pin.Dispose()
        } else {
            $volume = Enable-BitLocker -MountPoint $Drive -TpmProtector -ErrorAction Stop -Verbose:$false # 4>$null
        }
        
        $volume = Add-BitLockerKeyProtector -MountPoint $Drive -RecoveryPasswordProtector -ErrorAction Stop -Verbose:$false # 4>$null
    }

    if($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue) {
        $volume.KeyProtector | ForEach-Object {
            Write-Verbose -Message ('Protector Type: {0} Protector ID: {1} Protector Password: {2}' -f $_.KeyProtectorType,$_.KeyProtectorId,$_.RecoveryPassword)
        }
    }

    $recoveryPasswordProtector = $volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq [Microsoft.BitLocker.Structures.BitLockerVolumeKeyProtectorType]::RecoveryPassword }

    
    if ($RecoveryPath -ne $null) {
        $recoveryFile = '{0}\{1}_bitlocker_{2}.txt' -f $RecoveryPath.FullName,$env:COMPUTERNAME,$recoveryPasswordProtector.KeyProtectorId

        $volume.KeyProtector | ForEach-Object { 'Protector Type: {0} Protector ID: {1} Protector Password: {2}' -f $_.KeyProtectorType,$_.KeyProtectorId,$_.RecoveryPassword } | Out-File -FilePath $RecoveryFile -NoNewLine -Force
    }

    if ($UseActiveDirectory -and $isDomainJoined) {
        $volume = Backup-BitLockerKeyProtector -MountPoint $Drive -KeyProtectorId $recoveryPasswordProtector.KeyProtectorId -ErrorAction Stop -Verbose:$false

        # TODO: test that the recovery password was successfully written to AD
    }

    $status = Get-BitLockerStatus -Drive $Drive

    $needsReboot = $status.Flags -band 0x2 -eq 0x2
    
    if ($Restart -and $needsReboot) {
        Restart-Computer -Force
    }
}
