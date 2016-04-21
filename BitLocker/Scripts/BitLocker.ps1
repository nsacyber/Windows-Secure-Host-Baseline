#requires -RunAsAdministrator
#requires -version 3
Set-StrictMode -Version 3

Function Start-BitLocker() {
    <#
    .SYNOPSIS
    Starts the BitLocker encryption process for a drive or a set of drives.

    .DESCRIPTION
    Starts the BitLocker encryption process for a drive or a set of drives.

    .PARAMETER Drives
    One or more drive letters to enable BitLocker on.

    .PARAMETER UsePin
    Specifies to use a PIN along with a TPM.

    .PARAMETER Pin
    Specifies the PIN rather than being prompted for it

    .PARAMETER RecoveryPath
    The path of a folder to store recovery password information.

    .PARAMETER UseActiveDirectory
    Specifies to store the recovery password in Active Directory.

    .PARAMETER Restart
    Specifies to restart the system so the BitLocker encryption process can start.

    .EXAMPLE
    Start-BitLocker -Drives $env:SYSTEMDRIVE -RecoveryPath ($env:USERPROFILE,'Desktop' -join '\')

    .EXAMPLE
    Start-BitLocker -Drives $env:SYSTEMDRIVE -RecoveryPath ($env:USERPROFILE,'Desktop' -join '\') -UsePin

    .EXAMPLE
    Start-BitLocker -Drives $env:SYSTEMDRIVE -RecoveryPath ($env:USERPROFILE,'Desktop' -join '\') -UsePin -Pin '12345678'

    .EXAMPLE
    Start-BitLocker -Drives $env:SYSTEMDRIVE -RecoveryPath ($env:USERPROFILE,'Desktop' -join '\') -UseActiveDirectory

    .EXAMPLE
    Start-BitLocker -Drives $env:SYSTEMDRIVE -RecoveryPath ($env:USERPROFILE,'Desktop' -join '\') -UsePin -Pin '12345678' -UseActiveDirectory -Restart
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '', Scope='Function')]
    [CmdletBinding()] 
    [OutputType([System.Version])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='One or more drive letters to enable BitLocker on')]
        [string[]]$Drives,

        [Parameter(Position=1, Mandatory=$false, HelpMessage='Specifies to use a PIN along with a TPM')]
        [switch]$UsePin,

        [Parameter(Position=2, Mandatory=$false, HelpMessage='Specifies the PIN rather than being prompted for it')]
        [System.Security.SecureString]$Pin,

        [Parameter(Position=3, Mandatory=$false, HelpMessage='The path of a folder to store recovery password information')]
        [System.IO.DirectoryInfo]$RecoveryPath,

        [Parameter(Position=4, Mandatory=$false, HelpMessage='Specifies to store the recovery password in Active Directory')]
        [switch]$UseActiveDirectory,

        [Parameter(Position=5, Mandatory=$false, HelpMessage='Specifies to restart the system so the BitLocker encryption process can start')]
        [switch]$Restart 
    )

    $tpm = Get-WmiObject -Class 'Win32_Tpm' -Namespace 'root\CIMV2\Security\MicrosoftTpm'

    if(-not($tpm.IsReady().IsReady)) {
        $readyBitmask = $tpm.IsReadyInformation().Information
        $message = 'TPM is not ready for use by BitLocker. Ensure TPM is enabled, activated, and owned. ReadyInformation bitmask: 0x{0:X8} See https://msdn.microsoft.com/en-us/library/windows/desktop/jj660284(v=vs.85).aspx for more information.' -f $readyBitmask    
        throw $message 
    }

    if (-not(Test-Path -Path $RecoveryPath.FullName -PathType Container)) {
        throw "$RecoveryPath not found"
    }

    $isDomainJoined = (Get-WmiObject -Class 'Win32_ComputerSystem').PartOfDomain

    #if ($UseActiveDirectory -and $isDomainJoined) {
        # TODO: might want to check that the required AD schema is present. Server 2008 and later support it natively. Server 2003 SP1 needs a schema extension but since it is end of life, we won't check
        # https://technet.microsoft.com/en-us/library/dd875529(v=ws.10).aspx "Backing Up BitLocker and TPM Recovery Information to AD DS"
        # https://technet.microsoft.com/en-us/library/cc722309(WS.10).aspx "Append A: Checking BitLocker and TPM Schema Objects"

        #TODO: check if computer object can write to AD. This is only required for backing up the TPM Owner information, NOT the BitLocker recovery password information so may not need to do this
    #}

    $volume = Get-BitLockerVolume -MountPoint $Drives

    if ($volume.ProtectionStatus -eq [Microsoft.BitLocker.Structures.BitLockerVolumeProtectionStatus]::Off) {
        if ($UsePin) {
            if ($Pin.Length -eq 0) {
                $bitlockerPin = Read-Host -AsSecureString -Prompt 'Enter BitLocker PIN'
            } else {
                $bitlockerPin = $Pin            
            }

            $volume = Enable-BitLocker -MountPoint $Drives -PIN $bitlockerPin -TpmAndPinProtector -Verbose:$false # 4>$null

            $bitlockerPin.Dispose()
            $Pin.Dispose()
        } else {
            $volume = Enable-BitLocker -MountPoint $Drives -TpmProtector -Verbose:$false # 4>$null
        }
        
        $volume = Add-BitLockerKeyProtector -MountPoint $Drives -RecoveryPasswordProtector -Verbose:$false # 4>$null
    }

    if($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue) {
        $volume.KeyProtector | ForEach-Object {
            Write-Verbose -Message ('Protector Type: {0} Protector ID: {1} Protector Password: {2}' -f $_.KeyProtectorType,$_.KeyProtectorId,$_.RecoveryPassword)
        }
    }

    $recoveryPasswordProtector = $volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq [Microsoft.BitLocker.Structures.BitLockerVolumeKeyProtectorType]::RecoveryPassword }

    $recoveryFile = '{0}\{1}_bitlocker_{{2}}.txt' -f $RecoveryPath.FullName,$env:COMPUTERNAME,$recoveryPasswordProtector.KeyProtectorId

    $volume.KeyProtector | ForEach-Object { 'Protector Type: {0} Protector ID: {1} Protector Password: {2}' -f $_.KeyProtectorType,$_.KeyProtectorId,$_.RecoveryPassword } | Out-File -FilePath $RecoveryFile -NoNewLine -Force

    if ($UseActiveDirectory -and $isDomainJoined) {
        $volume = Backup-BitLockerKeyProtector -MountPoint $Drives -KeyProtectorId $recoveryPasswordProtector.KeyProtectorId -Verbose:$false

        # TODO: test that the recovery password was successfully written to AD
    }
    
    if ($Restart) {
        Restart-Computer -Force
    }
}