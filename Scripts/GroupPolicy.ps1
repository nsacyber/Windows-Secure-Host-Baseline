#requires -Version 3
Set-StrictMode -Version 3

Function Get-GPOBackupInformation() {
    <#
    .SYNOPSIS
    Gets Group Policy Object backup information.

    .DESCRIPTION
    Gets Group Policy Object backup information by parsing the bkupInfo.xml file from the GPO backup folder.

    .PARAMETER GPOBackupPath
    The path of the GPO backup folder. The path should end with a GUID and a bkupInfo.xml should be inside the folder.

    .EXAMPLE
    Get-GPOBackupInformation -GPOBackupPath '.\{BD6E70EE-4F8E-4BBA-A3C3-F1B715A2A028}'
    #>
    [CmdletBinding()] 
    [OutputType([pscustomobject])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="The path of the GPO backup folder.")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($_)})]
        [string]$GPOBackupPath
    )

    $backupXmlFile = 'bkupInfo.xml'

    $backupXmlFilePath = Join-Path -Path $GPOBackupPath -ChildPath $backupXmlFile 

    if(-not(Test-Path -Path $backupXmlFilePath)) {
        throw '$backupXmlFilePath does not exist'
    }

    $backupXml = [xml](Get-Content -Path $backupXmlFilePath)

    $backupInstNode = $backupXml.BackupInst

    $gpoGuid = [System.Guid]$backupInstNode.GPOGuid.'#cdata-section'
    $gpoDomain = [string]$backupInstNode.GPODomain.'#cdata-section'
    $gpoDomainGuid = [System.Guid]$backupInstNode.GPODomainGuid.'#cdata-section'
    $gpoDC = [string]$backupInstNode.GPODomainController.'#cdata-section'
    $backupTime = [System.DateTime]([System.DateTime]::ParseExact($backupInstNode.BackupTime.'#cdata-section', 'yyyy-MM-ddTHH:mm:ss', [System.Globalization.CultureInfo]::CurrentCulture).ToLocalTime())
    $id = [System.Guid]$backupInstNode.ID.'#cdata-section' # the GUID that the backup folder is name is this GUID
    $comment = [string]$backupInstNode.Comment.'#cdata-section'
    $gpoDisplayName = [string]$backupInstNode.GPODisplayName.'#cdata-section'

    $gpo = [pscustomobject]@{
        Guid = $gpoGuid;
        Domain = $gpoDomain;
        DomainGuid = $gpoDomainGuid;
        DomainContoller = $gpoDC;
        BackupTime = $backupTime;
        ID = $id;
        Comment = $comment;
        DisplayName = $gpoDisplayName
    }

    return $gpo
}

Function Update-GPOBackup() {
    <#
    .SYNOPSIS
    Updates an existing Group Policy Object backup with data from a different GPO backup.

    .DESCRIPTION
    Updates an existing Group Policy Object backup with data from a different GPO backup but keeps the current GPO backup GUID (aka the ID) in the backup metadata.

    .PARAMETER GPOBackupPath
    The path of the GPO backup folder. The path should end with a GUID and a bkupInfo.xml should be inside the folder.

    .EXAMPLE
    Update-GPOBackup -CurrentGPOBackupPath '.\{BD6E70EE-4F8E-4BBA-A3C3-F1B715A2A028}' -NewGPOBackupPath '.\'
    #>
    [CmdletBinding(SupportsShouldProcess=$True)] 
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage="The path of the current GPO backup folder.")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($_)})]
        [string]$CurrentGPOBackupPath,

        [Parameter(Position=1, Mandatory=$true, HelpMessage="The path of the new GPO backup folder.")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($_)})]
        [string]$NewGPOBackupPath
    )

    $backupXmlFile = 'bkupInfo.xml'

    $newBackupXmlFilePath = Join-Path -Path $NewGPOBackupPath -ChildPath $backupXmlFile 

    $currentBackupXmlFilePath = Join-Path -Path $CurrentGPOBackupPath -ChildPath $backupXmlFile 

    if(-not(Test-Path -Path $newBackupXmlFilePath)) {
        throw '$newBackupXmlFilePath does not exist'
    }

    if(-not(Test-Path -Path $currentBackupXmlFilePath)) {
        throw '$currentBackupXmlFilePath does not exist'
    }

    $newBackupInfo = Get-GPOBackupInformation -GPOBackupPath $NewGPOBackupPath

    $currentBackupInfo = Get-GPOBackupInformation -GPOBackupPath $CurrentGPOBackupPath

    $newGuid = $newBackupInfo.ID.ToString("B").ToUpper()
    Write-Verbose -Message ('New Guid: {0}' -f $newGuid)

    $currentGuid = $currentBackupInfo.ID.ToString("B").ToUpper()
    Write-Verbose -Message ('Current Guid: {0}' -f $currentGuid)

    if($newGuid -ne $currentGuid) {
        Remove-Item -Path $CurrentGPOBackupPath -Recurse -Force

        Copy-Item -Path $NewGPOBackupPath\* -Destination $CurrentGPOBackupPath -Container -Force -Recurse

        $xml = Get-Content -Path $currentBackupXmlFilePath

        $updatedXml = $xml.Replace($newGuid, $currentGuid)

        if($xml -ne $updatedXml) {
            Set-Content -Path $currentBackupXmlFilePath -Value $updatedXml -NoNewLine
            Write-Verbose -Message ('Replaced {0} with {1} in {2}' -f $newGuid,$currentGuid,$currentBackupXmlFilePath)
        } else {
            Write-Verbose -Message ('Did not update {0} because {1} was not found in the file' -f $currentBackupXmlFilePath,$newGuid)
        } 
    } else {
        Write-Verbose -Message ('Both GPO backup IDs are the same so {0} was not updated' -f $currentBackupXmlFilePath)
    }
}    