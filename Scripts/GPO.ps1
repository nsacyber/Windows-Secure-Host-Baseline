#requires -Version 3
Set-StrictMode -Version 3

Function Get-GPOBackupInformation() {
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
    $backupTime = [string]$backupInstNode.BackupTime.'#cdata-section' # parse to a real datetime with ParseExact
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
            Write-Verbose -Message ('Did not update {0}' -f $currentBackupXmlFilePath)
        } 
    } else {
        Write-Verbose -Message ('{0} did not need to be updated' -f $currentBackupXmlFilePath)
    }
}


    