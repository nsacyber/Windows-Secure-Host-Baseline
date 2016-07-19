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
        [Parameter(Position=0, Mandatory=$true, HelpMessage='The path of the GPO backup folder.')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
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
        [Parameter(Position=0, Mandatory=$true, HelpMessage='The path of the current GPO backup folder.')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$CurrentGPOBackupPath,

        [Parameter(Position=1, Mandatory=$true, HelpMessage='The path of the new GPO backup folder.')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
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

    $newGuid = $newBackupInfo.ID.ToString('B').ToUpper()
    Write-Verbose -Message ('New Guid: {0}' -f $newGuid)

    $currentGuid = $currentBackupInfo.ID.ToString('B').ToUpper()
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

Function Get-GPOBackupFolders() {
    <#
    .SYNOPSIS
    Gets folders containing Group Policy Object backups.

    .DESCRIPTION
    Gets folders containing Group Policy Object backups.

    .PARAMETER Path
    A path containing GPO backup folders.

    .EXAMPLE
    Get-GPOBackupFolders -Path '.\Secure-Host-Baseline'
    #>
    [CmdletBinding()] 
    [OutputType([System.IO.DirectoryInfo[]])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='A path containing GPO backup folders.')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path
    )

    return ,[System.IO.DirectoryInfo[]]@(Get-ChildItem -Path $Path -Recurse | Where-Object { $_.PsIsContainer -eq $true } | Where-Object { Test-Path -Path (Join-Path -Path $_.FullName -ChildPath 'bkupInfo.xml') -PathType Leaf} | Where-Object { try { [System.Guid]::Parse($_.Name) | Out-Null; $true } catch { $false } })
}

Function Get-GPODefinitions() {

    [CmdletBinding()] 
    [OutputType([System.IO.DirectoryInfo[]])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='A path containing policy.json files.')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path
    )

    $policyFiles = Get-ChildItem -Path $Path -Recurse | Where-Object { $_.PsIsContainer -eq $false -and $_.Name -eq 'policy.json' }

    $policyDefinitions = New-Object System.Collections.Generic.List[object]

    $policyFiles | ForEach-Object {
       $policyDefinition = Get-Content -Path $_.FullName | ConvertFrom-Json
     
       $gpoPaths = Get-GPOBackupFolders -Path $_.DirectoryName
       $gpoPath = $gpoPaths[0].FullName

       Write-Verbose -Message ('GPO Path: {0}' -f $gpoPath)

       $policyDefinition | Add-Member -MemberType NoteProperty -Name 'PolicyObjectPath' -Value $gpoPath 

       # Resolve-Path will throw an error if the path is wrong (does not exist) which is good
       $gptPath = Resolve-Path -Path (@($_.DirectoryName,$policyDefinition.PolicyTemplatePath,'Group Policy Templates') -join '\')
       $policyDefinition.PolicyTemplatePath = $gptPath

       Write-Verbose -Message ('GPT Path: {0}' -f $gptPath)

       $policyDefinitions.Add($policyDefinition)
    }

    return ,[System.Collections.Generic.List[object]]$policyDefinitions
}

Function Get-Intersection() {
    [CmdletBinding()]
    [OutputType([string[]])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='Left.')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Left,

        [Parameter(Position=0, Mandatory=$true, HelpMessage='Right.')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Right
    )
    #todo: function documentation
    $result = [string[]]@(Compare-Object $Left $Right -PassThru -IncludeEqual -ExcludeDifferent)
    return $result
}

Function Test-IsAdministrator() {
    [CmdletBinding()]
    [OutputType([bool])]
    Param (
        [Parameter(Position=0, Mandatory=$true, HelpMessage='The type of administrator')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Domain', 'Local', IgnoreCase=$true)]
        [string[]]$AdministratorType
    )
    #todo: function documentation
    $currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal -ArgumentList ([System.Security.Principal.WindowsIdentity]::GetCurrent())

    $isAdministrator = $false

    $builtInAdministratorRid = 0x220
    $domainAdministratorsRid = 0x200

    switch ($AdministratorType.ToLower()) {
        'domain' { 
            $isAdministrator = $currentPrincipal.IsInRole($domainAdministratorsRid)
            break 
         }
        'local' { 
            $isAdministrator = $currentPrincipal.IsInRole($builtInAdministratorRid) 
            break 
        }
        default { 
            throw "Unexpected administrator type of $AdministratorType" 
        }
    }

    return $isAdministrator
}

Function Test-IsElevated() {
    [CmdletBinding()]
    [OutputType([bool])]
    Param()
    #todo: function documentation
    #todo: P\Invoke OpenProcessToken, GetTokenInformation with TokenIntegrityLevel instead. TOKEN_GROUP.Groups (SID_AND_ATTRIBUTES) see https://msdn.microsoft.com/en-us/library/bb625963.aspx

    $processInfo = New-Object System.Diagnostics.ProcessStartInfo 
    $processInfo.FileName = 'whoami.exe'
    $processInfo.RedirectStandardError = $true 
    $processInfo.RedirectStandardOutput = $true 
    $processInfo.UseShellExecute = $false 
    $processInfo.CreateNoWindow = $true
    $processInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $processInfo.Arguments = '/all' 
    $process = New-Object System.Diagnostics.Process 
    $process.StartInfo = $processInfo 
    $process.Start() | Out-Null 
    $output = $process.StandardOutput.ReadToEnd() 
    $process.WaitForExit() 

    $highIntegrityLevel = 'S-1-16-12288'

    $isElevated = $output -match $highIntegrityLevel

    return $isElevated
}

Function Test-IsDomainController() {
    [CmdletBinding()]
    [OutputType([bool])]
    Param()
    #todo: function documentation
    $os = Get-WmiObject -Class 'Win32_OperatingSystem' -Filter 'Primary=true' | Select-Object ProductType

    # 1 = workstation, 2 = domain controller, 3 = member server
    return $os.ProductType -eq 2
}

Function Test-IsModuleAvailable() {
    [CmdletBinding()]
    [OutputType([bool])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='The module name.')]
        [ValidateNotNullOrEmpty()]
        [string]$Name    
    )

    $isAvailable = $false

    $error.Clear()
    Import-Module -Name $Name -ErrorAction SilentlyContinue
    $isAvailable = ($error.Count -eq 0)
    $error.Clear()

    return $isAvailable
}

Function Test-IsDomainJoined() {
    [CmdletBinding()]
    [OutputType([bool])]
    Param()
    #todo: function documentation
    $computer = Get-WmiObject -Class 'Win32_ComputerSystem' | Select-Object PartOfDomain

    return $computer.PartOfDomain
}

Function Get-GroupPolicyTemplateFolderPath() {
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='The type of the template folder path to get.')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Domain', 'Local', IgnoreCase=$true)]
        [string]$TemplatePathType
    )
    #todo: function documentation
    # default to using the local template path
    $path = '{0}\PolicyDefinitions' -f $env:SystemRoot

    if (-not(Test-Path -Path $path)) {
        throw "Unable to access policy template path of $path"
    }

    if ('Domain' -eq $TemplatePathType) {
        if(-not(Test-IsDomainJoined)) {
            throw 'Must be joined to a domain'
        }

        # UserDnsDomain only has a value when a user is logged in but this script is only going to be used in an interactive context
        $dnsDomain = $env:UserDnsDomain

        # central store format: \\Fully Qualified Domain Name\SYSVOL\Fully Qualified Domain Name\Policies\PolicyDefinitions\
        # see https://support.microsoft.com/en-us/kb/3087759
        $centralStorePath = '\\{0}\SYSVOL\{1}\Policies\PolicyDefinitions' -f $dnsDomain,$dnsDomain

        # use the central store path if it exists
        if (Test-Path -Path $centralStorePath -PathType Container) {
           $path = $centralStorePath
        }
    }

    return $path
}

Function Import-LocalPolicyObject() {
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='A path to lgpo tool.')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.File]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path,

        [Parameter(Position=1, Mandatory=$true, HelpMessage='A path to the GPO.')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$PolicyPath
    )
    #todo: function documentation
    Start-Process -FilePath $Path -ArgumentList "/g $PolicyPath" -Wait -WindowStyle Hidden # -NoNewWindow
}


Function Import-GroupPolicyObject() {
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='A path to GPO.')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.File]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path
    )
    #todo: function documentation
    Import-Module GroupPolicy

    Import-GPO -Path $Path
}

Function Import-PolicyObject() {
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='A path to GPO.')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.File]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path,

        [Parameter(Position=1, Mandatory=$true, HelpMessage='The types of the policies to apply.')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Domain', 'Local', IgnoreCase=$true)]
        [string]$PolicyType
    )
    #todo: function documentation
    switch ($PolicyType.ToLower()) {
        'domain' { 
            Import-GroupPolicyObject -Path $Path
            break 
         }
        'local' { 
            Import-LocalPolicyObject -Path (Get-ChildItem -Path 'lgpo.exe' -Recurse) -PolicyPath $Path
            break 
        }
        default { 
            throw "Unexpected policy type of $PolicyType" 
        }
    }
}

Function Invoke-ApplySecureHostBaseline() {
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Position=0, Mandatory=$true, HelpMessage='A path to the download SHB package.')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path,

        [Parameter(Position=1, Mandatory=$true, HelpMessage='The names of the policies to apply.')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Adobe Reader', 'AppLocker', 'BitLocker', 'Chrome', 'EMET', 'Internet Explorer', 'Office', 'Windows', 'Windows Firewall', IgnoreCase=$true)]
        [string[]]$PolicyNames,

        [Parameter(Position=2, Mandatory=$true, HelpMessage='The scope of the policies to apply.')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Computer', 'User', IgnoreCase=$true)]
        [string[]]$PolicyScopes,

        [Parameter(Position=3, Mandatory=$true, HelpMessage='The types of the policies to apply.')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Domain', 'Local', IgnoreCase=$true)]
        [string]$PolicyType,

        [Parameter(Position=4, Mandatory=$true, HelpMessage='The types of the policies to apply.')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Audit', 'Enforced', IgnoreCase=$true)]
        [string]$PolicyMode = 'Audit'
    )

    #todo: add 'Certificates' and 'Defender' to PolicyName once those GPOs are added

    #todo: add Prepare-SecureHostBaseline -Path $Path, currently might only need to download LGPO.exe
    #todo: update .gitignore based on Prepare-SecureHostBaseline function

    if(-not(Test-IsAdministrator -AdministratorType $PolicyType)) {
        throw "Must be running as a $PolicyType administrator"
    }

    if(-not(Test-IsElevated)) {
        throw 'Must be running in an elevated prompt'
    }

    if ('Domain' -eq $PolicyType -and -not(Test-IsDomainJoined)) {
        throw 'Must be joined to a domain'
    }

    # technically this could be made to work if it wasn't on a DC but it is much easier to do this from a DC
    # this way we can hopefully guarantee the Group Policy cmdlets will exist
    if ('Domain' -eq $PolicyType -and -not(Test-IsDomainController)) {
        throw 'Must be running on a domain controller'
    }

    # just in case we can't guarentee the Group Policy cmdlets are available, explicitly check for them
    if ('Domain' -eq $PolicyType -and -not(Test-IsModuleAvailable -Name 'GroupPolicy')) {
        throw 'Group Policy cmdlets must be installed'
    }

    # these parens are important, don't remove them
    $policyDefinitions = (Get-GPODefinitions -Path $Path) | Where-Object{ $_.PolicyName -in $PolicyNames -and (@( Get-Intersection -Left ($PolicyScopes) -Right ($_.PolicyScopes)).Count -ge 1) -and $PolicyType -in $_.PolicyTypes -and $PolicyMode -in $_.PolicyModes}

    # get SHB GPO template folders
    #$gptFolders = Get-ChildItem -Path $Path -Recurse | Where-Object { $_.PsIsContainer -and $_.Name -like '*Group Policy Template*' }

    # filter based on $PolicyName
    #$gptNameFolders = $gptFolders | Where-Object { @( Get-Intersection -Left ([string[]]@($_.FullName -split '\\')) $PolicyName ).Count -ne 0 }

    $templateFolderPath = Get-GroupPolicyTemplateFolderPath -TemplatePathType $PolicyType

    #todo: if existing template is different (use file size or hash) than the SHB template, then rename existing template first and then copy the template over
    # use similar rename logic as described https://github.com/iadgov/Secure-Host-Baseline/blob/master/Scripts/GitHub.ps1#L672

    #todo: add domain and local folders in Windows GPO folder


    # Windows Firewall is the only case where the folder is named 'Group Policy Object' instead of 'Group Policy Objects'
    # Get-ChildItem -Path $Path -Recurse | Where-Object { $_.PsIsContainer -and $_.Name -like '*Group Policy Object*' } | ForEach-Object { $_.Parent }
    #$gpoFolders = Get-ChildItem -Path $Path -Recurse | Where-Object { $_.PsIsContainer -and $_.Name -like '*Group Policy Object*' -and $_.Parent -in $Policy }
    #$gpoFolders = Get-GPOBackupFolders -Path $Path | Where-Object  { $_.FullName -match ".*\\$Policy\\.*"} #need to handle policy array
    #$gpoFolders = Get-GPOBackupFolders -Path $Path | Where-Object  { $_.FullName -match ".*\\$Policy\\.*"} # Policy | ForEach { '\',$_,'\' -join '' }
    #$gpoFolders = Get-GPOBackupFolders -Path $Path 

    # get SHB GPO folders based on $PolicyName    
    #$gpoNameFolders = $gpoFolders | Where-Object { @( Get-Intersection -Left ([string[]]@($_.FullName -split '\\')) $PolicyName ).Count -ne 0 }

    # filter out folders based on $PolicyType
    # this is tricky since some GPOs apply to both domain and local. we accomplish this by filter out folders that match the opposite of what we're looking for
    #$typeFolders = $gpoNameFolders | Where-Object { @( Get-Intersection -Left ([string[]]@($_.FullName -split '\\')) @('DomainLocal'.Replace($PolicyType,'')) ).Count -eq 0 }

    # filter out folders based on $PolicyMode
    # 'flip' the PolicyMode value. this allows us to keep folders that don't have the value we're looking for along with the actual value
    # keep all folders that don't contain audit. in effect, remove any folders that contain enforced which is the 'opposite' of audit
    #$modeFolders | Where-Object { @( Get-Intersection -Left ([string[]]@($_.FullName -split '\\')) @('AuditEnforced'.Replace($PolicyMode,'')) ).Count -eq 0 }

    $policyDefinitions | ForEach-Object {
        #todo: backup current GPO based on $Policy and $PolicyType, might be only relevant for Local context

        #todo: for domain context we might want to see if GPO exists first, not sure if that is done by Name or GUID

        #todo: import templates if they haven't been already

        # import GPO based on on $Policy and $PolicyType
        #Import-PolicyObject -Path $_.PolicyObjectPath -PolicyType $PolicyType  
    }
}