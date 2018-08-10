#requires -Version 3
Set-StrictMode -Version 3

Function Get-GPClientSideExtensions() {
    <#
    .SYNOPSIS
    Gets information about Group Policy Client Side Extensions available on the system.

    .DESCRIPTION
    Gets information about Group Policy Client Side Extensions available on the system.

    .EXAMPLE
    Get-GPClientSideExtensions
    #>
    [CmdletBinding()] 
    [OutputType([System.Collections.Hashtable])]
    Param()

    $cseDefinitions = @{}

    $systemRoot = $env:SystemRoot

    $gptExtPaths = [string[]]@('hklm:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\','hklm:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\')

    $gptExtPaths | ForEach-Object {
        # can't use below code because it skips the registry CSE GUID due to the subkey not having any defined value names (other default, which is empty) under it
        #Get-ChildItem $_ | Get-ItemProperty -Name 'PSChildName','(default)','DisplayName','DllName','ProcessGroupPolicy','ProcessGroupPolicyEx' -ErrorAction SilentlyContinue | ForEach-Object {
            $cseRootPath = $_
            (Get-Item $cseRootPath).GetSubKeyNames() | ForEach-Object {
            
            $cseGuid = $_

            Write-Verbose -Message ('Processing {0}' -f $cseGuid)

            $valueNames = Get-Item ('{0}\{1}' -f $cseRootPath,$cseGuid) | Get-ItemProperty -Name 'PSChildName','(default)','DisplayName','DllName','ProcessGroupPolicy','ProcessGroupPolicyEx' -ErrorAction SilentlyContinue

            $cseName = ''
            $cseDll = ''
                        
            if ($cseGuid -eq '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') {
                $cseName = 'Registry'
            }

            if ($valueNames -ne $null) {
                if ($valueNames.PSObject.Properties.Name -contains '(default)') {
                    $cseName = $valueNames.'(default)'
                }

                # if $cseName -eq '' then use LoadLibrary($cseDll), LoadString($cseDisplayName offset, if it has a value), FreeLibrary

                #$cseDisplayName = ''

                #if ($_.PSObject.Properties.Name -contains 'DisplayName') {
                #   $cseDisplayName = $_.DisplayName
                #}

                $cseProcessName = ''

                if ($valueNames.PSObject.Properties.Name -contains 'ProcessGroupPolicy') {
                    $cseProcessName = $valueNames.ProcessGroupPolicy
                }

                if ($cseName -eq '' -and $cseProcessName -ne '') {
                    $cseName = $cseProcessName
                    $cseName = $cseName.Replace('GroupPolicy','').Replace('Process','')
                }

                $cseProcessNameEx = ''
        
                if ($valueNames.PSObject.Properties.Name -contains 'ProcessGroupPolicyEx') {
                    $cseProcessNameEx = $valueNames.ProcessGroupPolicyEx
                    $cseName = $cseName.Replace('GroupPolicyEx','').Replace('Process','')
                }

                if ($cseName -eq '' -and $cseProcessNameEx -ne '') {
                    $cseName = $cseProcessNameEx
                }

                $cseDll = $valueNames.DllName

                if (-not([System.IO.Path]::IsPathRooted($cseDll))) {
                    $cseDll = '{0}\System32\{1}' -f $systemRoot,$cseDll
                }

                if (-not(Test-Path -Path $cseDll)) {
                    Write-Warning -Message ('{0} does not exist' -f $cseDll)
                }
            }

            $cse = [pscustomobject]@{
                Guid = $cseGuid;
                #DisplayName = $cseDisplayName;
                Name = $cseName;
                Dll = $cseDll;
            }

            if (-not($cseDefinitions.ContainsKey($cseGuid))) {
                $cseDefinitions.Add($cseGuid,$cse)
            }
        }
    }

    return $cseDefinitions
}


Function Get-GPOBackupClientSideExtensions() {
    <#
    .SYNOPSIS
    Gets information about Group Policy Client Side Extensions that are listed as being used in the GPO backup.

    .DESCRIPTION
    Gets information about Group Policy Client Side Extensions that are listed as being used in the GPO backup.

    .EXAMPLE
    Get-GPOBackupClientSideExtensions -Path '.\Secure-Host-Baseline\Windows\Group Policy Objects\Computer\{A2A38432-E322-437F-9975-B7CC7F16F4AA}'
    #>
    [CmdletBinding()] 
    [OutputType([System.Collections.Hashtable])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The path of the GPO backup folder')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path
    )

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    $gpoBackupExtensions = @{}

    $backupXmlFile = 'Backup.xml'

    $backupXmlFilePath = Join-Path -Path $Path -ChildPath $backupXmlFile 

    if(-not(Test-Path -Path $backupXmlFilePath)) {
        throw "$backupXmlFilePath does not exist"
    }

    $backupXml = [xml](Get-Content -Path $backupXmlFilePath)

    # note the extension GUIDs from the backup XML are two different types of extensions:
    # 1. client side extension GUIDs which is what we care about
    # 2. MMC snap-in GUIDs (can be enumerated under hklm:\SOFTWARE\Microsoft\MMC\SnapIns\ and hklm:\SOFTWARE\WOW6432Node\Microsoft\MMC\SnapIns\, FYI some have FX: prepended) which we don't care about
    
    $machineExtensions = [string[]]@()

    if ($backupXml.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.MachineExtensionGuids -is [System.Xml.XmlElement]) {
        $machineExtensions = [string[]]($backupXml.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.MachineExtensionGuids.'#cdata-section'.Replace('[','').Replace(']','').Replace('}{','},{').Split(','))
    }

    $userExtensions = [string[]]@()

    if ($backupXml.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.UserExtensionGuids -is [System.Xml.XmlElement]) {
        $userExtensions = [string[]]($backupXml.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.UserExtensionGuids.'#cdata-section'.Replace('[','').Replace(']','').Replace('}{','},{').Split(','))
    }

    $extensions = Get-GPClientSideExtensions

    # filter out the MMC snap-in GUIDs by only returning the CSE GUIDs
    [string[]]($machineExtensions + $userExtensions) | ForEach-Object {
        if ($extensions.ContainsKey($_)) {
            if (-not($gpoBackupExtensions.ContainsKey($_))) {
                $gpoBackupExtensions.Add($_, $extensions[$_])
            }
        }
    }

    return $gpoBackupExtensions
}


Function Get-GPOBackupInformation() {
    <#
    .SYNOPSIS
    Gets Group Policy Object backup information.

    .DESCRIPTION
    Gets Group Policy Object backup information by parsing the bkupInfo.xml file from the GPO backup folder.

    .PARAMETER Path
    The path of the GPO backup folder. The path should end with a GUID and a bkupInfo.xml should be inside the folder.

    .EXAMPLE
    Get-GPOBackupInformation -Path '.\{BD6E70EE-4F8E-4BBA-A3C3-F1B715A2A028}'
    #>
    [CmdletBinding()] 
    [OutputType([pscustomobject])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The path of the GPO backup folder')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path
    )

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    $backupXmlFile = 'bkupInfo.xml'

    $backupXmlFilePath = Join-Path -Path $Path -ChildPath $backupXmlFile 

    if(-not(Test-Path -Path $backupXmlFilePath)) {
        throw "$backupXmlFilePath does not exist"
    }

    $backupXml = [xml](Get-Content -Path $backupXmlFilePath)

    $backupInstNode = $backupXml.BackupInst

    $gpoGuid = [System.Guid]$backupInstNode.GPOGuid.'#cdata-section'
    $gpoDomain = [string]$backupInstNode.GPODomain.'#cdata-section'
    $gpoDomainGuid = [System.Guid]$backupInstNode.GPODomainGuid.'#cdata-section'
    $gpoDC = [string]$backupInstNode.GPODomainController.'#cdata-section'
    $backupTime = [System.DateTime]([System.DateTime]::ParseExact($backupInstNode.BackupTime.'#cdata-section', 'yyyy-MM-ddTHH:mm:ss', [System.Globalization.CultureInfo]::CurrentCulture).ToLocalTime())
    $id = [System.Guid]$backupInstNode.ID.'#cdata-section' # the GUID that the backup folder is named is this GUID
    $comment = [string]$backupInstNode.Comment.'#cdata-section'
    $gpoDisplayName = [string]$backupInstNode.GPODisplayName.'#cdata-section'

    $gpo = [pscustomobject]@{
        Guid = $gpoGuid;
        Domain = $gpoDomain;
        DomainGuid = $gpoDomainGuid;
        DomainContoller = $gpoDC;
        BackupTime = $backupTime;
        BackupGuid = $id;
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

    .PARAMETER CurrentGPOBackupPath
    The path of the current GPO backup folder. The path should end with a GUID and a bkupInfo.xml should be inside the folder.

    .PARAMETER NewGPOBackupPath
    The path of the new GPO backup folder.

    .EXAMPLE
    Update-GPOBackup -CurrentGPOBackupPath '.\{BD6E70EE-4F8E-4BBA-A3C3-F1B715A2A028}' -NewGPOBackupPath '.\'
    #>
    [CmdletBinding(SupportsShouldProcess=$True)] 
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The path of the current GPO backup folder.')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$CurrentGPOBackupPath,

        [Parameter(Mandatory=$true, HelpMessage='The path of the new GPO backup folder.')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$NewGPOBackupPath
    )

    $CurrentGPOBackupPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CurrentGPOBackupPath)

    $NewGPOBackupPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($NewGPOBackupPath)

    $backupXmlFile = 'bkupInfo.xml'

    $newBackupXmlFilePath = Join-Path -Path $NewGPOBackupPath -ChildPath $backupXmlFile 

    $currentBackupXmlFilePath = Join-Path -Path $CurrentGPOBackupPath -ChildPath $backupXmlFile 

    if(-not(Test-Path -Path $newBackupXmlFilePath)) {
        throw "$newBackupXmlFilePath does not exist"
    }

    if(-not(Test-Path -Path $currentBackupXmlFilePath)) {
        throw "$currentBackupXmlFilePath does not exist"
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

Function Test-IsGuid() {
    <#
    .SYNOPSIS
    Tests if the value is a GUID.

    .DESCRIPTION
    Tests if the value is a GUID.

    .PARAMETER Value
    A value to test.

    .EXAMPLE
    Test-IsGuid -Value '{AC662460-6494-4818-A303-FADC513B9876}'
    #>
    [CmdletBinding()] 
    [OutputType([System.IO.DirectoryInfo[]])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='A value to test')]
        [ValidateNotNullOrEmpty()]
        [string]$Value
    )

    $isGuid = $false;

    try { 
        [System.Guid]::Parse($Value) | Out-Null
        $isGuid = $true 
    } catch { } 

    return $isGuid
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
        [Parameter(Mandatory=$true, HelpMessage='A path containing GPO backup folders.')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path
    )

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    return ,[System.IO.DirectoryInfo[]]@(Get-ChildItem -Path $Path -Recurse | Where-Object { $_.PsIsContainer -eq $true } | Where-Object { Test-Path -Path (Join-Path -Path $_.FullName -ChildPath 'bkupInfo.xml') -PathType Leaf} | Where-Object { (Test-IsGuid -Value ($_.Name)) -eq $true })
}

Function Test-IsGPOBackupFolder() {
    <#
    .SYNOPSIS
    Tests if a path is a Group Policy Object backup folder.

    .DESCRIPTION
    Tests if a path is a Group Policy Object backup folder.

    .PARAMETER Path
    A path of a GPO backup folder.

    .EXAMPLE
    Test-IsGPOBackupFolder -Path '.\Secure-Host-Baseline\Windows\Group Policy Objects\Computer\{AC662460-6494-4818-A303-FADC513B9876}'
    #>
    [CmdletBinding()] 
    [OutputType([bool])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='A path of a GPO backup folders.')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path
    )

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    $folder = [System.IO.DirectoryInfo[]]$Path

    $backupFiles = [System.IO.FileInfo[]]@(Get-ChildItem -Path $Path | Where-Object { $_.Name -eq 'bkupInfo.xml' })

    return ($backupFiles.Count -eq 1) -and (Test-IsGuid -Value ($folder.Name))
}

Function Get-GPODefinitions() {
    <#
    .SYNOPSIS
    Gets the definitions of the Group Policy Objects.

    .DESCRIPTION
    Gets the definitions of the Group Policy Objects based on policy.json files that describe them.

    .PARAMETER Path
    A path the contains policy.json files.

    .EXAMPLE
    Get-GPODefinitions -Path '.\Secure-Host-Baseline\'
    #>
    [CmdletBinding()] 
    [OutputType([System.Collections.Generic.List[object]])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='A path containing policy.json files.')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path
    )

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    $policyFiles = [System.IO.FileInfo[]]@(Get-ChildItem -Path $Path -Recurse | Where-Object { $_.PsIsContainer -eq $false -and $_.Name -eq 'policy.json' })

    $policyDefinitions = New-Object System.Collections.Generic.List[object]

    $policyFiles | ForEach-Object {
        $policyDefinition = Get-Content -Path $_.FullName -Raw | ConvertFrom-Json
     
        $gpoPaths = Get-GPOBackupFolders -Path $_.DirectoryName
        $gpoPath = $gpoPaths[0].FullName

        $policyDefinition | Add-Member -MemberType NoteProperty -Name 'PolicyObjectPath' -Value $gpoPath 

        Write-Verbose -Message ('GPO Path: {0}' -f $gpoPath)

        # Resolve-Path will throw an error if the path is wrong (does not exist) which is the desired behavior
        $gptPath = Resolve-Path -Path (@($_.DirectoryName,$policyDefinition.PolicyTemplatePath,'Group Policy Templates') -join [System.IO.Path]::DirectorySeparatorChar)
        $policyDefinition.PolicyTemplatePath = $gptPath

        Write-Verbose -Message ('GPT Path: {0}' -f $gptPath)

        $gpoInformation = Get-GPOBackupInformation -Path $gpoPath

        $policyDefinition | Add-Member -MemberType NoteProperty -Name 'PolicyInformation' -Value $gpoInformation

        $policyDefinitions.Add($policyDefinition)
    }

    return ,[System.Collections.Generic.List[object]]$policyDefinitions
}

Function Get-Intersection() {
    <#
    .SYNOPSIS
    Gets the set intersection of two string arrays.

    .DESCRIPTION
    Gets the set intersection of two string arrays.

    .PARAMETER ReferenceObject
    An array of string objects used as a reference for comparison.
    
    .PARAMETER DifferenceObject
    An array of string objects compared to the reference objects. 

    .EXAMPLE
    Get-Intersection -ReferenceObject 'test1','test2' -DifferenceObject 'test1','test3'
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='An array of string objects used as a reference for comparison')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ReferenceObject,

        [Parameter(Mandatory=$true, HelpMessage='An array of string objects compared to the reference objects')]
        [ValidateNotNullOrEmpty()]
        [string[]]$DifferenceObject
    )

    $result = [string[]]@(Compare-Object $ReferenceObject $DifferenceObject -PassThru -IncludeEqual -ExcludeDifferent)
    return ,$result
}

Function Test-IsModuleAvailable() {
    <#
    .SYNOPSIS
    Tests if a PowerShell module is available on a system.

    .DESCRIPTION
    Tests if a PowerShell module is available on a system.

    .PARAMETER Name
    The module name.

    .EXAMPLE
    Test-IsModuleAvailable -Name 'ActiveDirectory'
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The module name')]
        [ValidateNotNullOrEmpty()]
        [string]$Name    
    )

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    $isAvailable = $false

    $error.Clear()
    Import-Module -Name $Name -ErrorAction SilentlyContinue
    $isAvailable = ($error.Count -eq 0)
    $error.Clear()

    return $isAvailable
}

Function Get-DomainSecurityIdentifier() {
<#
    .SYNOPSIS
    Gets the domain specific security identifier (SID) value. 

    .DESCRIPTION
    Gets the domain specific security identifier (SID) value. 

    .EXAMPLE
    Get-DomainSecurityIdentifier
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param()

    #$context = ([adsi]'LDAP://RootDSE').defaultNamingContext
    #$domainSidBytes = ([adsi]"LDAP://$context").Properties['objectsid'].Value
    #$domainSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $domainSidBytes,0 
    #return $domainSid.Value

    if (-not(Test-IsModuleAvailable -Name 'ActiveDirectory')) {
        throw 'ActiveDirectory module not available'
    }

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    Import-Module ActiveDirectory

    return (Get-ADDomain).DomainSid.Value
}

Function Test-IsAdministrator() {
    <#
    .SYNOPSIS
    Tests if current user is an administrator. 

    .DESCRIPTION
    Tests if current user is an administrator.

    .PARAMETER AdministratorType
    The type of administrator to test for.

    .EXAMPLE
    Test-IsAdministrator

    .EXAMPLE
    Test-IsAdministrator -AdministratorType 'Domain'

    .EXAMPLE
    Test-IsAdministrator -AdministratorType 'Local'
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    Param (
        [Parameter(Mandatory=$false, HelpMessage='The type of administrator to test for')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Domain', 'Local', IgnoreCase=$true)]
        [string]$AdministratorType
    )

    $currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal -ArgumentList ([System.Security.Principal.WindowsIdentity]::GetCurrent())

    $isAdministrator = $false

    $builtInAdministratorSid = [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544'
    $domainAdministratorsRid = 0x200
    
    if ('Domain' -eq $AdministratorType -or (Test-IsDomainJoined)) {
        $domainSid = Get-DomainSecurityIdentifier
        $domainAdministratorsSid = [System.Security.Principal.SecurityIdentifier]('{0}-{1}' -f $domainSid,$domainAdministratorsRid)
    }

    # using a SID for IsInRole has a number of advantages: 
    # 1. using RID  method didn't work when on a domain and using the domain admin RID 
    # 2. don't have to worry about name ambiguity 
    # 3. don't have to prepend names with domain name 
    # 4. documentation says its more efficient
    # https://msdn.microsoft.com/en-us/library/86wd8zba(v=vs.110).aspx

    switch ($AdministratorType.ToLower()) {
        'domain' { 
            $isAdministrator = $currentPrincipal.IsInRole($domainAdministratorsSid)
            break 
         }
        'local' { 
            $isAdministrator = $currentPrincipal.IsInRole($builtInAdministratorSid) 
            break 
        }
        '' {
            $isAdministrator = $currentPrincipal.IsInRole($builtInAdministratorSid) -or $currentPrincipal.IsInRole($domainAdministratorsSid) 
            break
        }
        default { 
            throw "Unexpected administrator type of $AdministratorType" 
        }
    }

    return $isAdministrator
}

Function Invoke-Process() {
    <#
    .SYNOPSIS
    Executes a process. 

    .DESCRIPTION
    Executes a process and waits for it to exit.

    .PARAMETER Path
    The path of the file to execute.

    .PARAMETER Arguments
    THe arguments to pass to the executable. Arguments with spaces in them are automatically quoted.

    .PARAMETER PassThru
    Return the results as an object.

    .EXAMPLE
    Invoke-Process -Path 'C:\Windows\System32\whoami.exe'

    .EXAMPLE
    Invoke-Process -Path 'C:\Windows\System32\whoami.exe' -Arguments '/groups'

    .EXAMPLE
    Invoke-Process -Path 'C:\Windows\System32\whoami.exe' -Arguments '/groups' -PassThru

    .EXAMPLE
    Invoke-Process -Path 'lgpo.exe' -Arguments '/g','C:\path to gpo folder' -PassThru
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The path of the file to execute')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
        [ValidateScript({[System.IO.File]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path,

        [Parameter(Mandatory=$false, HelpMessage='The arguments to pass to the executable')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Arguments,

        [Parameter(Mandatory=$false, HelpMessage='Return the results as an object')]
        [switch]$PassThru
    )

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    $parameters = $PSBoundParameters

    $escapedArguments = ''

    if ($parameters.ContainsKey('Arguments')) {
        $Arguments | ForEach-Object {
            if ($_.Contains(' ')) {
                $escapedArguments = $escapedArguments,("`"{0}`"" -f $_) -join ' '
            } else {
                $escapedArguments = $escapedArguments,$_ -join ' '
            }
        }
    }

    $processInfo = New-Object System.Diagnostics.ProcessStartInfo 
    $processInfo.FileName = $Path
    $processInfo.RedirectStandardError = $true 
    $processInfo.RedirectStandardOutput = $true 
    $processInfo.UseShellExecute = $false 
    $processInfo.CreateNoWindow = $true
    $processInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $processInfo.Arguments = $escapedArguments.Trim()
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processInfo 
    $process.Start() | Out-Null 
    $output = $process.StandardOutput.ReadToEnd() 
    $process.WaitForExit()
    
    $exitCode = $process.ExitCode

    if($PassThru) {
        return [pscustomobject]@{
            'ExitCode' = $exitCode;
            'Output' = $output;
            'Process' = $process;
        }
    }
}

Function Test-IsElevated() {
    <#
    .SYNOPSIS
    Tests if the current user is running in an elevated context.

    .DESCRIPTION
    Tests if the current user is running in an elevated context.

    .EXAMPLE
    Test-IsElevated
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    Param()

    #todo: P\Invoke OpenProcessToken, GetTokenInformation with TokenIntegrityLevel instead. TOKEN_GROUP.Groups (SID_AND_ATTRIBUTES) see https://msdn.microsoft.com/en-us/library/bb625963.aspx

    $path = $env:SYSTEMROOT,'System32','whoami.exe' -join [System.IO.Path]::DirectorySeparatorChar

    $result = Invoke-Process -Path $path -Arguments '/groups' -PassThru

    $highIntegrityLevelSid = 'S-1-16-12288'

    $isElevated = ($result.Output) -match $highIntegrityLevelSid

    return $isElevated
}

Function Test-IsDomainController() {
    <#
    .SYNOPSIS
    Tests if the system is a domain controller.

    .DESCRIPTION
    Tests if the system is a domain controller.

    .EXAMPLE
     Test-IsDomainController
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    Param()

    $os = Get-WmiObject -Class 'Win32_OperatingSystem' -Filter 'Primary=true' | Select-Object ProductType

    # 1 = workstation, 2 = domain controller, 3 = member server
    return $os.ProductType -eq 2
}

Function Test-IsDomainJoined() {
    <#
    .SYNOPSIS
    Tests if a system is joined to a domain. 

    .DESCRIPTION
    Tests if a system is joined to a domain. 

    .EXAMPLE
    Test-IsDomainJoined
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    Param()

    $computer = Get-WmiObject -Class 'Win32_ComputerSystem' | Select-Object PartOfDomain

    return $computer.PartOfDomain
}

Function Get-GroupPolicyTemplateFolderPath() {
    <#
    .SYNOPSIS
    Gets the path where Group Policy templates are stored.

    .DESCRIPTION
    Gets the path where Group Policy templates are stored. For a domain joined system, it will check if a Group Policy Central Store exists.

    .PARAMETER TemplatePathType
    The type of the template folder path to get.

    .EXAMPLE
    Get-GroupPolicyTemplateFolderPath

    .EXAMPLE
    Get-GroupPolicyTemplateFolderPath -TemplatePathType 'Domain'

    .EXAMPLE
    Get-GroupPolicyTemplateFolderPath -TemplatePathType 'Local'
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory=$false, HelpMessage='The type of the template folder path to get.')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Domain', 'Local', IgnoreCase=$true)]
        [string]$TemplatePathType
    )

    # default to using the local template path
    $path = '{0}\PolicyDefinitions' -f $env:SystemRoot

    if (-not(Test-Path -Path $path)) {
        throw "Unable to access policy template path of $path"
    }

    if ('Domain' -eq $TemplatePathType -and -not(Test-IsDomainJoined)) {
        throw 'Must be joined to a domain'
    }

    if (('Domain' -eq $TemplatePathType) -or (Test-IsDomainJoined)) {
        # $env:UserDnsDomain only has a value when a user is logged
        # NV Domain registry value contains the computer's primary DNS suffix. The Domain registry value contains the computer's primary DNS domain. 
        # NV Domain is the domain the system is joined to

        $dnsDomain = Get-ItemProperty -Path hklm:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters | Select-Object -ExpandProperty 'NV Domain'

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
    <#
    .SYNOPSIS
    Imports a local Group Policy object.

    .DESCRIPTION
    Imports a local Group Policy object.

    .PARAMETER Path
    The path of the GPO to import.

    .PARAMETER ToolPath
    The path to the LGPO tool.

    .EXAMPLE
    Import-LocalPolicyObject -Path '.\Secure-Host-Baseline\Windows\Group Policy Objects\Computer\{AC662460-6494-4818-A303-FADC513B9876}' -ToolPath '.\Secure-Host-Baseline\LGPO\lgpo.exe'
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The path of the GPO to import')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path,

        [Parameter(Mandatory=$true, HelpMessage='The path to the LGPO tool')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({([System.IO.FileInfo]$_).Name -eq 'lgpo.exe'})]
        [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
        [ValidateScript({[System.IO.File]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$ToolPath
    )

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    $ToolPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ToolPath)

    if (-not(Test-IsGPOBackupFolder -Path $Path)) {
        throw "$Path is not a Group Policy backup folder path"
    }

    $extensions = Get-GPOBackupClientSideExtensions -Path $Path
    $extensionArguments = [string[]]@()

    $extensions.Keys | ForEach-Object { 
        $extensionArguments += '/e'
        $extensionArguments += $_
    }

    $arguments = [string[]]@([string[]]@('/g',$Path) + $extensionArguments)

    $result = Invoke-Process -Path $ToolPath -Arguments $arguments -PassThru
    
    $exitCode = $result.ExitCode
    $output = $result.Output

    if (0 -ne $exitCode) {
        Write-Warning -Message 'LGPO import might have not executed correctly'
        Write-Warning -Message ('Exit code: {0}' -f $exitCode)

        if ($output -ne $null -and $output -ne '') {
            Write-Warning -Message ('Output: {0}{1}' -f [System.Environment]::NewLine,$output)
        }
    }
}

Function Test-DomainPolicyExists() {
    <#
    .SYNOPSIS
    Checks if a domain Group Policy object exists.

    .DESCRIPTION
    Checks if a domain Group Policy object exists by policy name or policy GUID.

    .PARAMETER Guid
    The GUID of the domain policy object.

    .PARAMETER Name
    The display name of the domain policy object.

    .EXAMPLE
    Test-DomainPolicyExists -Guid '{343866EE-1828-4BB7-B706-4989C511FEE9}'

    .EXAMPLE
    Test-DomainPolicyExists -Name 'Adobe Reader DC'
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$false, HelpMessage='The GUID of the domain policy object')]
        [ValidateNotNullOrEmpty()]
        [System.Guid]$Guid,

        [Parameter(Mandatory=$false, HelpMessage='The display name of the domain policy object')]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    $parameters = $PSBoundParameters

    if (-not($parameters.ContainsKey('Guid')) -and -not($parameters.ContainsKey('Name'))) {
        throw 'Must specified a domain policy name or domain policy guid'
    }

    $gpo = $null

    if ($parameters.ContainsKey('Guid')) {
        $gpo = Get-GPO -Guid $guid -ErrorAction SilentlyContinue
    }

    if ($parameters.ContainsKey('Name')) {
        $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    }

    return $null -ne $gpo
}

Function Import-DomainPolicyObject() {
   <#
    .SYNOPSIS
    Imports a domain Group Policy object.

    .DESCRIPTION
    Imports a domain Group Policy object.

    .PARAMETER Path
    The path of the Group Policy object to import.

    .PARAMETER Name
    The display name of the Group Policy object.

    .PARAMETER BackupGuid
    The GUID of the Group Policy object backup.

    .EXAMPLE
    Import-DomainPolicyObject -Path '.\Secure-Host-Baseline\Windows\Group Policy Objects\Computer\' -Name 'DoD Windows 10 STIG - Computer' -BackupGuid '{AC662460-6494-4818-A303-FADC513B9876}'
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The path of the Group Policy object to import')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path,

        [Parameter(Mandatory=$true, HelpMessage='The display name of the Group Policy object')]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory=$true, HelpMessage='The GUID of the Group Policy object backup')]
        [ValidateNotNullOrEmpty()]
        [System.Guid]$BackupGuid
    )

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    if (-not(Test-IsModuleAvailable -Name 'GroupPolicy')) {
        throw 'GroupPolicy module not available on this system'
    }

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    Import-Module GroupPolicy

    # Import-GPO works differently than LGPO, they expect a different folder (Import-GPO needs parent folder of GPO, LGPO needs actual folder of GPO)
    #if (-not(Test-IsGPOBackupFolder -Path $Path)) {
    #    throw "$Path is not a Group Policy backup folder path"
    #}


    # this does not work even through the documentation says it should: Import-GPO -Path $Path -BackupId $BackupGuid -TargetGuid $Guid -CreateIfNeeded
    # it throws an error of 'Import-GPO : A GPO with ID {0} was not found in the {1} domain.'
    # it obviously wants the GUID to exist already and does not create the GPO if it does not exist
    Import-GPO -Path $Path -BackupId $BackupGuid -TargetName $Name -CreateIfNeeded | Out-Null
}

Function Import-PolicyObject() {
   <#
    .SYNOPSIS
    Imports a Group Policy object.

    .DESCRIPTION
    Imports a Group Policy object.

    .PARAMETER Path
    The path of the Group Policy object to import.

    .PARAMETER PolicyType
    The type of the policy to import.

    .PARAMETER ToolPath
    The path to the LGPO tool.

    .PARAMETER Name
    The display name of the Group Policy object.

    .PARAMETER BackupGuid
    The GUID of the Group Policy object backup.

    .EXAMPLE
    Import-PolicyObject -Path '.\Secure-Host-Baseline\Windows\Group Policy Objects\Computer\' -Name 'DoD Windows 10 STIG - Computer' -BackupGuid '{AC662460-6494-4818-A303-FADC513B9876}'

    .EXAMPLE
    Import-PolicyObject -Path '.\Secure-Host-Baseline\Windows\Group Policy Objects\Computer\{AC662460-6494-4818-A303-FADC513B9876}' -ToolPath '.\Secure-Host-Baseline\LGPO\lgpo.exe'
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The path of the Group Policy Object to import')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path,

        [Parameter(Mandatory=$false, HelpMessage='The type of the policy to import')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Domain', 'Local', IgnoreCase=$true)]
        [string]$PolicyType,

        [Parameter(Mandatory=$false, HelpMessage='The path to the LGPO tool')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({([System.IO.FileInfo]$_).Name -eq 'lgpo.exe'})]
        [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
        [ValidateScript({[System.IO.File]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$ToolPath,

        [Parameter(Mandatory=$false, HelpMessage='The display name of the Group Policy object')]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory=$false, HelpMessage='The GUID of the Group Policy object backup')]
        [ValidateNotNullOrEmpty()]
        [System.Guid]$BackupGuid
    )

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    $parameters = $PSBoundParameters

    # Import-GPO works differently than LGPO, they expect a different folder (Import-GPO needs parent folder of GPO, LGPO needs actual folder of GPO)
    #if (-not(Test-IsGPOBackupFolder -Path $Path)) {
    #    throw "$Path is not a Group Policy backup folder path"
    #}

    if (('Local' -eq $PolicyType -or -not(Test-IsDomainJoined)) -and -not($parameters.ContainsKey('ToolPath'))) {
        throw 'Must specify the path of the LPGO executable'
    }

    if ('Domain' -eq $PolicyType -and -not($parameters.ContainsKey('Name'))) {
        throw 'Must specify the domain policy object display name'
    }

    if ('Domain' -eq $PolicyType -and -not($parameters.ContainsKey('BackupGuid'))) {
        throw 'Must specify the domain policy object backup Guid'
    }

    if ('Domain' -eq $PolicyType -and -not($parameters.ContainsKey('Name'))) {
        throw 'Must specify the display name of the domain policy object'
    }

    switch ($PolicyType.ToLower()) {
        'domain' { 
            Import-DomainPolicyObject -Path $Path -BackupGuid $BackupGuid -Name $Name
            break 
         }
        'local' {
            $ToolPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ToolPath)
            Import-LocalPolicyObject -Path $Path -ToolPath $ToolPath
            break 
        }
        '' {
            if (Test-IsDomainJoined) {
                Import-DomainPolicyObject -Path $Path -BackupGuid $BackupGuid -Name $Name
            } else {
                $ToolPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ToolPath)
                Import-LocalPolicyObject -Path $Path -ToolPath $ToolPath
            }
            break
        }
        default { 
            throw "Unexpected policy type of $PolicyType" 
        }
    }
}

Function New-LocalPolicyObjectBackup() {
    <#
    .SYNOPSIS
    Creates a backup of the current local Group Policy.

    .DESCRIPTION
    Creates a backup of the current local Group Policy.

    .PARAMETER Path
    The path to save the backup to.

    .PARAMETER ToolPath
    The path to the LGPO tool.

    .EXAMPLE
    New-LocalPolicyObjectBackup -Path '.\LocalPolicyBackup' -ToolPath '.\Secure-Host-Baseline\LGPO\lgpo.exe'
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The path to save the backup to')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path,

        [Parameter(Mandatory=$true, HelpMessage='The path to LGPO tool')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({([System.IO.FileInfo]$_).Name -eq 'lgpo.exe'})]
        [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
        [ValidateScript({[System.IO.File]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$ToolPath
    )

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    $ToolPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ToolPath)

    $date = Get-Date
    $policyName = 'Local Group Policy Backup for {0} - {1:MM/dd/yyyy HH:mm:ss}' -f $env:COMPUTERNAME,$date

    $result = Invoke-Process -Path $ToolPath -Arguments '/b',$Path,'/n',$policyName -PassThru

    $exitCode = $result.ExitCode
    $output = $result.Output

    if (0 -ne $exitCode) {
        Write-Warning -Message 'LGPO backup might have not executed correctly'
        Write-Warning -Message ('{Exit code: {1}' -f $exitCode)

        if ($output -ne $null -and $output -ne '') {
            Write-Warning -Message ('Output: {0}{1}' -f [System.Environment]::NewLine,$output)
        }
    }
}

Function New-DomainPolicyObjectBackup() {
   <#
    .SYNOPSIS
    Creates a backup of the specified domain Group Policy object.

    .DESCRIPTION
    Creates a backup of the specified domain Group Policy object.

    .PARAMETER Path
    The path to save the backup to.

    .PARAMETER Name
    The display name of the Group Policy object.

    .EXAMPLE
    Import-DomainPolicyObject -Path '.\DomainPolicy\Backup\Windows\Computer' -Name 'DoD Windows 10 STIG - Computer'
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The path to save the backup to')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path,

        [Parameter(Mandatory=$true, HelpMessage='The display name of the Group Policy object')]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    if (-not(Test-IsModuleAvailable -Name 'GroupPolicy')) {
        throw 'GroupPolicy module not available on this system'
    }

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    Import-Module GroupPolicy

    # -Name is DisplayName of GPO. it is not guaranteed to be unique
    # -Guid is the unique ID that is only displayed in Details tab of Group Policy Managementy snap-in 
    # -All is overkill for our needs
    # Import-GPO has a bug where -CreateIfNeeded does not work for a non-existent -TargetGuid value
    # this bug forces the use of -Name instead of -Guid for Backup-GPO to be consistent with Import-GPO
    if (Test-DomainPolicyExists -Name $Name) {
        Backup-GPO -Path $Path -Name $Name | Out-Null
    }
}

Function New-PolicyObjectBackup() {
   <#
    .SYNOPSIS
    Creates a backup of a Group Policy object.

    .DESCRIPTION
    Creates a backup of a Group Policy object.

    .PARAMETER Path
    The path to save the backup to.

    .PARAMETER PolicyType
    The type of the policy to backup.

    .PARAMETER ToolPath
    The path to the LGPO tool.

    .PARAMETER Name
    The display name of the Group Policy object.

    .EXAMPLE
    New-PolicyObjectBackup -Path '.\Secure-Host-Baseline\Windows\Group Policy Objects\Computer\{AC662460-6494-4818-A303-FADC513B9876}'

    .EXAMPLE
    New-PolicyObjectBackup -Path '.\Secure-Host-Baseline\Windows\Group Policy Objects\Computer\{AC662460-6494-4818-A303-FADC513B9876}' -ToolPath '.\Secure-Host-Baseline\LGPO\lgpo.exe'
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The path to save the backup to')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path,

        [Parameter(Mandatory=$false, HelpMessage='The type of the policy to backup')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Domain', 'Local', IgnoreCase=$true)]
        [string]$PolicyType,

        [Parameter(Mandatory=$false, HelpMessage='The path to the LGPO tool')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({([System.IO.FileInfo]$_).Name -eq 'lgpo.exe'})]
        [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
        [ValidateScript({[System.IO.File]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$ToolPath,

        [Parameter(Mandatory=$false, HelpMessage='The display name of the Group Policy object')]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    $parameters = $PSBoundParameters

    if (('Local' -eq $PolicyType -or -not(Test-IsDomainJoined)) -and -not($parameters.ContainsKey('ToolPath'))) {
        throw 'Must specify the path of the LPGO executable'
    }

    if ('Domain' -eq $PolicyType -and -not($parameters.ContainsKey('Name'))) {
        throw 'Must specify the domain policy object display name'
    }

    switch ($PolicyType.ToLower()) {
        'domain' { 
            New-DomainPolicyObjectBackup -Path $Path -Name $Name
            break 
         }
        'local' { 
            $ToolPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ToolPath)
            New-LocalPolicyObjectBackup -Path $Path -ToolPath $ToolPath
            break 
        }
        '' {
            if (Test-IsDomainJoined) {
                New-DomainPolicyObjectBackup -Path $Path -Name $Name
            } else {
                $ToolPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ToolPath)
                New-LocalPolicyObjectBackup -Path $Path -ToolPath $ToolPath 
            }
            break
        }
        default { 
            throw "Unexpected policy type of $PolicyType" 
        }
    }
}

Function Get-FipsFileHash() {
   <#
    .SYNOPSIS
    Gets a file hash using FIPS compliant hash algorithms.

    .DESCRIPTION
    Gets a file hash using FIPS compliant hash algorithms. Requires .Net 3.5 is installed.

    .PARAMETER Path
    The path of the file to hash.

    .PARAMETER Algorithm
    The name of the algorithm.

    .EXAMPLE
    Get-FipsFileHash -Path 'C:\Windows\regedit.exe' -Algorithm 'SHA1'
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The path of the file to hash')]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory=$true, HelpMessage='The name of the algorithm')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('SHA1','SHA256','SHA384','SHA512',IgnoreCase=$true)]
        [string]$Algorithm
    )

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    $provider = $null

    switch($Algorithm.ToLower()){
        'sha1' { $provider = New-Object System.Security.Cryptography.SHA1Cng ; break }
        'sha256' { $provider = New-Object System.Security.Cryptography.SHA256Cng ; break }
        'sha384' { $provider = New-Object System.Security.Cryptography.SHA384Cng ; break }
        'sha512' { $provider = New-Object System.Security.Cryptography.SHA512Cng ; break }
        default { throw "$Algorithm not supported" }
    }

    if (-not(Test-Path -Path $Path -PathType Leaf)) {
        throw "$Path not found"
    }

    [System.IO.FileStream]$stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
    $bytes = $provider.ComputeHash($stream)

    $hash = ''
    $bytes | ForEach-Object { $hash = ($hash,('{0:X2}' -f $_)) -join '' }

    $stream.Dispose()
    [System.IDisposable].GetMethod('Dispose').Invoke($provider,@()) | Out-Null

    return $hash
}

Function Test-FilesEqual() {
   <#
    .SYNOPSIS
    Tests if two files are equal.

    .DESCRIPTION
    Tests is two files are equa by comparing the hash of their content.

    .PARAMETER ReferenceFile
    The reference file.

    .PARAMETER DifferenceFile
    The other file to test the reference against.

    .EXAMPLE
    Test-FilesEqual -ReferenceFile 'file1.txt' -DifferenceFile 'file2.txt'
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The reference file')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
        [ValidateScript({[System.IO.File]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$ReferenceFile,

        [Parameter(Mandatory=$true, HelpMessage='The other file to test the reference against')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
        [ValidateScript({[System.IO.File]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$DifferenceFile
    )

    $isEqual = $false

    if ($PSVersionTable.PSVersion -ge ([System.Version]'5.0')) {
        $isEqual = (Get-FileHash -Path $ReferenceFile -Algorithm SHA256).Hash -eq (Get-FileHash -Path $DifferenceFile -Algorithm SHA256).Hash
    } else {
        # PowerShell 4.0 Get-FileHash doesn't work when FIPS is enabled
        # PowerShell 3.0 and earlier do not have Get-FileHash

        $isEqual = (Get-FipsFileHash -Path $ReferenceFile -Algorithm SHA256) -eq (Get-FipsFileHash -Path $DifferenceFile -Algorithm SHA256)
    }

    return $isEqual
}

Function Import-LocalCertificate() {
   <#
    .SYNOPSIS
    Imports certificates into a local certificate store.

    .DESCRIPTION
    Imports certificates into a local certificate store.

    .PARAMETER Path
    The path to the folder containing the downloaded and extracted GitHub SHB repository.

    .PARAMETER Store
    The name of the certificate store.

    .EXAMPLE
    Import-LocalCertificate -Path '.\Secure-Host-Baseline' -Store 'Root'

    .EXAMPLE
    Import-LocalCertificate -Path '.\Secure-Host-Baseline' -Store 'Intermediate'
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='A path to the downloaded SHB package')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path,

        [Parameter(Mandatory=$true, HelpMessage='The name of the certificate store')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Root','Intermediate', IgnoreCase = $true)]
        [string]$Store
    )

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    $certSearchPath = ''
    $certStorePath = ''

    switch($Store.ToLower()) {
        'root' { $certSearchPath = 'Certificates\Root' ; $certStorePath = 'cert:\LocalMachine\Root'; break }
        'intermediate' { $certSearchPath = 'Certificates\Intermediate' ; $certStorePath = 'cert:\LocalMachine\CA' ; break }
        default { throw "Unsupported certificate store name of $Store" }
    }

    $certificateFiles = @(Get-ChildItem -Path $Path -Recurse -Include *.cer | Where-Object { $_.FullName.Contains($certSearchPath) -and $_.PsIsContainer -eq $false})

    $certificateFiles | ForEach-Object {
        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $_.FullName

        # test if certificate exists so we don't try to import it again. you will get access denied errors
        if ((Get-ChildItem -Path $certStorePath | Where-Object { $_.Thumbprint -eq $certificate.Thumbprint }) -eq $null ) {
            Import-Certificate -FilePath $_.FullName -CertStoreLocation $certStorePath | Out-Null
        }
    }
}

Function Invoke-ApplySecureHostBaseline() {
   <#
    .SYNOPSIS
    Applies the Secure Host Baseline.

    .DESCRIPTION
    Applies the Secure Host Baseline Group Policy Objects. In the domain case, the GPOs are merely imported into the domain. In the local/standalone system case, the GPOs are applied to the system.

    .PARAMETER Path
    Required. The path to the folder containing the downloaded and extracted GitHub SHB repository.

    .PARAMETER PolicyNames
    Required. The names of the policies to apply. Can be 1 or more policy names. Available names: 'Adobe Reader', 'AppLocker', 'Certificates', 'Chrome', 'Internet Explorer', 'Office 2013', 'Windows', 'Windows Firewall'.

    .PARAMETER PolicyScopes
    Optional. The scope of the policies to apply. Available scopes: 'Computer', 'User'. Defaults to 'Computer','User'.

    .PARAMETER PolicyType
    Optional. The type of policies to apply. Available types: 'Domain', 'Local'. Defaults to 'Domain' when joined to a domain. Defaults to 'Local' when not joined to a domain.

    .PARAMETER PolicyMode
    Optional. The mode of policies to apply, if supported by the specific policy. For example, AppLocker supports audit and enforcement modes. Available modes: 'Audit', 'Enforced'. Defaults to 'Audit'.

    .PARAMETER BackupPath
    Optional. The path to a folder to save backups of Group Policy Objects and Group Policy Templates to in case a rollback is needed. Defaults to $env:USERPROFILE\Desktop\Backup_yyyyMMddHHmmss for when the script was executed.

    .PARAMETER ToolPath
    Optional. The path to the LGPO tool. Required when PolicyType is 'Local'.

    .PARAMETER UpdateTemplates
    Optional. Update Group Policy templates that correspond to the applied Group Policy objects.

    .EXAMPLE
    Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'Chrome' -PolicyType 'Local' -ToolPath '.\Secure-Host-Baseline\LGPO\lgpo.exe' -Verbose

    .EXAMPLE
    Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'Adobe Reader' -PolicyType 'Local' -ToolPath '.\Secure-Host-Baseline\LGPO\lgpo.exe' -UpdateTemplates

    .EXAMPLE
    Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'Chrome' -PolicyType 'Local' -PolicyMode 'Enforced' -BackupPath "$env:USERPROFILE\Desktop\MyBackup" -ToolPath '.\Secure-Host-Baseline\LGPO\lgpo.exe'

    .EXAMPLE
    Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'Adobe Reader','AppLocker','Certificates','Chrome','Internet Explorer','Office 2013','Office 2016','Windows','Windows Firewall' -PolicyType 'Domain' -PolicyMode 'Enforced'

    .EXAMPLE
    Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'Adobe Reader','AppLocker','Certificates','Chrome','Internet Explorer','Office 2013','Office 2016','Windows','Windows Firewall' -PolicyType 'Local' -PolicyMode 'Enforced' -ToolPath '.\Secure-Host-Baseline\LGPO\lgpo.exe'

    .EXAMPLE
    Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'Adobe Reader','AppLocker','Certificates','Chrome','Internet Explorer','Office 2013','Office 2016','Windows','Windows Firewall' -PolicyType 'Domain' -PolicyMode 'Enforced' -UpdateTemplates

    .EXAMPLE
    Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'Adobe Reader','AppLocker','Certificates','Chrome','Internet Explorer','Office 2013','Office 2016','Windows','Windows Firewall' -PolicyType 'Local' -PolicyMode 'Enforced' -ToolPath '.\Secure-Host-Baseline\LGPO\lgpo.exe' -UpdateTemplates
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='A path to the downloaded SHB package')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [ValidateScript({[System.IO.Directory]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$Path,

        [Parameter(Mandatory=$true, HelpMessage='The names of the policies to apply')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('ActivClient', 'Adobe Reader', 'AppLocker', 'Certificates', 'Chrome', 'Internet Explorer', 'Office 2013', 'Office 2016', 'Windows', 'Windows Firewall', IgnoreCase=$true)]
        [string[]]$PolicyNames,

        [Parameter(Mandatory=$false, HelpMessage='The scope of the policies to apply')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Computer', 'User', IgnoreCase=$true)]
        [string[]]$PolicyScopes = @('Computer','User'),

        [Parameter(Mandatory=$false, HelpMessage='The types of the policies to apply')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Domain', 'Local', IgnoreCase=$true)]
        [string]$PolicyType,

        [Parameter(Mandatory=$false, HelpMessage='The mode of the policies to apply')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Audit', 'Enforced', IgnoreCase=$true)]
        [string]$PolicyMode = 'Audit',

        [Parameter(Mandatory=$false, HelpMessage='A path to save backups to in case roll back is needed')]
        [ValidateNotNullOrEmpty()]
        [string]$BackupPath,

        [Parameter(Mandatory=$false, HelpMessage='The path to LGPO tool')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({([System.IO.FileInfo]$_).Name -eq 'lgpo.exe'})]
        [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
        [ValidateScript({[System.IO.File]::Exists($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_))})]
        [string]$ToolPath,

        [Parameter(Mandatory=$false, HelpMessage='Update the Group Policy templates')]
        [ValidateNotNullOrEmpty()]
        [switch]$UpdateTemplates
    )

    #todo: add Prepare-SecureHostBaseline -Path $Path, currently might only need it to download LGPO.exe

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    $parameters = $PSBoundParameters

    if (-not($parameters.ContainsKey('PolicyType'))) {
        if (Test-IsDomainJoined) {
            $PolicyType = 'Domain'
        } else {
            $PolicyType = 'Local'
        }
    }

    if (-not($parameters.ContainsKey('BackupPath'))) {
        $baseBackupPath = $env:USERPROFILE,'Desktop' -join [System.IO.Path]::DirectorySeparatorChar
    } else {
        $baseBackupPath = $BackupPath
    }

    if (-not(Test-Path -Path $baseBackupPath)) {
        throw "$baseBackupPath does not exist"
    }

    $date = Get-Date

    $backupPathInstance = $baseBackupPath,('Backup_{0:yyyyMMddHHmmss}' -f $date) -join [System.IO.Path]::DirectorySeparatorChar

    if (-not(Test-Path -Path $backupPathInstance -PathType Container)) {
        New-Item -Path $backupPathInstance -ItemType Directory | Out-Null
    }

    if ('Local' -eq $PolicyType -and -not($parameters.ContainsKey('ToolPath'))) {
        throw 'Must specify the path of the LPGO executable'
    }

    if(-not(Test-IsAdministrator -AdministratorType $PolicyType)) {
        throw "Must be running as a $PolicyType administrator"
    }

    if(-not(Test-IsElevated)) {
        throw 'Must be running at an elevated prompt'
    }

    if ('Local' -eq $PolicyType -and (Test-IsDomainJoined)) {
        throw 'Must not be joined to a domain to apply local policy'
    }

    if ('Domain' -eq $PolicyType -and -not(Test-IsDomainJoined)) {
        throw 'Must be joined to a domain to apply domain policy'
    }

    # technically this could be made to work if it wasn't on a DC but it is much easier to do this from a DC since the Group Policy cmdlets will exist
    if ('Domain' -eq $PolicyType -and -not(Test-IsDomainController)) {
        throw 'Must be running on a domain controller'
    }
    
    # explicitly check for Group Policy cmdlets just to be sure
    if ('Domain' -eq $PolicyType -and -not(Test-IsModuleAvailable -Name 'GroupPolicy')) {
        throw 'Group Policy cmdlets must be installed'
    }

    # these parens are important, don't remove them otherwise Where-Object doesn't work, need to pipeline
    $policyDefinitions = @((Get-GPODefinitions -Path $Path) | Where-Object { $_.PolicyName -in $PolicyNames -and (@( Get-Intersection -ReferenceObject ($PolicyScopes) -DifferenceObject ($_.PolicyScopes)).Count -ge 1) -and $PolicyType -in $_.PolicyTypes -and $PolicyMode -in $_.PolicyModes})

    if (0 -eq $policyDefinitions.Count) {
        throw 'Unable to apply policies because no policies matched'
    }

    $templateFolderPath = Get-GroupPolicyTemplateFolderPath -TemplatePathType $PolicyType

    #todo: add domain and local folders inside Windows GPO folder to resolve import errors for the local case

    $gpoBackupFolder = "$backupPathInstance\Group Policy Objects"
    New-Item -Path $gpoBackupFolder -ItemType Container | Out-Null

    $gptBackupFolder = "$backupPathInstance\Group Policy Templates"
    New-Item -Path $gptBackupFolder -ItemType Container | Out-Null

    # there's only 1 policy object for local policy so only 1 backup needs to occur unlike domain policy
    if ('Local' -eq $PolicyType) {
        $ToolPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ToolPath)
        New-PolicyObjectBackup -Path $gpoBackupFolder -PolicyType $PolicyType -ToolPath $ToolPath
    }

    $policyDefinitions | ForEach-Object {
        $policyDefinition = $_
        $newPolicyPath = $policyDefinition.PolicyObjectPath

        #$gpoGuid = $_$policyDefinitionolicyInformation.Guid
        $gpoBackupGuid = $policyDefinition.PolicyInformation.BackupGuid
        $gpoName = $policyDefinition.PolicyInformation.DisplayName

        if ('Domain' -eq $PolicyType) {
            New-PolicyObjectBackup -Path $gpoBackupFolder -PolicyType $PolicyType -Name $gpoName
        }

        if ($UpdateTemplates) {
            if (-not('Local' -eq $PolicyType -and $policyDefinition.PolicyName -eq 'Certificates' )) {
                $newTemplatePath = $_.PolicyTemplatePath
                $newTemplates = [System.IO.FileInfo[]]@(Get-ChildItem -Path $newTemplatePath -Recurse -Include '*.adml','*.admx')

                $newTemplates | ForEach-Object {
                    $newTemplate = $_.FullName
                    $targetTemplate = $newTemplate.Replace($newTemplatePath,$templateFolderPath)
        
                    # todo: change to better strategy, json file with sha256 hash and osVersion template is for?
                    # prevent overwriting newer OS group policy templates with older OS group policy templates, policy template version must be newer than OS version
                    # https://technet.microsoft.com/en-us/windows/release-info.aspx Version 1511 as of 08/09/2016
                    if (($policyDefinition.PolicyTemplateType -eq 'Application') -or ($policyDefinition.PolicyTemplateType -eq 'OS' -and ([System.Version]$policyDefinition.PolicyTemplateVersion).CompareTo([System.Version]'10.0.10586.545') -ge 0)) {
                        if (Test-Path -Path $targetTemplate -PathType Leaf) {
                            if (-not(Test-FilesEqual -ReferenceFile $targetTemplate -DifferenceFile $newTemplate)) {
                                Copy-Item -Path $targetTemplate -Destination $gptBackupFolder # make a backup copy # todo: add en-us folder for .adml/.admx files
                                Copy-Item -Path $newTemplate -Destination $targetTemplate -Force
                            }
                        } else {
                            Copy-Item -Path $newTemplate -Destination $targetTemplate -Force
                        }

                    } else {
                        Write-Verbose -Message ('Skipped updating {0} since the OS Group Policy template is newer than the repository version of the Group Policy template' -f $newTemplate)
                    }
                }
            }
        }

        if ('Local' -eq $PolicyType) {
            # no local policy support for certificates so manually import them
            if ($_.PolicyName -eq 'Certificates') {
                Import-LocalCertificate -Path $Path -Store 'Root'
                Import-LocalCertificate -Path $Path -Store 'Intermediate'
            } else {
                $ToolPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ToolPath)
                Import-PolicyObject -Path $newPolicyPath -PolicyType $PolicyType -ToolPath $ToolPath
            }

        } else {
            $newPolicyPathParent = ([System.IO.DirectoryInfo]$newPolicyPath).Parent.FullName 
            Import-PolicyObject -Path $newPolicyPathParent  -PolicyType $PolicyType -BackupGuid $gpoBackupGuid -Name $gpoName
        }

    }

    # if we didn't actually backup any GPOs or GPTs, then delete the empty backup instance folder
    # this is really only relevant in domain case where the SHB GPOs might not exist OR the -UpdateTemplates parameter was used (it isn't by default)
    if (@(Get-ChildItem -Path $backupPathInstance -Recurse | Where-Object { $_.PsIsContainer -eq $false }).Count -eq 0) {
        Remove-Item -Path $backupPathInstance -Recurse -Force -ErrorAction SilentlyContinue -Confirm:$false 
    }
}