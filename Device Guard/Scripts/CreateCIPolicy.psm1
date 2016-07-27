
$script:DeviceGuard_PolicyRegistryKeyName = "HKLM:SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
$script:DeviceGuard_FullXmlPolicyFileName = "HVCIPolicyScan.xml"
$script:DeviceGuard_IncrementalXmlPolicyFileName = "IncrementalScan.xml"
$script:DeviceGuard_BinaryPolicyFileName = "HVCIPolicy.bin"


$script:POLICY_RULE_OPTION_UMCI = 0
$script:POLICY_RULE_OPTION_BOOT_MENU_PROTECTION = 1
$script:POLICY_RULE_OPTION_WHQL = 2
$script:POLICY_RULE_OPTION_AUDIT_MODE = 3
$script:POLICY_RULE_OPTION_FLIGHT_SIGNING = 4
$script:POLICY_RULE_OPTION_INHERENT_DEFAULT_POLICY = 5
$script:POLICY_RULE_OPTION_UNSIGNED_SYSTEM_INTEGRITY_POLICY = 6
$script:POLICY_RULE_OPTION_DEBUG_POLICY_AUGMENTED = 7
$script:POLICY_RULE_OPTION_EV_SIGNED = 8
$script:POLICY_RULE_OPTION_ADVANCED_BOOT_OPTIONS_MENU = 9
$script:POLICY_RULE_OPTION_BOOT_AUDIT_ON_FAILURE = 10


function Test-LastCommandSuccessful(){
	return ([bool]$?)
}

function isFile([string]$path){
	return  $(Get-Item $path).PSIsContainer -eq $FALSE
}

function isWindows10 (){
	return $(Test-MajorOSVersion 10) -eq $TRUE
}

function GetVolumeOfPath ($path){
	#Split-Path returns C: need to append \ for use as a volume
	return $(Split-Path $path -Qualifier) + "\"

}

function GetVolumesFromPaths([string[]]$paths){
	$volumes = @()

	ForEach($path in $paths){
		[void] ($volumes.add((GetVolumeOfPath $path)))
	}

	return ,$volumes
}


function CreateCIPolicyXml ($scanPath, $policyOutPath) {
	if((Test-Path $scanPath) -eq $FALSE){
		Write-Error "Path: $scanPath does not exist"
		return $NULL
	}

	$executables = Get-AllExecutables -ScanPath $scanPath

	New-CIPolicy -Level PcaCertificate -FilePath $policyOutPath -DriverFiles $executables -Fallback Hash -UserPEs 3> CIPolicyLog.txt
	Write-Host "Created file $policyOutPath"

}

function CreateCIPolicyBin ($policyPath, $binOutPath){
	ConvertFrom-CIPolicy $policyPath $binOutPath
	Write-Host "Created file $binOutPath"
}






function CreateVolumeShadowCopyOfVolumes($volumes){
	$shadowCopies = @()
	$context = "ClientAccessible"
	ForEach($volume in $volumes){
		$shadowCopy = (New-VolumeShadowCopy $volume $context)
		if($shadowCopy -eq $NULL){
			Write-Error "Error creating volume shadow copy of volume $volume.  Rolling back already created volume shadow copies"
			ForEach($shadowCopy in $shadowCopies){
				Write-Host "Removing ShadowCopy with ID=$($shadowCopy.shadowId)"
				Remove-VolumeShadowCopy $shadowCopy.ShadowId
			}


			return $NULL
		}
		Write-Host "Created ShadowCopy with ID=$($shadowCopy.ShadowId)"	
		$shadowCopies += $shadowCopy

	}

	return ,$shadowCopies
}

function New-VolumeShadowCopy(){
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$TRUE)]
			[string]$volume,
		[Parameter(Mandatory=$TRUE)]
			[string]$context
	)


	BEGIN{}

	PROCESS{
		return (Get-WmiObject -List Win32_ShadowCopy).Create($volume, $context)
	}


	END{}
}

function Remove-VolumeShadowCopy(){
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$TRUE)]
			[string]$shadowId
	)


	BEGIN{}

	PROCESS{
		$shadowCopy = Get-WmiObject Win32_ShadowCopy | Where {$_.ID -eq $shadowId}

		if ($shadowCopy -eq $NULL){
			Write-Host "id: $id does not exist"
			return $FALSE
		}

		$shadowCopy.Delete()

		return $TRUE
	}


	END{}
}


function CreateCodeIntegrityPolicyForPath([String]$appPath, [String]$policyPath){
	CreateCIPolicyXml $appPath $policyPath
	Write-Host "Created code integrity policy for path $appPath"
}


function CreateCodeIntegrityPolicyForPaths(
	[string[]]$ScanPaths,
	[string]$outPathRoot){

	#make sure that outPathRoot directory exists or bail out if the user
	#does not want to create it
	if((Test-Path $outPathRoot) -eq $FALSE){
		$answer = Read-Host "Directory: $outPathRoot does not exist.  Would you like to create it? (Y/N)"
		if($answer.ToLower() -eq "y"){
			Write-Host "Created directory $outPathRoot"
			New-Item $outPathRoot -type Directory | Out-Null
			if(Test-LastCommandSuccessful -eq $FALSE){
				return $NULL
			}
		}
		else{
			Write-Error "Directory: $outPathRoot does not exist"
			return $NULL
		}
		
	}


	ForEach($scanPath in $scanPaths){
		if((Test-Path $scanPath) -eq $FALSE){
			Write-Error "Path: $scanPath does not exist"
			return $NULL
		}
	}

	$currentTime = $(Get-Date -format yyyyMMdd-HHmmss)

	$xmlFileName = "$($currentTime)_$($script:DeviceGuard_FullXmlPolicyFileName)"
	$FullCIPolicyXmlPath = Join-Path $outPathRoot $xmlFileName

	$binFileName = "$($currentTime)_$($script:DeviceGuard_BinaryPolicyFileName)"
	$CIPolicyBinPath = Join-Path $outPathRoot $binFileName 

	$IncrementalCIPolicyXmlPath = Join-Path $outPathRoot $script:DeviceGuard_IncrementalXmlPolicyFileName
		
	$head, $tail = @($ScanPaths)

	CreateCodeIntegrityPolicyForPath $head $FullCIPolicyXmlPath

	ForEach($scanPath in $tail){
		CreateCodeIntegrityPolicyForPath $scanPath $IncrementalCIPolicyXmlPath
		Merge-CIPolicy -PolicyPaths $FullCIPolicyXmlPath,$IncrementalCIPolicyXmlPath -OutputFilePath $FullCIPolicyXmlPath 
	}


	CreateCIPolicyBin $FullCIPolicyXmlPath $CIPolicyBinPath
}




function New-Symlink(){
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$TRUE)]
			[string]$link,
		[Parameter(Mandatory=$TRUE)]
			[string]$target
	)


	BEGIN{}

	PROCESS{
		cmd /c mklink /d $link $target
		return $LASTEXITCODE
	}


	END{}
}


function Remove-Symlink(){
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$TRUE)]
			[string]$link
	)


	BEGIN{}

	PROCESS{
		cmd /c rmdir $link
		return $LASTEXITCODE
	}


	END{}
}



function Get-OSVersion(){
	return [environment]::OSVersion.Version
}



function Enable-AuditMode(){
<#
	.SYNOPSIS

	Enables audit mode for a code integrity policy.

	.DESCRIPTION

	Enables audit mode for a code integrity policy.

	.PARAMETER ciPolicyXmlPath
	[string]: The location of the xml version of the code integrity policy to enable the AuditMode property.
	
	.EXAMPLE

	Enable-AuditMode -ciPolicyXmlPath ".\ciPolicy.xml"

#>
	[CmdletBinding()]
	param(
		[string]$ciPolicyXmlPath
	)

	BEGIN{}

	PROCESS{
		if((Test-Path $ciPolicyXmlPath) -eq $FALSE){
			Write-Error "Policy: $ciPolicyXmlPath does not exist"
			return $NULL
		}

		if((isFile $ciPolicyXmlPath) -eq $FALSE){
			Write-Error "$ciPolicyXmlPath is not a file object"
			return $NULL
		}

		Set-RuleOption -Option $script:POLICY_RULE_OPTION_AUDIT_MODE -FilePath $ciPolicyXmlPath
	}

	END{}
}


function Disable-AuditMode(){
<#
	.SYNOPSIS

	Disables audit mode for a code integrity policy.

	.DESCRIPTION

	Disables audit mode for a code integrity policy.

	.PARAMETER ciPolicyXmlPath
	[string]: The location of the xml version of the code integrity policy to disable the AuditMode property.
	
	.EXAMPLE

	Disable-AuditMode -ciPolicyXmlPath ".\ciPolicy.xml"

#>
	[CmdletBinding()]
	param(
		[string]$ciPolicyXmlPath
	)

	BEGIN{}

	PROCESS{
		if((Test-Path $ciPolicyXmlPath) -eq $FALSE){
			Write-Error "Policy: $ciPolicyXmlPath does not exist"
			return $NULL
		}

		if( (isFile $ciPolicyXmlPath) -eq $FALSE){
			Write-Error "$ciPolicyXmlPath is not a file object"
			return $NULL
		}

		Set-RuleOption -Option $script:POLICY_RULE_OPTION_AUDIT_MODE -FilePath $ciPolicyXmlPath -Delete

	}

	END{}
}

function Enable-RequirePolicyIsSigned(){
<#
	.SYNOPSIS

	Enables RequirePolicyIsSigned mode for a code integrity policy.

	.DESCRIPTION

	Enables RequirePolicyIsSigned mode for a code integrity policy.

	.PARAMETER ciPolicyXmlPath
	[string]: The location of the xml version of the code integrity policy to enable the RequirePolicyIsSigned property.
	
	.EXAMPLE

	Enable-RequirePolicyIsSigned -ciPolicyXmlPath ".\ciPolicy.xml"

#>
	[CmdletBinding()]
	param(
		[string]$ciPolicyXmlPath
	)

	BEGIN{}

	PROCESS{
		if((Test-Path $ciPolicyXmlPath) -eq $FALSE){
			Write-Error "Policy: $ciPolicyXmlPath does not exist"
			return $NULL
		}

		if( (isFile $ciPolicyXmlPath) -eq $FALSE){
			Write-Error "$ciPolicyXmlPath is not a file object"
			return $NULL
		}

		Set-RuleOption -Option $script:POLICY_RULE_OPTION_UNSIGNED_SYSTEM_INTEGRITY_POLICY -FilePath $ciPolicyXmlPath -Delete
	}

	END{}
}

function Disable-RequirePolicyIsSigned(){
<#
	.SYNOPSIS

	Disables RequirePolicyIsSigned mode for a code integrity policy.

	.DESCRIPTION

	Disables RequirePolicyIsSigned mode for a code integrity policy.

	.PARAMETER ciPolicyXmlPath
	[string]: The location of the xml version of the code integrity policy to disable the RequirePolicyIsSigned property.
	
	.EXAMPLE

	Disable-RequirePolicyIsSigned -ciPolicyXmlPath ".\ciPolicy.xml"

#>
	[CmdletBinding()]
	param(
		[string]$ciPolicyXmlPath
	)

	BEGIN{}

	PROCESS{
		if((Test-Path $ciPolicyXmlPath) -eq $FALSE){
			Write-Error "Policy: $ciPolicyXmlPath does not exist"
			return $NULL
		}

		if( (isFile $ciPolicyXmlPath) -eq $FALSE){
			Write-Error "$ciPolicyXmlPath is not a file object"
			return $NULL
		}

		Set-RuleOption -Option $script:POLICY_RULE_OPTION_UNSIGNED_SYSTEM_INTEGRITY_POLICY -FilePath $ciPolicyXmlPath

	}

	END{}
}



function Test-MajorOSVersion(){
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$TRUE)]
			[int]$expectedMajorOsVersion
	)


	BEGIN{}

	PROCESS{

		return  $(Get-OSversion).major -eq $expectedMajorOsVersion
	}


	END{}
}


function Get-CIPolicyFilePath(){
	return (Get-ItemProperty $script:DeviceGuard_PolicyRegistryKeyName).ConfigCIPolicyFilePath
}

function Get-DeployConfigPolicy(){
	return (Get-ItemProperty $script:DeviceGuard_PolicyRegistryKeyName).DeployConfigCIPolicy
}


function Test-DeviceGuardPolicyFileConfigured(){
	if( ((Test-Path $script:DeviceGuard_PolicyRegistryKeyName) -eq $FALSE) -or 
			((Get-CIPolicyFilePath) -eq $NULL) -or 
			((Test-Path $(Get-CIPolicyFilePath)) -eq $FALSE)){
		return $FALSE
	}

	return $TRUE
}

function Test-DeviceGuardConfiguredToDeploy() {
	if( ((Test-Path $script:DeviceGuard_PolicyRegistryKeyName) -eq $FALSE) -or 
			((Get-DeployConfigPolicy) -eq $NULL) -or
			((Get-DeployConfigPolicy) -eq 0))	{
		return $FALSE
	}

	return $TRUE

}

function Test-DeviceGuardPolicyReady() {
	return (Test-DeviceGuardPolicyFileConfigured) -and (Test-DeviceGuardConfiguredToDeploy)

}

function Copy-DeviceGuardPolicy([string]$ciPolicyBinPath){
	if( (Test-Path $ciPolicyBinPath) -eq $FALSE){
		Write-Error "Path: $ciPolicyBinPath does not exist"
		return $NULL
	}

	if( (isFile $ciPolicyBinPath) -eq $FALSE){
		Write-Error "$ciPolicyBinPath is not a file"
		return $NULL
	}


	if( (Test-DeviceGuardConfiguredToDeploy) -eq $FALSE){
		Write-Error "CIPolicy fiilepath not configured in group policy"
		return $NULL
	}

	Copy-Item $ciPolicyBinPath $(Get-CIPolicyFilePath)

}


function Get-AllExecutables(){
	[CmdletBinding()]
	param(
		[parameter(ValueFromPipeLine=$TRUE)]
		[string]$ScanPath = "C:\")

	BEGIN{
		$PathsToIgnore = @("C:\Windows.old")
	}

	PROCESS{
		return Get-SystemDriver -UserPEs -ScanPath $ScanPath -OmitPaths $PathsToIgnore
	}

	END{}
}


function New-CIPolicyFromGoldenSystem (){
<#
	.SYNOPSIS

	Creates a new Device Guard code integrity policy for an already set up system.  

	.DESCRIPTION

	Creates a new Device Guard code integrity policy for an already set up system.  By default, the system recursively scans C:\ grabbing all user-mode and kernel-mode binaries/scripts.  All signed executables have their certificates added to the allow policy.  If an executable is not signed, then a hash is computed as a fallback and added to the policy.  The output of this cmdlet is two files: An XML file detailing the code integrity policy and a binary version.  The binary version must be placed in C:\windows\system32\codeintegrity\SIPolicy.p7b and the system must be rebooted for the code integrity policy to take effect.

	.PARAMETER OutputFileRootDir
	[string]: The directory to output the xml and binary versions of the code integrity policy.

	.PARAMETER ScanPaths
	[string[]]: A string array containing the paths to look for kernel-mode and user-mode binaries and scripts.  By default, this is C:\.


	.EXAMPLE

	New-CIPolicyFromGoldenSystem -OutputFileRootDir "C:\users\administrator\desktop"


#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$TRUE)]
		[string]$OutputFileRootDir,
		[string[]]$ScanPaths = @("C:\")
	)


	BEGIN{}

	PROCESS{
		if((isWindows10) -eq $FALSE){
			Write-Error -Message "This host is not running Windows 10. Detected OS is $((Get-WMIObject Win32_OperatingSystem).version)"
			return $NULL
		}

		
		CreateCodeIntegrityPolicyForPaths $ScanPaths $OutputFileRootDir
	
	}


	END{}

	

}




	




