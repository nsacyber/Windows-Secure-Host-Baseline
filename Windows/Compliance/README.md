# Windows 10 Compliance
The Windows 10 [audit file](./Windows 10.audit) can be used to verify compliance of the Windows 10 configuration portion of the SHB. The Nessus audit file provides an automatic way to verify as many checks as possible. Five of the checks require [Base64 encoded PowerShell](#Base64-Encoded-PowerShell) in order to perform the check correctly. The PowerShell and matching Base64 string are listed below for documentation proposes. The Base64 version of the PowerShell checks are included in the audit file. There are a few remaining [manual checks](#Manual-Checks) that can not be automated. Instructions for running the compliance checks in a domain or standalone environment can be found on the [Compliance](./../../Compliance/README.md) page.

## Manual Checks
The following checks must be performed manually because there is currently no automated way of performing these checks. These checks are not covered by the current .audit file, hence these must be performed manually.

* WN10-00-000015 - System firmware or system controllers must have administrator accounts/passwords configured.
* WN10-00-000020 - The system must not use removable media as the boot loader. 
* WN10-00-000030 - Mobile systems must encrypt all discs to protect the confidentiality and integrity of all information at rest.
* WN10-00-000130 - Software certificate installation files must be removed from a system.
* WN10-00-000140 - Inbound exceptions to the firewall on domain workstations must only allow authorized remote management hosts.
* WN10-AU-000515 - Permissions for the Application event log must prevent access by non-privileged accounts.
* WN10-AU-000520 - Permissions for the Security event log must prevent access by non-privileged accounts.
* WN10-AU-000525 - Permissions for the System event log must prevent access by non-privileged accounts.
* WN10-UC-000005 - A screen saver must be enabled on the system.
* WN10-UC-000010 - The screen saver must be password protected. 
* WN10-UC-000015 - Toast notifications to the lock screen must be turned off.
* WN10-UC-000020 - Zone information must be preserved when saving attachments.


## Base64 Encoded PowerShell Audits
The following PowerShell-based checks need to be base 64 encoded to run correctly. 

WN10-00-000050 - Local volumes must be formatted using NTFS. The following PowerShell can automate this check but it must be Base64 encoded to run under Nessus.

```
$FileSystem = "NTFS"
$drives = get-wmiobject -class "Win32_Volume" -namespace "root\CIMV2" -filter "DriveType = 3" -computername "."
foreach ($drv in $drives) { 
if (-Not ($drv.FileSystem -Match 'NTFS')) {$FileSystem = $drv.FileSystem}
}
write-host $FileSystem
```

```
CgAkAEYAaQBsAGUAUwB5AHMAdABlAG0AIAA9ACAAIgBOAFQARgBTACIACgAkAGQAcgBpAHYAZQBzACAAPQAgAGcAZQB0AC0AdwBtAGkAbwBiAGoAZQBjAHQAIAAtAGMAbABhAHMAcwAgACIAVwBpAG4AMwAyAF8AVgBvAGwAdQBtAGUAIgAgAC0AbgBhAG0AZQBzAHAAYQBjAGUAIAAiAHIAbwBvAHQAXABDAEkATQBWADIAIgAgAC0AZgBpAGwAdABlAHIAIAAiAEQAcgBpAHYAZQBUAHkAcABlACAAPQAgADMAIgAgAC0AYwBvAG0AcAB1AHQAZQByAG4AYQBtAGUAIAAcIC4AHSAKAGYAbwByAGUAYQBjAGgAIAAoACQAZAByAHYAIABpAG4AIAAkAGQAcgBpAHYAZQBzACkAIAB7ACAACgBpAGYAIAAoAC0ATgBvAHQAIAAoACQAZAByAHYALgBGAGkAbABlAFMAeQBzAHQAZQBtACAALQBNAGEAdABjAGgAIAAnAE4AVABGAFMAJwApACkAIAB7ACQARgBpAGwAZQBTAHkAcwB0AGUAbQAgAD0AIAAkAGQAcgB2AC4ARgBpAGwAZQBTAHkAcwB0AGUAbQB9AAoAfQAKAHcAcgBpAHQAZQAtAGgAbwBzAHQAIAAkAEYAaQBsAGUAUwB5AHMAdABlAG0ACgA=
```

WN10-00-000060 - Non system-created file shares on a system must limit access to groups that require it.

```
$shares = ""
$ctr = 0
$shared_drives = get-wmiobject -class "win32_Share"  -namespace "root\CIMV2" -computername "." | sort-object Name
foreach ($drive in $shared_drives) { 
  	if ($ctr -eq 0) { $shares = $drive.Name }
  	else { $shares = $shares + " " + $drive.Name }
  	$ctr++
}
write-host $shares
```

```
CgAkAHMAaABhAHIAZQBzACAAPQAgACIAIgAKACQAYwB0AHIAIAA9ACAAMAAKACQAcwBoAGEAcgBlAGQAXwBkAHIAaQB2AGUAcwAgAD0AIABnAGUAdAAtAHcAbQBpAG8AYgBqAGUAYwB0ACAALQBjAGwAYQBzAHMAIAAiAHcAaQBuADMAMgBfAFMAaABhAHIAZQAiACAAIAAtAG4AYQBtAGUAcwBwAGEAYwBlACAAIgByAG8AbwB0AFwAQwBJAE0AVgAyACIAIAAtAGMAbwBtAHAAdQB0AGUAcgBuAGEAbQBlACAAHCAuAB0gIAB8ACAAcwBvAHIAdAAtAG8AYgBqAGUAYwB0ACAATgBhAG0AZQAKAGYAbwByAGUAYQBjAGgAIAAoACQAZAByAGkAdgBlACAAaQBuACAAJABzAGgAYQByAGUAZABfAGQAcgBpAHYAZQBzACkAIAB7ACAACgAgACAACQBpAGYAIAAoACQAYwB0AHIAIAAtAGUAcQAgADAAKQAgAHsAIAAkAHMAaABhAHIAZQBzACAAPQAgACQAZAByAGkAdgBlAC4ATgBhAG0AZQAgAH0ACgAgACAACQBlAGwAcwBlACAAewAgACQAcwBoAGEAcgBlAHMAIAA9ACAAJABzAGgAYQByAGUAcwAgACsAIAAiACAAIgAgACsAIAAkAGQAcgBpAHYAZQAuAE4AYQBtAGUAIAB9AAoAIAAgAAkAJABjAHQAcgArACsACgB9AAoAdwByAGkAdABlAC0AaABvAHMAdAAgACQAcwBoAGEAcgBlAHMACgA=
```

WN10-00-000065 - Unused accounts must be disabled or removed from the system after 35 days.

```
$Cutoff = (Get-Date).AddDays(-35)
$Cnt = 0
([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
	$user = ([ADSI]$_.Path)
	$lastLogin = $user.Properties.LastLogin.Value
	$enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2

	if ($lastLogin -lt $Cutoff -And $enabled) {
Write-Host $user.Name
		$Cnt++
	}
}
if ($Cnt -eq 0) {Write-Host "None"}
```

```
CgAkAEMAdQB0AG8AZgBmACAAPQAgACgARwBlAHQALQBEAGEAdABlACkALgBBAGQAZABEAGEAeQBzACgALQAzADUAKQAKACQAQwBuAHQAIAA9ACAAMAAKACgAWwBBAEQAUwBJAF0AKAAnAFcAaQBuAE4AVAA6AC8ALwB7ADAAfQAnACAALQBmACAAJABlAG4AdgA6AEMATwBNAFAAVQBUAEUAUgBOAEEATQBFACkAKQAuAEMAaABpAGwAZAByAGUAbgAgAHwAIABXAGgAZQByAGUAIAB7ACAAJABfAC4AUwBjAGgAZQBtAGEAQwBsAGEAcwBzAE4AYQBtAGUAIAAtAGUAcQAgACcAdQBzAGUAcgAnACAAfQAgAHwAIABGAG8AcgBFAGEAYwBoACAAewAKACQAdQBzAGUAcgAgAD0AIAAoAFsAQQBEAFMASQBdACQAXwAuAFAAYQB0AGgAKQAKACQAbABhAHMAdABMAG8AZwBpAG4AIAA9ACAAJAB1AHMAZQByAC4AUAByAG8AcABlAHIAdABpAGUAcwAuAEwAYQBzAHQATABvAGcAaQBuAC4AVgBhAGwAdQBlAAoAJABlAG4AYQBiAGwAZQBkACAAPQAgACgAJAB1AHMAZQByAC4AUAByAG8AcABlAHIAdABpAGUAcwAuAFUAcwBlAHIARgBsAGEAZwBzAC4AVgBhAGwAdQBlACAALQBiAGEAbgBkACAAMAB4ADIAKQAgAC0AbgBlACAAMAB4ADIACgAKAGkAZgAgACgAJABsAGEAcwB0AEwAbwBnAGkAbgAgAC0AbAB0ACAAJABDAHUAdABvAGYAZgAgAC0AQQBuAGQAIAAkAGUAbgBhAGIAbABlAGQAKQAgAHsACgBXAHIAaQB0AGUALQBIAG8AcwB0ACAAJAB1AHMAZQByAC4ATgBhAG0AZQAKACQAQwBuAHQAKwArAAoAfQAKAH0ACgBpAGYAIAAoACQAQwBuAHQAIAAtAGUAcQAgADAAKQAgAHsAVwByAGkAdABlAC0ASABvAHMAdAAgACIATgBvAG4AZQAiAH0ACgA=
```

WN10-00-000090 - Accounts must be configured to require password expiration

```
$Active = 0
$colItems = get-wmiobject -class "Win32_userAccount" -namespace "root\CIMV2" -filter "LocalAccount = True" -computername "."
foreach ($objItem in $colItems) { 
	if (-Not $objItem.PasswordExpires) { write-host $objItem.Caption; $Active++ }
}
if ($Active -eq 0) { write-host "NULL" }
```

```
CgAkAEEAYwB0AGkAdgBlACAAPQAgADAACgAkAGMAbwBsAEkAdABlAG0AcwAgAD0AIABnAGUAdAAtAHcAbQBpAG8AYgBqAGUAYwB0ACAALQBjAGwAYQBzAHMAIAAiAFcAaQBuADMAMgBfAHUAcwBlAHIAQQBjAGMAbwB1AG4AdAAiACAALQBuAGEAbQBlAHMAcABhAGMAZQAgACIAcgBvAG8AdABcAEMASQBNAFYAMgAiACAALQBmAGkAbAB0AGUAcgAgACIATABvAGMAYQBsAEEAYwBjAG8AdQBuAHQAIAA9ACAAVAByAHUAZQAiACAALQBjAG8AbQBwAHUAdABlAHIAbgBhAG0AZQAgACIALgAiAAoAZgBvAHIAZQBhAGMAaAAgACgAJABvAGIAagBJAHQAZQBtACAAaQBuACAAJABjAG8AbABJAHQAZQBtAHMAKQAgAHsAIAAKAGkAZgAgACgALQBOAG8AdAAgACQAbwBiAGoASQB0AGUAbQAuAFAAYQBzAHMAdwBvAHIAZABFAHgAcABpAHIAZQBzACkAIAB7ACAAdwByAGkAdABlAC0AaABvAHMAdAAgACQAbwBiAGoASQB0AGUAbQAuAEMAYQBwAHQAaQBvAG4AOwAgACQAQQBjAHQAaQB2AGUAKwArACAAfQAKAH0ACgBpAGYAIAAoACQAQQBjAHQAaQB2AGUAIAAtAGUAcQAgADAAKQAgAHsAIAB3AHIAaQB0AGUALQBoAG8AcwB0ACAAIgBOAFUATABMACIAIAB9AAoA
```

WN10-ER-000005 - The Windows Error Reporting Service must be running and configured to start automatically.

```
(Get-WmiObject -Class Win32_Service -Property StartMode -Filter "Name='WerSvc'" | Select-Object StartMode | Select-Object -ExpandProperty StartMode) -eq "Auto" -and ((Get-Service -Name 'WerSvc').Status) -eq "Running"
```

```
CgAoAEcAZQB0AC0AVwBtAGkATwBiAGoAZQBjAHQAIAAtAEMAbABhAHMAcwAgAFcAaQBuADMAMgBfAFMAZQByAHYAaQBjAGUAIAAtAFAAcgBvAHAAZQByAHQAeQAgAFMAdABhAHIAdABNAG8AZABlACAALQBGAGkAbAB0AGUAcgAgACIATgBhAG0AZQA9ACcAVwBlAHIAUwB2AGMAJwAiACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIABTAHQAYQByAHQATQBvAGQAZQAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAALQBFAHgAcABhAG4AZABQAHIAbwBwAGUAcgB0AHkAIABTAHQAYQByAHQATQBvAGQAZQApACAALQBlAHEAIAAiAEEAdQB0AG8AIgAgAC0AYQBuAGQAIAAoACgARwBlAHQALQBTAGUAcgB2AGkAYwBlACAALQBOAGEAbQBlACAAJwBXAGUAcgBTAHYAYwAnACkALgBTAHQAYQB0AHUAcwApACAALQBlAHEAIAAiAFIAdQBuAG4AaQBuAGcAIgAKAA==
```

