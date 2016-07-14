# Windows 10 Compliance
The Windows 10 [audit file](./Windows 10.audit) can be used to verify compliance of the Windows 10 configuration portion of the SHB. The Nessus audit file provides an automatic way to verify as many checks as possible. One of the checks require [Base64 encoded PowerShell](#Base64-Encoded-PowerShell) in order to perform the check correctly. The PowerShell and matching Base64 string are listed below for documentation proposes. The Base64 version of the PowerShell checks are included in the audit file. There are a few remaining [manual checks](#Manual-Checks) that can not be automated. Instructions for running the compliance checks in a domain or standalone environment can be found on the [Compliance](./../../Compliance/README.md) page.

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
The following PowerShell-based check currently needs to be base 64 encoded to run correctly. 

WN10-ER-000005 - The Windows Error Reporting Service must be running and configured to start automatically.

```
(Get-WmiObject -Class Win32_Service -Property StartMode -Filter "Name='WerSvc'" | Select-Object StartMode | Select-Object -ExpandProperty StartMode) -eq "Auto" -and ((Get-Service -Name 'WerSvc').Status) -eq "Running"
```

```
CgAoAEcAZQB0AC0AVwBtAGkATwBiAGoAZQBjAHQAIAAtAEMAbABhAHMAcwAgAFcAaQBuADMAMgBfAFMAZQByAHYAaQBjAGUAIAAtAFAAcgBvAHAAZQByAHQAeQAgAFMAdABhAHIAdABNAG8AZABlACAALQBGAGkAbAB0AGUAcgAgACIATgBhAG0AZQA9ACcAVwBlAHIAUwB2AGMAJwAiACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIABTAHQAYQByAHQATQBvAGQAZQAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAALQBFAHgAcABhAG4AZABQAHIAbwBwAGUAcgB0AHkAIABTAHQAYQByAHQATQBvAGQAZQApACAALQBlAHEAIAAiAEEAdQB0AG8AIgAgAC0AYQBuAGQAIAAoACgARwBlAHQALQBTAGUAcgB2AGkAYwBlACAALQBOAGEAbQBlACAAJwBXAGUAcgBTAHYAYwAnACkALgBTAHQAYQB0AHUAcwApACAALQBlAHEAIAAiAFIAdQBuAG4AaQBuAGcAIgAKAA==
```

