# Windows 10 Compliance
The Windows 10 [audit file](./Windows10.audit) can be used to verify compliance of the Windows 10 configuration portion of the SHB. The Nessus audit file provides an automatic way to verify as many checks as possible. There are a few remaining [manual checks](#Manual-Checks) that can not be automated. Instructions for running the compliance checks in a domain or standalone environment can be found on the [Compliance](./../../Compliance/README.md) page.

## Manual Checks
The following checks must be performed manually because there is currently no automated way of performing these checks. These checks are not covered by the current .audit file, hence these must be performed manually.

* WN10-00-000015 - System firmware or system controllers must have administrator accounts/passwords configured.
* WN10-00-000020 - The system must not use removable media as the boot loader. 
* WN10-00-000030 - Mobile systems must encrypt all discs to protect the confidentiality and integrity of all information at rest.
* WN10-00-000130 - Software certificate installation files must be removed from a system.
* WN10-00-000140 - Inbound exceptions to the firewall on domain workstations must only allow authorized remote management hosts.
* WN10-UC-000005 - A screen saver must be enabled on the system.
* WN10-UC-000010 - The screen saver must be password protected. 
* WN10-UC-000015 - Toast notifications to the lock screen must be turned off.
* WN10-UC-000020 - Zone information must be preserved when saving attachments.

