# Microsoft BitLocker

[Microsoft BitLocker](https://technet.microsoft.com/en-us/library/cc731549.aspx) is a full volume encryption feature built into Windows. BitLocker is intended to protect data on devices that have been lost or stolen. BitLocker is available in the Ultimate and Enterprise editions of Windows Vista and Windows 7 and in the Professional and Enterprise editions of Windows 8 and later. A [Group Policy Object](./Group Policy Objects/Computer/) for BitLocker is included in the SHB. The Group Policy Object contains recommended security settings for BitLocker on Windows 10 Version 1511 and later.

## Importing the BitLocker Group Policy

### Importing the BitLocker domain Group Policy
Use the PowerShell Group Policy commands to import the BitLocker Group Policy into a domain. Run the following command on a domain controller from a PowerShell prompt running as a domain administrator. 

```
Import-Module GroupPolicy

Import-GPO -Path ".\BitLocker\Group Policy Objects\Computer\{9D614C55-E361-45A1-87CB-09A2B1EED0C4}"
```
### Importing the BitLocker local Group Policy
Use Microsoft's LGPO tool to apply the BitLocker Group Policy to a standalone system. Run the following command from a command prompt running as a local administrator.

```
lgpo.exe /g ".\BitLocker\Group Policy Objects\Computer\{9D614C55-E361-45A1-87CB-09A2B1EED0C4}"
```

