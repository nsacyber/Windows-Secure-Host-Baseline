# Windows 10
Group Policy Objects for [Computer](./Group Policy Objects/Computer/) and [User](./Group Policy Objects/User/) policies for Windows 10 are included in the SHB.

[Group Policy Templates](./Group Policy Templates/) have been added to this repository for convenience. This repository contains the latest versions of the templates some of which have changed since the [Windows 10 Version 1511 templates](https://www.microsoft.com/en-us/download/details.aspx?id=48257) were released. Changes appear to have occurred in:

* CipherSuiteOrder.adml
* WindowsStore.adml 
* WinMaps.adml
* WindowsStore.admx
* WinMaps.admx

In [some](https://support.microsoft.com/en-us/kb/3077013) [cases](https://social.technet.microsoft.com/Forums/office/en-US/b4c68086-d348-45ae-aa48-4bd8fd9c3959/upgrading-central-store-error-message-namespace?forum=winserverGP) templates were renamed leading to error messages (e.g. *Namespace 'Microsoft.Policies.WindowsStore' is already defined as the target namespace for another file in the store*, *Namespace 'Microsoft.Policies.Sensors.WindowsLocationProvider' is already defined as the target namespace for another file in the store*) when [different template files contain the same Group Policy definitions](https://support.microsoft.com/en-us/kb/3077013).

## Importing the Windows Group Policy

### Importing the Windows domain Group Policy
Use the PowerShell Group Policy commands to import the Windows Group Policy into a domain. Run the following command on a domain controller from a PowerShell prompt running as a domain administrator. 

```
Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'Windows'
```

### Importing the Windows local Group Policy
Use Microsoft's LGPO tool to apply the Windows Group Policy to a standalone system. Run the following command from a command prompt running as a local administrator.

```
Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'Windows' -ToolPath '.\LGPO\lgpo.exe'
```

## Hardware
See the [Hardware page](./../Hardware/README.md) for more information about hardware and firmware requirements to take full advantage of Windows 10 security features.

## Remove Legacy Features
It is highly recommended to remove legacy features and protocols as known and unknown vulnerabilities in them expose the network to severe risk. NSA Information Assurance has issued security guidance for the removal of [Outdated Software and Protocols](https://www.iad.gov/iad/library/ia-advisories-alerts/outdated-software-and-protocols-update.cfm). The [RemoveLegacyComponents.ps1](./Scripts/RemoveLegacyComponents.ps1) script can be used to help with the removal of legacy components from Windows 10, like PowerShell 2.0, SMBv1, and NetBIOS.

## Guidance
NSA Information Assurance guidance for Windows 10:
* [Security Highlights of Windows 10](https://www.iad.gov/iad/library/ia-guidance/security-configuration/operating-systems/security-highlights-of-windows-10.cfm)

## Microsoft Guidance
* [Microsoft Security Baseline for Windows 10 Version 1511](https://blogs.technet.microsoft.com/secguide/2016/01/22/security-baseline-for-windows-10-v1511-threshold-2-final/)
* [Microsoft Security Baseline for Windows 10 Version 1507](https://blogs.technet.microsoft.com/secguide/2016/01/22/security-baseline-for-windows-10-v1507-build-10240-th1-ltsb-update/)

## Downloads for Windows 10
* [Group Policy templates for version 1507 and 1511](https://www.microsoft.com/en-us/download/details.aspx?id=48257)
* [Group Policy templates for version 1607](https://www.microsoft.com/en-us/download/details.aspx?id=53430)
* [Group Policy reference](https://www.microsoft.com/en-us/download/details.aspx?id=25250)
* [Security Compliance Manager 4.0](http://go.microsoft.com/fwlink/?LinkId=823534)

## Links
* [Windows 10 release information](https://technet.microsoft.com/en-us/windows/release-info.aspx)
* [Group Policy search](http://gpsearch.azurewebsites.net/)