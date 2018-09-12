# Windows 10
Group Policy Objects for [Computer](./Group%20Policy%20Objects/Computer/) and [User](./Group%20Policy%20Objects/User/) policies for Windows 10 are included in the SHB. The latest versions of  the [Group Policy Templates](./Group%20Policy%20Templates/) for Windows 10 are also included.

Note that the latest SHB (10.1.0) is for Windows 10 1607 which is what this repository is in sync with.

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

## Remove Legacy Features
It is highly recommended to remove legacy features and protocols as known and unknown vulnerabilities in them expose the network to severe risk. NSA Information Assurance has issued security guidance for the removal of [Outdated Software and Protocols](https://www.iad.gov/iad/library/ia-advisories-alerts/outdated-software-and-protocols-update.cfm). The [Scripts folder](./Scripts/) contains a number of PowerShell modules that can be used to disable or remove legacy components from Windows 10 such as [PowerShell 2.0](./Scripts/PowerShell.psm1), [SMB 1.0](./Scripts/SMB.psm1), and [NetBIOS](./Scripts/NetBIOS.psm1).

## Guidance
NSA Information Assurance guidance for Windows 10:
* [Security Highlights of Windows 10](https://www.iad.gov/iad/library/ia-guidance/security-configuration/operating-systems/security-highlights-of-windows-10.cfm)
* [Windows 10 for Enterprises](https://www.iad.gov/iad/library/ia-guidance/security-tips/windows-10-enterprises.cfm)

## Microsoft Guidance
* [Microsoft Security Baseline for Windows 10 Version 1607](https://blogs.technet.microsoft.com/secguide/2016/10/17/security-baseline-for-windows-10-v1607-anniversary-edition-and-windows-server-2016/)
* [Microsoft Security Baseline for Windows 10 Version 1511](https://blogs.technet.microsoft.com/secguide/2016/01/22/security-baseline-for-windows-10-v1511-threshold-2-final/)
* [Microsoft Security Baseline for Windows 10 Version 1507](https://blogs.technet.microsoft.com/secguide/2016/01/22/security-baseline-for-windows-10-v1507-build-10240-th1-ltsb-update/)
* [Microsoft Security Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)

## Downloads for Windows 10
* [Group Policy templates for version 1607](https://www.microsoft.com/en-us/download/details.aspx?id=53430)
* [Group Policy templates for version 1507 and 1511](https://www.microsoft.com/en-us/download/details.aspx?id=48257)
* [Group Policy reference](https://www.microsoft.com/en-us/download/details.aspx?id=25250)
* [Security Compliance Manager 4.0](http://go.microsoft.com/fwlink/?LinkId=823534) - replaced by the Microsoft Security Toolkit

## Links
* [Windows 10 release information](https://technet.microsoft.com/en-us/windows/release-info.aspx)
* [Group Policy search](http://gpsearch.azurewebsites.net/)