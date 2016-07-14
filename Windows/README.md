# Windows 10
Group Policy Objects for [Computer](./Group Policy Objects/Computer/) and [User](./Group Policy Objects/User/) policies for Windows 10 are included in the SHB.

[Group Policy Templates](./Group Policy Templates/) have been added to this repository for convenience. This repository contains the latest versions of the templates some of which have changed since the [Windows 10 Version 1511 templates](https://www.microsoft.com/en-us/download/details.aspx?id=48257) were released. Changes appear to have occurred in:

* CipherSuiteOrder.adml
* WindowsStore.adml 
* WinMaps.adml
* WindowsStore.admx
* WinMaps.admx

In [some](https://support.microsoft.com/en-us/kb/3077013) [cases](https://social.technet.microsoft.com/Forums/office/en-US/b4c68086-d348-45ae-aa48-4bd8fd9c3959/upgrading-central-store-error-message-namespace?forum=winserverGP) templates were renamed leading to error messages (e.g. *Namespace 'Microsoft.Policies.WindowsStore' is already defined as the target namespace for another file in the store*) when different template files contained the same Group Policy definitions.

## Hardware
See the [Hardware page](./../Hardware/README.md) for more information about hardware and firmware requirements to take full advantage of Windows 10 security features.

## Downloads for Windows 10
* [Group Policy templates](https://www.microsoft.com/en-us/download/details.aspx?id=48257)
* [Group Policy reference](https://www.microsoft.com/en-us/download/details.aspx?id=25250)
* [Microsoft Security Baseline for Windows 10 Version 1511](https://blogs.technet.microsoft.com/secguide/2016/01/22/security-baseline-for-windows-10-v1511-threshold-2-final/)
* [Microsoft Security Baseline for Windows 10 Version 1507](https://blogs.technet.microsoft.com/secguide/2016/01/22/security-baseline-for-windows-10-v1507-build-10240-th1-ltsb-update/)

## Guidance
NSA Information Assurance guidance for Windows 10:
* [Security Highlights of Windows 10](https://www.iad.gov/iad/library/ia-guidance/security-configuration/operating-systems/security-highlights-of-windows-10.cfm)

## Links
* [Group Policy Search](http://gpsearch.azurewebsites.net/)