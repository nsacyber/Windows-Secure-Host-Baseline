# Windows 10
Group Policy Objects for [Computer](./Windows/Group Policy Objects/Computer/) and [User](./Windows/Group Policy Objects/User/) for Windows 10 are included in the SHB.

## Hardware and Firmware requirements for the SHB
[Credential Guard](https://technet.microsoft.com/en-us/library/mt483740(v=vs.85).aspx) must be enabled to meet the security requirements of the SHB. While Credential Guard can be enabled in Group Policy, it does not provide any additional protection unless certain hardware and firmware requirements are met. Without meeting these requirements, Credential Guard does not take affect on a system. Credential Guard requires that: 
* 64-bit capable processor and the 64-bit version of Windows is installed
* the Enterprise Edition of Windows is installed
* Unified Extensible Firmware Interface (UEFI) firmware, as opposed to legacy BIOS, version 2.3.1 (Errata C) or later is configured in native mode in the firmware rather than in legacy mode (Compatibility Support Module (CSM))
* Secure Boot is supported and enabled in the firmware
* memory virtualization extensions (Intel VT-x or AMD-V) are supported by the processor and enabled in the firmware
* Second Level Address Translation (Intel EPT or [AMD-RVI](http://support.amd.com/en-us/kb-articles/Pages/GPU120AMDRVICPUsHyperVWin8.aspx)) is supported by the processor
* the OS is not running in a virtual machine (includes Virtual Desktop Infrastructure (VDI) client systems)

Meeting these requirements also positions an organization to be able to enable [Device Guard](https://technet.microsoft.com/en-us/library/mt463091(v=vs.85).aspx).

Some hardware and firmware features, if they exist, can be leveraged by Credential Guard and Device Guard to provide extra security benefits. These features include: 
* a Trusted Platform Module (TPM), version 1.2 or later, when present and enabled in the firmware
* device Input/Output Memory Management Unit (IOMMU) virtualization extensions (Intel Vt-d or AMD-Vi) when supported by the processor and enabled in the firmware 

While these hardware and firmware features are optional since Credential Guard and Device Guard can technically work without them, they are critical to ensuring the security improvements offered by Credential Guard and Device Guard are effectively protected against certain types of attacks. These hardware and firmware features should be considered required by organizations when procuring hardware for Windows 10.

Most enterprise and business class models from OEMs that have passed the Windows Hardware Certification Program for Windows 8 or later likely meet these requirements.


A list of Intel processors that support 64-bit, VT-x, EPT, and VT-d is available [here](http://ark.intel.com/Search/Advanced?s=t&InstructionSet=64-bit&VTX=true&ExtendedPageTables=true&VTD=true). A similar list for AMD processors that support 64-bit, AMD-V, AMD-RVI, and AMD-Vi could not be found.


Ensuring the operating system is updated in a timely and regular manner is also critical for the SHB as Credential Guard and Device Guard are improved over time. New features were added to Credential Guard in [Version 1511](https://technet.microsoft.com/en-us/library/mt621547(v=vs.85).aspx) as well as support for using TPM 1.2.


## Downloads for Windows 10
* [Group Policy templates](https://www.microsoft.com/en-us/download/details.aspx?id=48257)
* [Group Policy reference](https://www.microsoft.com/en-us/download/details.aspx?id=25250)
* [Microsoft Security Baseline](http://blogs.technet.com/cfs-filesystemfile.ashx/__key/telligent-evolution-components-attachments/01-4062-00-00-03-65-94-81/Windows-10-TH2-Security-Baseline.zip) from [this Microsoft blog post](http://blogs.technet.com/b/secguide/archive/2016/01/22/security-baseline-for-windows-10-v1511-quot-threshold-2-quot-final.aspx)

## Guidance
IAD has guidance for Windows 10:
* [Security Highlights of Windows 10](https://www.iad.gov/iad/library/ia-guidance/security-configuration/operating-systems/security-highlights-of-windows-10.cfm)
* Security Improvements in Windows 10
* Hardware Recommendations for Windows 10


