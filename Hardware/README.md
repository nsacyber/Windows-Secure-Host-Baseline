# Hardware and Firmware Requirements for an SHB System

[Credential Guard](https://technet.microsoft.com/en-us/library/mt483740(v=vs.85).aspx) must be enabled to meet the security requirements of the SHB. While Credential Guard can be enabled in Group Policy, it does not provide any additional protection unless certain hardware and firmware requirements are met. Without meeting these requirements, Credential Guard does not take affect on a system. Credential Guard requires that: 
* a 64-bit capable processor and the 64-bit version of Windows is installed
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

While these hardware and firmware features are optional since Credential Guard and Device Guard can technically work without them, they are critical to ensuring the security improvements offered by Credential Guard and Device Guard are effectively protected against certain types of attacks. These hardware and firmware features should be considered required by organizations when procuring hardware for Windows 10. **Microsoft provides a clear list of which security features in Windows 10 use certain hardware and firmware features in the [What's new in Windows 10 security: Windows 10 hardware considerations](https://technet.microsoft.com/en-us/library/mt637125(v=vs.85).aspx#hardware) article**. The notation in the table is **R** = recommended, **Y** = required, and **N** = not used.

Most enterprise and business class models from OEMs that have passed the Windows Hardware Certification Program for Windows 8 or later likely meet these requirements.


A list of Intel processors that support 64-bit, VT-x, EPT, and VT-d is available [here](http://ark.intel.com/Search/Advanced?s=t&InstructionSet=64-bit&VTX=true&ExtendedPageTables=true&VTD=true). A similar list for AMD processors that support 64-bit, AMD-V, AMD-RVI, and AMD-Vi could not be found.


Ensuring the operating system is updated in a timely and regular manner is also critical for the SHB as Credential Guard and Device Guard are improved over time. New features were added to Credential Guard in [Version 1511](https://technet.microsoft.com/en-us/library/mt621547(v=vs.85).aspx) as well as support for using TPM 1.2.

## Ideal System Properties for an SHB System
Properties of an ideal system for Windows 10 Secure Host Baseline include:
* Processor supports 64-bit instructions.
* Firmware is UEFI and implements UEFI 2.3.1 Errata C or higher.
* Firmware is in UEFI native mode by default.
* Firmware supports Secure Boot and Secure Boot is enabled by default.
* Processor supports memory virtualization and the firmware has memory virtualization enabled by default if a configurable option is provided.
* Processor supports IOMMU device virtualization and the firmware has IOMMU device virtualization enabled by default if a configurable option is provided.
* Processor supports Second Level Address Translation.
* System has a Trusted Platform Module, version 1.2 or later, that implements the Physical Presence Interface specification 1.2 or later, is enabled by default, and can be automatically provisioned by Windows 8 or later.
* System supports Credential Guard and Device Guard.
* System supports firmware updates using Windows UEFI Firmware Update Platform specification (optional, but recommended).
* System has passed a Windows Microsoft Hardware Certification Program for at least Windows 8 or later, but preferably for Windows 10.

## Hardware and Firmware Survey
In support of deployment of the Windows 10 Secure Host Baseline, a number of hardware and firmware questions need to be answered about systems used by the DoD. The purpose of these questions is to determine how ready a system is to enable Windows 10 security features, such as Credential Guard and Device Guard, with the preferred hardware and firmware configuration. Answers to these questions can be used by DoD components to determine whether certain Windows 10 security features are supported by the model. Answers are needed for any Windows tablet, laptop, desktop, and server models produced by OEMs that are used in DoD. Answers should focus on enterprise and business class models rather than consumer class models. 

### Questions

Answer these questions per model:

1. Which processors are available as options for this model?
1. Which chipsets are available as options for this model?
1. Does the model ship with processors that support 64-bit instructions? 
1. Does the model use Unified Extensible Firmware Interface (UEFI) firmware as opposed to legacy BIOS? 
1. If the model has UEFI firmware, does the model ship with the firmware in native mode or legacy mode (Compatibility Support Module) by default? 
1. If the model has UEFI firmware, which version of the UEFI specification, including errata version, is implemented? 
1. Does the model ship with Secure Boot support? 
1. If the model ships with Secure Boot support, does the model ship with Secure Boot enabled by default? 
1. If the model did not initially support Secure Boot, can it be upgraded via a firmware update to support Secure Boot? 
1. If the model has UEFI firmware, does it implement the MemoryOverwriteRequestControl UEFI variable (aka Secure MOR)? 
1. Does the model support memory virtualization extensions (Intel VT-x/AMD-V)? 
1. If the model supports memory virtualization extensions, does it have memory virtualization extensions enabled by default in the firmware if a configurable option is provided? 
1. Does the model support IOMMU device virtualization extensions (Intel VT-d/AMD-Vi)? 
1. If the model supports IOMMU device virtualization extensions, does it have IOMMU device virtualization extensions enabled by default if a configurable option is provided? 
1. Does the model ship with support for Second Level Address Translation (SLAT) (Intel EPT/AMD-RVI)? 
1. Does the model ship with a Trusted Platform Module (TPM)? 
1. If the model ships with a TPM, what version is the TPM (1.2, 2.0)? 
1. If the model ships with a TPM, does it ship with the TPM enabled by default? 
1. If the model ships with a TPM, can the TPM be automatically provisioned (enabled, activated, and owned) by Windows 8 and later OSes? 
1. If the model ships with a TPM, does the TPM that support the Physical Presence Interface specification? 
1. If the model ships with a TPM that supports the Physical Presence Interface specification, what version of the PPI specification does it implement (1.0, 1.1, 1.2)? 
1. Has the model been tested with Credential Guard enabled? 
1. Has the model been tested with Device Guard enabled? 
1. Does the model require a firmware update to fix issues that may prevent Credential Guard or Device Guard from working? 
1. If the model require a firmware update to fix issues with Credential Guard or Device Guard, what is the version information for the update? 
1. Does the model support deploying firmware updates using the Windows UEFI Firmware Update Platform specification? 
1. Does the model officially support Windows 10? 
1. If the model does not officially support Windows 10, then is there knowledge (e.g. customer reports, internal testing) of it working with Windows 10? 
1. Has the model passed a Windows Hardware Certification Program? 
1. If the model passed a Windows Hardware Certification Program, then which OS version of the certification program was the model tested for? 

### Request for Answers

Both OEMs and DoD administrators are requested to provide answers for the above questions. There are answer templates available in [markdown](./Template.md), [CSV](./Template.csv), and [Excel](./Template.xlsx) formats. There are number of ways to contribute answers:
* [Submit an issue](https://github.com/iadgov/Secure-Host-Baseline/issues/new) in [this repository's issue tracker](https://github.com/iadgov/Secure-Host-Baseline/issues) that contains answers to the questions for a model or for a number of models. 
* [Submit an issue](https://github.com/iadgov/Secure-Host-Baseline/issues/new) and [attach a file](https://help.github.com/articles/file-attachments-on-issues-and-pull-requests/) using the [CSV](./Template.csv) or [Excel](./Template.xlsx) template that contains answers for a model or for a number of models. Please do not attach Excel files as they will not be accepted. If using the Excel template, then please convert the output to CSV in Excel by going to **File** > **Save As** and selecting **CSV (Comma delimited) (\*.csv)**.
* [Submit a pull request](https://help.github.com/articles/creating-a-pull-request/) with a modification to an existing answer for an OEM or use the [Markdown template](./Template.md) to add a new OEM. See [this page](https://help.github.com/articles/using-pull-requests/) for more information on using pull requests.

Cataloging answers in [one location](./) is more efficient than having individual DoD components ask OEMs for this information. DoD administrators can also contribute by submitting answers based on their own testing. 

### Answers

* [Microsoft](./Microsoft/Microsoft.md)

## Other links

* [List of Dell models tested for upgrade to Windows 10](http://www.dell.com/support/article/us/en/19/SLN297954)
* [List of Intel processors that support 64-bit, VT-x, EPT, and VT-d](http://ark.intel.com/Search/Advanced?s=t&InstructionSet=64-bit&VTX=true&ExtendedPageTables=true&VTD=true)
* [What's new in Windows 10 security: Windows 10 hardware considerations](https://technet.microsoft.com/en-us/library/mt637125(v=vs.85).aspx#hardware)