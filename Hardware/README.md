# Hardware and Firmware Recommendations for an SHB System

Microsoft provides a clear list of which security features in Windows 10 use certain hardware and firmware features in the [What's new in Windows 10 security: Windows 10 hardware considerations](https://technet.microsoft.com/en-us/library/mt637125(v=vs.85).aspx#hardware) article. The notation in the table is **R** = recommended, **Y** = required, and **N** = not used.

## Ideal properties of an SHB system
Properties of an ideal system for Windows 10 Secure Host Baseline include:
* Processor supports 64-bit instructions.
* Firmware type is Unified Extensible Firmware Interface (UEFI) and implements UEFI specification version 2.3.1 Errata C or higher.
* Firmware is in UEFI native mode by default (if a firmware configuration option is provided) rather than Legacy mode aka Compatibility Support Module (CSM) mode.
* Firmware supports Secure Boot and Secure Boot is enabled by default (if a firmware configuration option is provided).
* Processor supports memory virtualization (Intel VT-x or AMD-V) and the firmware has memory virtualization enabled by default (if a firmware configuration option is provided).
* Processor supports IOMMU device virtualization (Intel Vt-d or AMD-Vi) and the firmware has IOMMU device virtualization enabled by default (if a firmware configuration option is provided).
* Processor supports Second Level Address Translation (Intel EPT or AMD-RVI).
* System has a Trusted Platform Module (TPM), at least version 1.2, but version 2.0 is recommended if available.
* TPM implements the Physical Presence Interface specification 1.2 or later.
* TPM is enabled and activated by default (if a firmware configuration option is provided) or can be automatically provisioned by Windows 8 or later.
* Firmware supports, and is compatible with, Credential Guard and Device Guard.
* Device drivers are compatible ([1](https://blogs.msdn.microsoft.com/windows_hardware_certification/2015/10/29/new-device-level-test-to-be-included-as-part-of-the-compatibility-program-in-november-2015/),[2](https://blogs.msdn.microsoft.com/windows_hardware_certification/2015/05/22/driver-compatibility-with-device-guard-in-windows-10/)) with Device Guard and Virtualization-based protection of code integrity aka Hypervisor-based Code Integrity (HVCI).
* System supports firmware updates using Windows UEFI Firmware Update Platform specification (optional, but recommended).
* System has passed a Windows Microsoft Hardware Certification Program for at least Windows 8, but preferably for Windows 10.

**A system that satisfies the above properties should work out-of-the-box with [Credential Guard](../Credential Guard), [Device Guard](../Device Guard), and Virtualization-based protection of code integrity.**

A list of Intel processors that support 64-bit, VT-x, EPT, and VT-d is available [here](http://ark.intel.com/Search/Advanced?s=t&InstructionSet=64-bit&VTX=true&ExtendedPageTables=true&VTD=true). A similar list for AMD processors that support 64-bit, AMD-V, AMD-RVI, and AMD-Vi could not be found.

## Hardware and firmware survey
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
1. If the model has UEFI firmware, does it implement the [MemoryOverwriteRequestControl/MemoryOverwriteRequestControlLock](https://msdn.microsoft.com/en-us/windows/hardware/drivers/bringup/device-guard-requirements) UEFI variables (aka Secure MOR) and enable the lock? 
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

### Request for answers

Both OEMs and DoD administrators are requested to provide answers for the above questions. There are answer templates available in [markdown](./Template.md), [CSV](./Template.csv), and [Excel](./Template.xlsx) formats. There are number of ways to contribute answers:
* [Submit an issue](https://github.com/iadgov/Secure-Host-Baseline/issues/new) in [this repository's issue tracker](https://github.com/iadgov/Secure-Host-Baseline/issues) that contains answers to the questions for a model or for a number of models. 
* [Submit an issue](https://github.com/iadgov/Secure-Host-Baseline/issues/new) and [attach a file](https://help.github.com/articles/file-attachments-on-issues-and-pull-requests/) using the [CSV](./Template.csv) or [Excel](./Template.xlsx) template that contains answers for a model or for a number of models. Please do not attach Excel files as they will not be accepted. If using the Excel template, then please convert the output to CSV in Excel by going to **File** > **Save As** and selecting **CSV (Comma delimited) (\*.csv)**.
* [Submit a pull request](https://help.github.com/articles/creating-a-pull-request/) with a modification to an existing answer for an OEM or use the [Markdown template](./Template.md) to add a new OEM. See [this page](https://help.github.com/articles/using-pull-requests/) for more information on using pull requests.

Cataloging answers in [one location](./) is more efficient than having individual DoD components ask OEMs for this information. DoD administrators can also contribute by submitting answers based on their own testing. 

### Answers

* [Microsoft](./Microsoft/Survey.md)
* [Dell](./Dell/Survey.md)

## STIG items related to hardware and firmware dependencies
Directly related:
* V-63323: Domain-joined systems must have a Trusted Platform Module (TPM) enabled and ready for use. 
* V-63595: Virtualization Based Security must be enabled with the platform security level configured to Secure Boot only *or* Secure Boot and DMA Protection. 
* V-63599: Credential Guard must be running on domain-joined systems.
* V-63603: Virtualization-based protection of code integrity must be enabled on domain-joined systems.

Indirectly related:
* V-63319: Domain-joined systems must use Windows 10 Enterprise Edition.
* V-63327: System firmware or system controllers must have administrator accounts/passwords configured.
* V-63331: The system must not use removable media as the boot loader.
* V-63365: Users must not be allowed to run virtual machines in Hyper-V on the system.

## Potential hardware and firmware issues
These section mentions some potential hardware and firmware issues related to Windows 10 security features that leverage specific hardware and firmware dependencies.
*	Many systems do not have their TPM enabled and activated by default. Some OEM (HP and Dell) enterprise class systems can have their TPMs automatically enabled using free OEM provided tools.
*	Windows 8+ is capable of automatically enabling and activating a TPM, but many older TPMs (>3-4 years) can’t be automatically enabled and activated using Windows 8+. 
*	TPM ownership must have been performed by Windows rather than third-party software.
*	Many older systems (>4 years) do not support UEFI firmware.
*	Many systems that support UEFI firmware are shipped in Legacy (aka CSM) mode by default rather than in native mode. Some OEM (HP and Dell) enterprise class systems can change UEFI mode to native mode with free OEM provided tools, but the operating system will need to be re-installed after the change. Secure Boot requires systems to be in UEFI native mode.
*	Many older systems (>4 years) do not support Secure Boot . 
*	Some older systems (3-4 years ago around the release of Windows 8) support Secure Boot but may need a firmware update to support Secure Boot.
*	Even if the firmware supports Secure Boot, some systems may have Option ROMs (a firmware component) that do not support Secure Boot. This is more common in systems that may have SCSI or other storage controllers.
*	64-bit was not widely supported by processors until about Windows 7 even though it has been more common in Intel processors since 2007/2008. 
*	SLAT was not widely supported by processors until about Windows 8 even though it has been more common in Intel processors since 2008/2009.  
*	VT-x was not widely supported by processors until about Windows 7 even though it has been more common in Intel processors since 2007/2008. 
*	Older systems (>5 years ago) shipped with VT-x disabled by default in the firmware. Newer systems (<3-4 years) typically have VT-x enabled by default. Some OEM (HP and Dell) enterprise class systems can have VT-x automatically enabled with free OEM provided tools.
*	Vt-d was not widely supported by processors until about Windows 7 SP1 even though it has been more common in Intel processors since 2011/2012.
*	Vt-d is generally disabled by default in the firmware. Some OEM (HP and Dell) enterprise class systems can have  Vt-d automatically enabled with free OEM provided tools.
* System and peripheral device drivers may not be compatible with Virtualization-based protection of code integrity aka Hypervisor-based Code Integrity (HVCI).

## Other links

* [List of Intel processors that support 64-bit, VT-x, EPT, and VT-d](http://ark.intel.com/Search/Advanced?s=t&InstructionSet=64-bit&VTX=true&ExtendedPageTables=true&VTD=true)
* [What's new in Windows 10 security: Windows 10 hardware considerations](https://technet.microsoft.com/en-us/library/mt637125(v=vs.85).aspx#hardware)
