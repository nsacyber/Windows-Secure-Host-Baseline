# Credential Guard

Credential Guard is required to be enabled in the SHB due to being a CAT I item in the Windows 10 STIG to prevent some common forms of credential theft attacks. Some CAT II items related to Credential Guard mentioned in the STIG are:
*	Windows 10 Version 1511 Enterprise Edition must be installed (V-63319).
*	A Trusted Platform Module (TPM), version 1.2 or later, must be enabled (V-63323).
*	Virtualization Based Security must be enabled (V-63595).

A TPM is *not* required for Credential Guard to work, but it is preferred and recommended for Credential Guard to most effectively protect a system. Windows 10 Version 1511 added support for Credential Guard to be able to use a TPM version 1.2. Windows 10 1507 only supported Credential Guard with TPM version 2.0.

## Credential Guard dependencies 
Credential Guard may be the source of concern from some DoD components about hardware compatibility for Windows 10. This section clarifies required versus optional hardware and firmware dependencies for Credential Guard.

Required dependencies for Credential Guard:
* The Enterprise edition of Windows 10 must be installed.
*	The 64-bit version of Windows 10 must be installed.
*	The processor must support 64-bit architecture.
*	The processor must support memory virtualization (Intel VT-x/AMD-Vi) and it must be enabled in the firmware.
*	The processor must support Second Level Address Translation (Intel-EPT/AMD RVI).
*	The firmware type must be Unified Extensible Firmware Interface (UEFI), rather than legacy BIOS, running in UEFI native mode instead of Compatibility Support Module (CSM) mode.
* The firmware must implemented UEFI version 2.3.1 or later.
*	The firmware must support Secure Boot and it must be enabled in the firmware.

Optional dependencies for Credential Guard:
* Trusted Platform Module version 1.2 (Windows 10 Version 1511) or version 2.0 (Windows 10 Version 1507 and later)
* IOMMU (Intel VT-d/AMD-Vi)

Most enterprise and business class models from Original Equipment Manufacturers (OEMs) that have passed the Windows Hardware Certification Program for Windows 8 or later likely satisfy the required dependencies for Credential Guard. Some enterprise and business class models released within 1-2 years before the release of Windows 8 may also support Credential Guard but may need a firmware update to support Secure Boot. Some features used by Credential Guard may need to be enabled in the firmware (Secure Boot, Intel VT-x/AMD-Vi, Intel VT-d/AMD-Vi) since some OEMs chose to disable certain features by default. In order to clarify which models satisfy the Windows 10 Credential Guard dependencies, which models may need firmware configuration changes, and which models may need firmware updates, IAD has requested OEMs provide information on a [publicly accessible web site](./../Hardware/README.md) to clarify these issues and is currently awaiting answers.

## Credential Guard configuration issues

The final determination if Windows will enable Credential Guard depends on if the system supports an IOMMU as well as the specific Group Policy value that is selected. **The behavior in some cases is unintuitive and can lead to Credential Guard not being enabled.** The Credential Guard behavior, as of Windows 10 Version 1511, is documented below based on the **Select Platform Security Level** drop down menu selection and if an IOMMU is present:
* System with an IOMMU present and enabled:
    * Selected value is **Secure Boot** - System will enable Credential Guard with DMA protection but not lock it. 
    * Selected value is **Secure Boot and DMA Protection** - System will enable Credential Guard with DMA protection and lock it.
* System without an IOMMU present *or* without the IOMMU enabled:
    * Selected value is **Secure Boot** - System will enable Credential Guard without DMA protection.
    * Selected value is **Secure Boot and DMA Protection** - System will *not* enable Credential Guard.

**When there is no IOMMU present, or it is present but not enabled, with the combination of the DMA Protection option selected results in unintuitive and undesirable behavior since Credential Guard will not be enabled.** Many enterprise and business class models produced in the last 5 years have an IOMMU (Intel VT-d/AMD-Vi) present but most OEMs have it disabled by default in the system firmware due to no compelling reason to have it enabled in the past (unlike the Intel VT-x/AMD-V virtualization extensions which are usually enabled by default).

Until this behavior is changed, the recommended Credential Guard configuration is:
1. For networks where an administrator can verify all systems have an IOMMU present and enabled, select the **Secure Boot and DMA Protection** option.
1. For networks where an administrator cannot verify all systems have an IOMMU present and enabled, select the **Secure Boot** option.

The Windows 10 STIG will allow for either **Secure Boot** or **Secure Boot and DMA Protection** even though, as of the April 2016 release, it says to select **Secure Boot and DMA Protection**. The STIG will be updated in the future to reflect allowing either value.

## Enabling Credential Guard

To enable Credential Guard:

1. Go to **Computer Configuration** > **Administrative Templates** > **System** > **Device Guard**
1. Double click the **Turn On Virtualization Based Security** policy
1. Select the **Enabled** radio button
1. From the **Select Platform Security Level** drop down, select the option that will result in the most systems having Credential Guard enabled as discussed above. 
1. Click **OK**

Windows 10 Version 1507 did not have the **Credential Guard Configuration** drop down menu. Its default behavior was equivalent to **Enabled with UEFI lock**. The Windows 10 STIG does not specify a specific value.

## Detecting if an IOMMU is enabled

It is difficult to detect if a system has an IOMMU present but disabled. The case of when an IOMMU is present and enabled can be reliably detected though. Use the **Test-IsIOMMUEnabled** function in the [Hardware PowerShell script](./../Hardware/Scripts/Hardware.ps1) to detect if an IOMMU is enabled. It cannot detect if an IOMMU is present but disabled.

## Detecting if Credential Guard is enabled
