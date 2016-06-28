# Credential Guard

Credential Guard is required to be enabled in the SHB due to being a CAT III item in the Windows 10 STIG to prevent some common forms of credential theft attacks. DISA was directed to make modifications to the Windows 10 STIG downgrading the Credential Guard Category I finding to a Category III finding in the **Updated Direction for the Implementation of Microsoft Windows 10 Secure Host Baseline** memo from the DoD CIO dated 06/01/2016. Note that the memo also says **Credential Guard must be enabled on Windows 10 computers that support the feature.**

## Credential Guard dependencies 
Credential Guard may be the source of concern from some DoD components about hardware compatibility for Windows 10. This section clarifies required versus optional dependencies for Credential Guard.

Required dependencies for Credential Guard:

* The Enterprise edition of Windows 10 must be installed.
*	The 64-bit version of Windows 10 must be installed.
*	The processor must support 64-bit architecture.
*	The processor must support memory virtualization (Intel VT-x/AMD-V) and it must be enabled in the firmware.
*	The processor must support Second Level Address Translation (Intel EPT/AMD RVI).
*	The firmware type must be Unified Extensible Firmware Interface (UEFI), rather than legacy BIOS, running in UEFI native mode instead of Compatibility Support Module (CSM) mode.
* The firmware must implement UEFI version 2.3.1 or later.
*	The firmware must support Secure Boot and it must be enabled in the firmware.

Optional dependencies for Credential Guard:

* Trusted Platform Module (TPM) version 1.2 (Windows 10 Version 1511) or version 2.0 (Windows 10 Version 1507 and later).
* IOMMU (Intel VT-d/AMD-Vi). 

Even though a TPM is *not* required for Credential Guard to work, it is highly recommended for Credential Guard to most effectively protect a system. A **TPM is so highly recommended that it should be considered required** similar to how TPMs are recommended, but in reality required, for BitLocker since BitLocker protection is ineffective without a TPM. Windows 10 Version 1511 added support for Credential Guard to be able to use a TPM version 1.2. Windows 10 1507 only supported Credential Guard with TPM version 2.0.

Most enterprise and business class models from Original Equipment Manufacturers (OEMs) that have passed the Windows Hardware Certification Program for Windows 8 or later likely satisfy the required dependencies for Credential Guard. Some enterprise and business class models released within 1-2 years before the release of Windows 8 may also support Credential Guard but may need a firmware update to support Secure Boot. Some features used by Credential Guard, such as Secure Boot, Intel VT-x/AMD-Vi, and Intel VT-d/AMD-Vi, may need to be enabled in the firmware since some OEMs chose to disable certain features by default. In order to clarify which models satisfy the Windows 10 Credential Guard dependencies, which models may need firmware configuration changes, and which models may need firmware updates, NSA Information Assurance has requested OEMs provide information on a [publicly accessible web site](./../Hardware/README.md) to clarify these issues and is currently awaiting answers.

## Credential Guard configuration issues

The final determination if Windows enables Credential Guard depends on if the system supports an IOMMU as well as the specific Group Policy value that is selected. **The behavior in some cases is unintuitive and can lead to Credential Guard not being enabled.** The Credential Guard behavior, as of Windows 10 Version 1511, is documented below based on the **Select Platform Security Level** drop down menu selection and if an IOMMU is present:

* System with an IOMMU present and enabled:
    * Selected value is **Secure Boot** - System will enable Credential Guard with DMA protection but not lock it. 
    * Selected value is **Secure Boot and DMA Protection** - System will enable Credential Guard with DMA protection and lock it.
* System without an IOMMU present *or* without the IOMMU enabled:
    * Selected value is **Secure Boot** - System will enable Credential Guard without DMA protection.
    * Selected value is **Secure Boot and DMA Protection** - System will *not* enable Credential Guard.

**When selecting the DMA Protection option and there is no IOMMU present, or it is present but *not* enabled, then the result is unintuitive and undesirable behavior since Credential Guard will not be enabled.** Many enterprise and business class models produced in the last 5 years have an IOMMU (Intel VT-d/AMD-Vi) present but most OEMs have it disabled by default in the system firmware due to no compelling reason to have it enabled in the past (unlike the Intel VT-x/AMD-V virtualization extensions which are usually enabled by default).

Until this behavior is changed, the recommended Credential Guard configuration is:

1. For networks where an administrator can verify all systems have an IOMMU present and enabled, select the **Secure Boot and DMA Protection** option.
1. For networks where an administrator cannot verify all systems have an IOMMU present and enabled, select the **Secure Boot** option.

Due to the unintuitive behavior where Credential Guard may not be enabled, the Windows 10 STIG will allow for either **Secure Boot** or **Secure Boot and DMA Protection** even though, as of the April 2016 release, it says to select **Secure Boot and DMA Protection**. The STIG will be updated in July to reflect allowing either value.

## Enabling Credential Guard

To enable Credential Guard:

1. Go to **Computer Configuration** > **Administrative Templates** > **System** > **Device Guard**
1. Double click the **Turn On Virtualization Based Security** policy
1. Select the **Enabled** radio button
1. From the **Select Platform Security Level** drop down, select the option that will result in the most systems having Credential Guard enabled as discussed above. 
1. From the **Credential Guard Configuration** drop down, select either option. **Enabled without UEFI lock** may be the safest option until Credential Guard is more widely used in a large scale operational environment to ensure any other issues are identified and resolved before locking it. 
1. Click **OK**

Windows 10 Version 1507 did not have the **Credential Guard Configuration** drop down menu but its default behavior was equivalent to **Enabled with UEFI lock**. The Windows 10 STIG does not specify a specific value. If the configuration is locked, then the only way to unlock the configuration (e.g. disable Credential Guard) is by having an administrator use SecConfig.efi, reboot the computer, and press a key during system boot to accept the security prompt to change the configuration. In other words, an administrator must be physically present to disable Credential Guard when the UEFI lock option is used.

## Detecting if an IOMMU is enabled

It is difficult to detect if a system has an IOMMU present but disabled. The case of when an IOMMU is present and enabled can be reliably detected though. Use the **Test-IsIOMMUEnabled** function in the [Hardware PowerShell script](./../Hardware/Scripts/Hardware.ps1) to detect if an IOMMU is enabled. It cannot detect if an IOMMU is present but disabled.

## Detecting if Credential Guard is enabled

Use the **Test-IsCredentialGuardEnabled** function in the [Hardware PowerShell script](./../Hardware/Scripts/Hardware.ps1) to detect if Credential Guard is enabled and running on a system.

## Detecting if a system is ready for Credential Guard
Use the **Test-IsSystemCredentialGuardReady** function in the [Hardware PowerShell script](./../Hardware/Scripts/Hardware.ps1) to detect if a system is ready for Credential Guard to be enabled.

## Limitations of Credential Guard
Microsoft's [Credential Guard documentation](https://technet.microsoft.com/en-us/itpro/windows/keep-secure/credential-guard) identifies it protects domain credentials such as NTLM password hashes and Kerberos Ticket Granting Tickets. Credential Guard only prevents some forms of credential theft attacks. Credentials that are exposed through the [CredSSP](https://msdn.microsoft.com/en-us/library/windows/desktop/bb931352(v=vs.85).aspx), TsPkg (Terminal Services/Remote Desktop), and [WDigest](https://msdn.microsoft.com/en-us/library/windows/desktop/aa378745(v=vs.85).aspx) security providers can still be used to steal credentials. For example, if WDigest is enabled (it is disabled by default in Windows 8.1 and later), then [mimikatz](https://github.com/gentilkiwi/mimikatz) can still be used to extract domain password hashes. Credential Guard does not protect local account credentials nor can it protect against Golden Ticket or Silver Ticket credential abuses. Microsoft lists additional limitations [here](https://technet.microsoft.com/itpro/windows/keep-secure/credential-guard#scenarios-not-protected-by-credential-guard). Despite these limitations, enabling Credential Guard is a starting point for reducing the effectiveness of credential theft attacks. Windows 10 Version 1511 added [improvements](https://technet.microsoft.com/en-us/itpro/windows/whats-new/credential-guard) to Credential Guard so future improvements may further reduce the credential theft attack surface.

## Links
* [Protect derived domain credentials with Credential Guard](https://technet.microsoft.com/en-us/itpro/windows/keep-secure/credential-guard)
* [What's new in Credential Guard?](https://technet.microsoft.com/en-us/itpro/windows/whats-new/credential-guard)
* [Credential Guard and WDigest](https://social.technet.microsoft.com/Forums/en-US/a428cc98-934d-49b0-89ec-56913e1f99f4/credentialguard-and-wdigest?forum=WinPreview2014General)