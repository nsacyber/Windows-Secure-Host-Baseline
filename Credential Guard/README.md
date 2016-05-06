Credential Guard may be the source of concern for some DoD components about hardware compatibility for Windows 10. Credential Guard is required to be enabled due to being a CAT I item in the Windows 10 STIG to prevent common forms of credential theft attacks used against the DoD. Some CAT II items related to Credential Guard mentioned in the STIG are:
*	Windows 10 Version 1511 Enterprise Edition must be installed (V-63319).
*	A Trusted Platform Module (TPM), version 1.2 or later, must be enabled (V-63323).
*	Virtualization Based Security must be enabled (V-63595).

A TPM is not required for Credential Guard to work, but it is preferred and recommended in order to protect Credential Guard against attacks. Windows 10 Version 1511 is required because it added support for Credential Guard to be able to use a TPM version 1.2.

Dependencies for Credential Guard that are not explicit CAT items in the STIG are:
*	The 64-bit version of Windows 10 must be installed.
*	Processor must support 64-bit architecture.
*	Processor must support memory virtualization (Intel VT-x/AMD-Vi).
*	Processor must support Second Level Address Translation (Intel-EPT/AMD RVI).
*	Firmware type must be Unified Extensible Firmware Interface (UEFI), rather than legacy BIOS, running in UEFI native mode instead of Compatibility Support Module (CSM) mode and UEFI version 2.3.1 or later must be implemented.
*	Firmware must have Secure Boot enabled.

Most enterprise and business class models from Original Equipment Manufacturers (OEMs) that have passed the Windows Hardware Certification Program for Windows 8 or later likely meet the requirements for Credential Guard. Some enterprise and business class models released within 1-2 years before the release of Windows 8 may also support Credential Guard but may need a firmware update. DoD components may need to configure firmware settings to enable features needed by Credential Guard since some OEMs chose to disable certain features by default. In order to clarify which models meet or do not meet the Windows 10 Credential Guard requirements, which models may need configuration changes, and which models may need firmware updates, IAD has requested OEMs provide information on a publicly accessible web site to clarify these issues and is currently awaiting answers.