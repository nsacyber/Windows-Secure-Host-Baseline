# Adobe Reader DC

[Group Policy Objects](./Group Policy Objects/) for [User](./Group Policy Objects/User/) and [Computer](./Group Policy Objects/Computer/) policy and [Group Policy template files](./Group Policy Templates/) are included in the SHB. The settings implemented in the GPOs are from IAD guidance paper [Recommendations for Configuring Adobe Acrobat Reader DC in a Windows Environment](https://www.iad.gov/iad/library/ia-guidance/security-configuration/applications/recommendations-for-configuring-adobe-acrobat-reader-dc-in-a-windows-environment.cfm). This guidance aligns with the initial version of the DISA STIG for ARDC since STIG development was a collaborative effort. Recommendations are for the [continuous track](http://www.adobe.com/devnet-docs/acrobatetk/tools/AdminGuide/whatsnewdc.html) version of Adobe Reader DC (ARDC) and focus on enabling security features without sacrificing usability.

## Updating the Adobe Reader DC policy templates
The Group Policy template files need to be copied to specific a location on the file system. The location to copy the files to varies depending on if it is a domain versus a standalone system.

### Updating the Adobe Reader DC Policy templates for a domain 

If the domain administrators have configured a [Group Policy Central Store](https://support.microsoft.com/en-us/kb/929841) for the domain, then copy the **ReaderDC.admx** file to **\\\\_Fully Qualified Domain Name_\SYSVOL\\_Fully Qualified Domain Name_\Policies\PolicyDefinitions\\** and copy the **ReaderDC.adml** file to **\\\\_Fully Qualified Domain Name_\SYSVOL\\_Fully Qualified Domain Name_\Policies\PolicyDefinitions\en-us\\**

If the domain administrators have **not** configured a Group Policy Central Store for the domain, then copy the **ReaderDC.admx** file to **%SystemRoot%\PolicyDefinitions\\**, typically **C:\Windows\PolicyDefinitions\\**, and copy the **ReaderDC.adml** file to **%SystemRoot%\PolicyDefinitions\en-us\\** folder on the domain controller.

### Updating the Adobe Reader DC Policy templates for a standalone system 

**%SystemRoot%\PolicyDefinitions\\**, typically **C:\Windows\PolicyDefinitions\\**, contains Group Policy templates used by Local Group Policy on a standalone system. Copy the **ReaderDC.admx** file to **%SystemRoot%\PolicyDefinitions\\** and copy the **ReaderDC.adml** file  to **%SystemRoot%\PolicyDefinitions\en-us\\** folder on the domain controller.

## Compliance
The [Compliance](./Compliance/) folder contains a Nessus (aka [ACAS](http://www.disa.mil/cybersecurity/network-defense/acas) in the DoD) .audit file to check compliance with the settings implemented in the Group Policy Object.

## Download Adobe Reader DC

[Adobe Reader DC Download](https://get.adobe.com/reader/)

## Guidance
IAD has a security guide for Adobe Reader DC called [Recommendations for Configuring Adobe Acrobat Reader DC in a Windows Environment](https://www.iad.gov/iad/library/ia-guidance/security-configuration/applications/recommendations-for-configuring-adobe-acrobat-reader-dc-in-a-windows-environment.cfm)