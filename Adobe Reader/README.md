# Adobe Reader DC

The Group Policy Object, Templates and scripts in this folder are for the configuration and  compliance of the continuous version of Adobe Reader DC (ARDC) in a Windows environment. The  setting implemented in these GPO's are from NSA/IAD's Guidance Paper "Recommendations for Configuring Adobe Acrobat Reader DC in a Windows Environment" which aligns with guidance in the DISA STIG for ARDC. Recommendations focus on enabling enhanced security features without sacrificing usability features.

### Updating the Reader DC Policy templates for a domain 

If the domain administrators have configured a [Group Policy Central Store](https://support.microsoft.com/en-us/kb/929841) for the domain, then copy the **ReaderDC.admx** file to **\\\\_Fully Qualified Domain Name_\SYSVOL\\_Fully Qualified Domain Name_\Policies\PolicyDefinitions\\** and copy the **ReaderDC.adml** file to **\\\\_Fully Qualified Domain Name_\SYSVOL\\_Fully Qualified Domain Name_\Policies\PolicyDefinitions\en-us\\**

If the domain administrators have **not** configured a Group Policy Central Store for the domain, then copy the **ReaderDC.admx** file to **%SystemRoot%\PolicyDefinitions\\**, typically **C:\Windows\PolicyDefinitions\\**, and copy the **ReaderDC.adml** file to **%SystemRoot%\PolicyDefinitions\en-us\\** folder on the domain controller.

### Updating the Reader DC Policy templates for a standalone system 

**%SystemRoot%\PolicyDefinitions\\**, typically **C:\Windows\PolicyDefinitions\\**, contains Group Policy templates used by Local Group Policy on a standalone system. Copy the **ReaderDC.admx** file to **%SystemRoot%\PolicyDefinitions\\** and copy the **ReaderDC.adml** file  to **%SystemRoot%\PolicyDefinitions\en-us\\** folder on the domain controller.

## Aquire Reader DC
[Adobe Reader DC Download](https://get.adobe.com/reader/)

## Guidance
NSA/IAD has a security guide for Reader DC called [Recommendations for Configuring Adobe Acrobat Reader DC in a Windows Environment](https://www.iad.gov:8443/iad/library/ia-guidance/security-configuration/applications/recommendations-for-configuring-adobe-acrobat-reader-dc-in-a-windows-environment.cfm)