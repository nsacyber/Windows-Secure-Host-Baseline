# Adobe Reader DC

[Group Policy Objects](./Group Policy Objects/) for [User](./Group Policy Objects/User/) and [Computer](./Group Policy Objects/Computer/) policy and [Group Policy template files](./Group Policy Templates/) are included in the SHB. The settings implemented in the GPOs are from the NSA Information Assurance guidance paper [Recommendations for Configuring Adobe Acrobat Reader DC in a Windows Environment](https://www.iad.gov/iad/library/ia-guidance/security-configuration/applications/recommendations-for-configuring-adobe-acrobat-reader-dc-in-a-windows-environment.cfm). 

Using the [continuous track](http://www.adobe.com/devnet-docs/acrobatetk/tools/AdminGuide/whatsnewdc.html) version of Adobe Reader DC (ARDC) is recommended.

## Updating the Adobe Reader DC Group Policy templates
The Group Policy template files need to be copied to specific a location on the file system. The location to copy the files to varies depending on if it is a domain versus a standalone system.

### Updating the Adobe Reader DC Group Policy templates for a domain 

If the domain administrators have configured a [Group Policy Central Store](https://support.microsoft.com/en-us/kb/929841) for the domain, then copy the **ReaderDC.admx** file to **\\\\_Fully Qualified Domain Name_\\SYSVOL\\_Fully Qualified Domain Name_\\Policies\\PolicyDefinitions\\** and copy the **ReaderDC.adml** file to **\\\\_Fully Qualified Domain Name_\\SYSVOL\\_Fully Qualified Domain Name_\\Policies\\PolicyDefinitions\\en-us\\**

If the domain administrators have **not** configured a Group Policy Central Store for the domain, then copy the **ReaderDC.admx** file to **%SystemRoot%\PolicyDefinitions\\**, typically **C:\\Windows\\PolicyDefinitions\\**, and copy the **ReaderDC.adml** file to **%SystemRoot%\\PolicyDefinitions\\en-us\\** folder on the domain controller.

### Updating the Adobe Reader DC Group Policy templates for a standalone system 

**%SystemRoot%\\PolicyDefinitions\\**, typically **C:\\Windows\\PolicyDefinitions\\**, contains Group Policy templates used by Local Group Policy on a standalone system. Copy the **ReaderDC.admx** file to **%SystemRoot%\\PolicyDefinitions\\** and copy the **ReaderDC.adml** file  to **%SystemRoot%\\PolicyDefinitions\\en-us\\** folder on the domain controller.

## Importing the Adobe Reader DC Group Policy

### Importing the Adobe Reader DC domain Group Policy
Use the PowerShell Group Policy commands to import the Adobe Reader DC Group Policy into a domain. Run the following command on a domain controller from a PowerShell prompt running as a domain administrator. 

```
Import-Module GroupPolicy

Import-GPO -Path ".\Adobe Reader\Group Policy Objects\Computer\{659E383E-BA08-4166-9A33-60EC86176370}"
```
### Importing the Adobe Reader DC local Group Policy
Use Microsoft's LGPO tool to apply the Adobe Reader DC Group Policy to a standalone system. Run the following command from a command prompt running as a local administrator.

```
lgpo.exe /g ".\Adobe Reader\Group Policy Objects\Computer\{659E383E-BA08-4166-9A33-60EC86176370}"
```

## Compliance
The [Compliance](./Compliance/) folder contains a Nessus (aka [ACAS](http://www.disa.mil/cybersecurity/network-defense/acas) in the DoD) .audit file to check compliance with the settings implemented in the Group Policy Object.

## Download Adobe Reader DC

[Adobe Reader DC Download](https://get.adobe.com/reader/)

You can use the Get-AdobeReaderInstaller command in the [AdobeReader.ps1](./Scripts/AdobeReader.ps1) file in the [scripts folder](./Scripts) to download a specific version of Adobe Reader DC. Example: **Get-AdobeReaderInstaller -Version '2015.016.20039'** Adobe Reader DC version numbers that can be used with this script can be found on [Adobe Reader for Windows page](http://www.adobe.com/support/downloads/product.jsp?platform=windows&product=10).

## Managing updates
Adobe Reader DC installs a task that executes an update check every time a user logs in. After a successful update check, another update check will not occur for 3 days even though the task runs at every user login. Manually running the installed task named **Adobe Acrobat Update Task** will result in an error of *The user account does not have permission to run this task*. Systems may rarely automatically update since the task can't successfully execute. A [new task](./Adobe Reader x64 Update Task.xml) has been included in this repository which can be imported to a system using the [Register-ScheduledTask command](https://technet.microsoft.com/en-us/library/jj649811(v=wps.630).aspx).

```
Register-ScheduledTask -Xml ((Get-Content -Path '.\Secure-Host-Baseline\Adobe Reader\Adobe Reader x64 Update Task.xml') | Out-String) -TaskName 'Adobe Reader x64 Update Task'
```

The updater will also not execute if the Adobe Reader EULA has not been accepted which may result in some systems not getting updated. This behavior can be prevented by creating a **DWORD** registry value named **iDisableCheckEula** under **HKLM\Software\Adobe\Adobe ARM\1.0\ARM** and setting the value to **1**. This value can be configured using the provided Group Policy template.

## Guidance
NSA Information Assurance has a security guide for Adobe Reader DC called [Recommendations for Configuring Adobe Acrobat Reader DC in a Windows Environment](https://www.iad.gov/iad/library/ia-guidance/security-configuration/applications/recommendations-for-configuring-adobe-acrobat-reader-dc-in-a-windows-environment.cfm)

## Links
* [Adobe Reader Security Bulletins](https://helpx.adobe.com/security.html#reader)
* [Adobe Reader Updates for Windows](http://www.adobe.com/support/downloads/product.jsp?platform=windows&product=10)
* [Adobe Reader Release Notes](https://helpx.adobe.com/acrobat/release-note/release-notes-acrobat-reader.html)
* [Enterprise Toolkit for Adobe Products home page](http://www.adobe.com/devnet-docs/acrobatetk/index.html)
* [Adobe Reader Enterprise Administration Guide](http://www.adobe.com/devnet-docs/acrobatetk/tools/AdminGuide/index.html)
* [Adobe Reader Settings for Windows - HKCU](https://www.adobe.com/devnet-docs/acrobatetk/tools/PrefRef/Windows/index.html)
* [Adobe Reader Settings for Windows - HKLM](https://www.adobe.com/devnet-docs/acrobat)
* [Adobe Reader Application Security Guide](http://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/index.html)
* [Adobe Reader Updater: A configuration and user guide](http://kb2.adobe.com/cps/837/cpsid_83709/attachments/Acrobat_Reader_Updater.pdf)
* [Adobe Group Policy Templates](http://www.adobe.com/devnet-docs/acrobatetk/tools/AdminGuide/gpo.html)