# Chrome

[Group Policy Object](./Group Policy Objects/Computer/) and [Group Policy template files](./Group Policy Templates/) for the Chrome browser are included in the SHB. The Group Policy template files typically change when a major version of Chrome is released but not all major releases change the templates. A file diffing tool can be used to determine if changes were made to the templates between major Chrome releases. The templates are included as a convenience and may not always be updated to the templates that correspond to the latest major Chrome release. The templates currently included in this repository correspond to Chrome 52.0.2743.116 [released on August 3, 2016](https://googlechromereleases.blogspot.com/2016/08/stable-channel-update-for-desktop.html).

## Updating the Chrome Group Policy templates

The latest version of the Group Policy template files can be downloaded from https://dl.google.com/dl/edgedl/chrome/policy/policy_templates.zip The VERSION file inside the zip file should match the latest version listed at https://omahaproxy.appspot.com/win. Once the zip file has been extracted, copy the following files:
* \windows\admx\chrome.admx
* \windows\admx\en-us\chrome.adml


You can use the Get-ChromeGroupPolicyTemplate command in the [Chrome.ps1](./Scripts/Chrome.ps1) file in the [scripts folder](./Scripts) to download the Chrome Group Policy templates. Example: **Get-ChromeGroupPolicyTemplate**


Unlike Windows Group Policy templates, the Chrome Group Policy templates change fairly often. Major Chrome releases may have new policies added or current policies removed due to being deprecated. Administrators should compare the policy templates for the current version of Chrome they are using against the newly downloaded policy templates and note any additions or removals. This can be achieved by using a file comparison tool to review the changes between the two versions of the templates.


Administrators can also identify deprecated policies in Chrome by installing the new version of Chrome but not immediately updating the policy templates used in their Chrome GPO to the latest policy templates. Then administrators can check the Chrome policies tab for deprecated policies by typing **chrome://policy** in the URL bar and looking for the text **This policy has been deprecated** under the **Status** column. This notice is displayed since Chrome still recognizes the registry data associated with deprecated policies for approximately 4 major releases of Chrome before it is completely removed. Once the policy has been completely removed from Chrome the Status column will display a message of **Unknown policy**.


Before administrators update the Chrome GPO with the latest policy template they should first modify any deprecated policies currently configured in their Chrome GPO. Use the Group Policy Management Editor to set all the deprecated policies to **Not Configured**. The registry data for the deprecated policies will be removed from systems once Group Policy updates have been applied. If this procedure isn't used, then registry data for the deprecated policies will remain indefinitely and **Unknown policy** will always be displayed for the policy. Once Group Policy updates have been applied to all systems, then administrators should update their Chrome GPO to use the latest Chrome Group Policy templates and configure any newly added policies. 


The Group Policy template files need to be copied to specific a location on the file system. The location to copy the files to varies depending on if it is a domain versus a standalone system.

### Updating the Chrome Group Policy templates for a domain 

If the domain administrators have configured a [Group Policy Central Store](https://support.microsoft.com/en-us/kb/929841) for the domain, then copy the **chrome.admx** file to **\\\\_Fully Qualified Domain Name_\\SYSVOL\\_Fully Qualified Domain Name_\\Policies\\PolicyDefinitions\\** and copy the **chrome.adml** file to **\\\\_Fully Qualified Domain Name_\SYSVOL\\_Fully Qualified Domain Name_\\Policies\\PolicyDefinitions\\en-us\\**


If the domain administrators have **not** configured a Group Policy Central Store for the domain, then copy the **chrome.admx** file to **%SystemRoot%\\PolicyDefinitions\\**, typically **C:\\Windows\\PolicyDefinitions\\**, and copy the **chrome.adml** file to **%SystemRoot%\\PolicyDefinitions\\en-us\\** folder on the domain controller.

Follow the same steps for the Google Update Group Policy templates (GoogleUpdate.admx and GoogleUpdate.adml).

### Updating the Chrome Group Policy templates for a standalone system 

**%SystemRoot%\\PolicyDefinitions\\**, typically **C:\Windows\\PolicyDefinitions\\**, contains Group Policy templates used by Local Group Policy on a standalone system. Copy the **chrome.admx** file to **%SystemRoot%\\PolicyDefinitions\\** and copy the **chrome.adml** file to **%SystemRoot%\\PolicyDefinitions\\en-us\\** folder on the domain controller.

Follow the same steps for the Google Update Group Policy templates (GoogleUpdate.admx and GoogleUpdate.adml).

# Google Update Group Policy templates
Google Update, based on the open source [Omaha project](https://github.com/google/omaha), automatically updates Chrome to the latest version. The Group Policy template files for Google Update can be downloaded from http://dl.google.com/dl/update2/enterprise/googleupdateadmx.zip but this template rarely changes. This template is included in this repository as a convenience.

You can use the Get-GoogleUpdateGroupPolicyTemplate command in the [Chrome.ps1](./Scripts/Chrome.ps1) file in the [scripts folder](./Scripts) to download the Google Update Group Policy template. Example: **Get-GoogleUpdateGroupPolicyTemplate**

## Compliance
The [Compliance](./Compliance/) folder contains a Nessus (aka [ACAS](http://www.disa.mil/cybersecurity/network-defense/acas) in the DoD) .audit file to check compliance with the settings implemented in the Group Policy Object.

# Download Google Chrome
Download the latest enterprise/business version of Google Chrome:
* [64-bit](https://dl.google.com/edgedl/chrome/install/GoogleChromeStandaloneEnterprise64.msi) (recommended)
* [32-bit](https://dl.google.com/edgedl/chrome/install/GoogleChromeStandaloneEnterprise.msi)

The version number of Chrome the download represents is available at https://omahaproxy.appspot.com/win. You can use the Get-ChromeInstaller command in the [Chrome.ps1](./Scripts/Chrome.ps1) file in the [scripts folder](./Scripts) to download Chrome and automatically have the file named after the current Chrome version. Examples: **Get-ChromeInstaller -Architecture 64** or **Get-ChromeInstaller -Architecture 32**

# Guidance
NSA Information Assurance has a security guide for Chrome called [Deploying and Securing Google Chrome in a Windows Enterprise](https://www.iad.gov/iad/library/ia-guidance/security-configuration/applications/deploying-and-securing-google-chrome-in-a-windows-enterprise.cfm). Google has also published a [Chrome for Work Deployment Guide](https://support.google.com/chrome/a/answer/3115278?hl=en) for Windows enterprises.