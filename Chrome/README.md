# Chrome

[Group Policy Object](./Group Policy Objects/Computer/) and [Group Policy template files](./Group Policy Template/) for the Chrome browser are included in the SHB. The Group Policy template files typically change when a major version of Chrome is released but not all major releases change the templates. A file diffing tool can be used to determine if changes were made to the templates between major Chrome releases. The templates are provided as a convenience and may not always be updated to the templates that correspond to the latest major Chrome release. The templates currently included in the SHB correspond to version Chrome 49.0.2623.87 [released on March 8, 2016](http://googlechromereleases.blogspot.com/2016/03/stable-channel-update_8.html).

## Updating the Chrome Group Policy templates

The latest version of the Group Policy template files can be downloaded from http://dl.google.com/dl/edgedl/chrome/policy/policy_templates.zip The VERSION file inside the zip file should match the latest version listed at http://omahaproxy.appspot.com/win Once the zip file has been extracted, copy the following files:
* \windows\admx\chrome.admx
* \windows\admx\en-us\chrome.adml


Unlike Windows Group Policy templates, the Chrome Group Policy templates change fairly often. Major Chrome releases may have new policies added or current policies removed due to being deprecated. Administrators should compare the policy templates for the current version of Chrome they are using against the newly downloaded policy templates and note any additions or removals. This can be achieved by using a file comparison tool to review the changes between the two versions of the templates.


Administrators can also identify deprecated policies in Chrome by installing the new version of Chrome but not immediately updating the policy templates used in their Chrome GPO to the latest policy templates. Then administrators can check the Chrome policies tab for deprecated policies by typing **chrome://policy** in the URL bar and looking for the text **This policy has been deprecated** under the **Status** column. This notice is displayed since Chrome still recognizes the registry data associated with deprecated policies for approximately 4 major releases of Chrome before it is completely removed. Once the policy has been completely removed from Chrome the Status column will display a message of **Unknown policy**.


Before administrators update the Chrome GPO with the latest policy template they should first modify any deprecated policies currently configured in their Chrome GPO. Use the Group Policy Management Editor to set all the deprecated policies to **Not Configured**. The registry data for the deprecated policies will be removed from systems once Group Policy updates have been applied. If this procedure isn’t used, then registry data for the deprecated policies will remain indefinitely and **Unknown policy** will always be displayed for the policy. Once Group Policy updates have been applied to all systems, then administrators should update their Chrome GPO to use the latest Chrome Group Policy templates and configure any newly added policies. 


The Group Policy template files need to be copied to specific a location on the file system. The location to copy the files to varies depending on if it is a domain versus a standalone system.

### Updating the Chrome Group Policy templates for a domain 

If the domain administrators have configured a [Group Policy Central Store](https://support.microsoft.com/en-us/kb/929841) for the domain, then copy the **chrome.admx** file to **\\\\_Fully Qualified Domain Name_\SYSVOL\\_Fully Qualified Domain Name_\Policies\PolicyDefinitions\\** and copy the **chrome.adml** file to **\\\\_Fully Qualified Domain Name_\SYSVOL\\_Fully Qualified Domain Name_\Policies\PolicyDefinitions\en-us\\**


If the domain administrators have **not** configured a Group Policy Central Store for the domain, then copy the **chrome.admx** file to **%SystemRoot%\PolicyDefinitions\\**, typically **C:\Windows\PolicyDefinitions\\**, and copy the **chrome.adml** file to **%SystemRoot%\PolicyDefinitions\en-us\\** folder on the domain controller.

### Updating the Chrome Group Policy templates for a standalone system 

**%SystemRoot%\PolicyDefinitions\\**, typically **C:\Windows\PolicyDefinitions\\**, contains Group Policy templates used by Local Group Policy on a standalone system. Copy the **chrome.admx** file to **%SystemRoot%\PolicyDefinitions\\** and copy the **chrome.adml** file to **%SystemRoot%\PolicyDefinitions\en-us\\** folder on the domain controller.


# Google Update Group Policy template
Chrome uses Google Update to automatically update Chrome to the latest version. The Group Policy template file for Google Update can be downloaded from http://dl.google.com/update2/enterprise/GoogleUpdate.adm but this template rarely changes.

# Acquiring Googe Chrome
Download the latest enterprise/business version of Google Chrome:
* [X86](https://dl.google.com/edgedl/chrome/install/GoogleChromeStandaloneEnterprise.msi)
* [X64](https://dl.google.com/edgedl/chrome/install/GoogleChromeStandaloneEnterprise64.msi)


The version number of Chrome the download represents is available at http://omahaproxy.appspot.com/win

# Guidance
IAD has a security guide for Chrome called [Deploying and Securing Google Chrome in a Windows Enterprise](https://www.iad.gov/iad/library/ia-guidance/security-configuration/applications/deploying-and-securing-google-chrome-in-a-windows-enterprise.cfm).