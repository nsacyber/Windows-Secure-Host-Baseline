# Chrome

These folders contain the Group Policy Object and Group Policy template files for the latest major version of Chrome. The Group Policy template files typically change when a major version of Chrome is released but not all major releases change the templates. A file diffing tool can be used to determine if changes were made to the templates between major Chrome releases. The templates in this folder are provided as a convenience and may not always be updated to the templates that correspond to the latest major Chrome release.


The latest version of the Group Policy templates can be downloaded from http://dl.google.com/dl/edgedl/chrome/policy/policy_templates.zip The VERSION file inside the zip file should match the latest version listed at http://omahaproxy.appspot.com/win Once the zip file has been extracted, copy the following files:
* \windows\admx\**chrome.admx**
* \windows\admx\en-us\**chrome.adml**


Those Group Policy template files need to be copied to specific locations on the file system. The location to copy the files to varies depending on if it is a domain versus a standalone system.


## Domain 

If the domain administrators have configured a [Group Policy Central Store](https://support.microsoft.com/en-us/kb/929841) for the domain, then copy the **chrome.admx** file to **\\_Fully Qualified Domain Name_\SYSVOL\Fully Qualified Domain Name_\Policies\PolicyDefinitions\** and copy the **chrome.adml** file to **\\_Fully Qualified Domain Name_\SYSVOL\Fully Qualified Domain Name_\Policies\PolicyDefinitions\en-us\**


If the domain administrators have **not** configured a Group Policy Central Store for the domain, then copy the **chrome.admx** file to **%SystemRoot%\PolicyDefinitions**, typically **C:\Windows\PolicyDefinitions**, and copy the **chrome.adml** file to **%SystemRoot%\PolicyDefinitions\en-us\** folder on the domain controller.


The chrome.admx file should be placed directly in the PolicyDefinitions folder and the chrome.adml file should beplaced in the \PolicyDefinitions\en-us\ folder (assuming the chrome.adml file from the zip file was taken from its en-us folder).

## Standalone 

**%SystemRoot%\PolicyDefinitions**, typically **C:\Windows\PolicyDefinitions**, contains Group Policy templates used by Local Group Policy on a standalone system. Copy the **chrome.admx** file to **%SystemRoot%\PolicyDefinitions** and copy the **chrome.adml** file to **%SystemRoot%\PolicyDefinitions\en-us\** folder on the domain controller.



# Google Update
The Group Policy template file for Google Update can be downloaded from http://dl.google.com/update2/enterprise/GoogleUpdate.adm