# ActivClient

ActivClient [Group Policy Objects](./Group Policy Objects/) for [Computer](./Group Policy Objects/Computer/) policy and [Group Policy template files](./Group Policy Templates/) are included in the SHB. ActivClient is used by those who want additional smart card login features outside of the built-in Windows smart card functionality. The most significant feature is support for reading the "legacy edge" used by Common Access Cards. This page provides instructions how to [enable support](#enabling-the-us-department-of-defense-configuration) for reading the legacy edge, called the US Department of Defense configuration, and [configuring the ActivClient smart card logon credential provider](#configuring-activclient-as-the-default-logon-credential-provider) as the default logon credential provider in Windows.

## Enabling the US Department of Defense configuration
ActivClient does not enable support for the legacy edge, called the US Department of Defense configuration, by default. This configuration change can be applied at install time and can also be configured using local or domain Group Policy.

### Enabling the US Department of Defense configuration using the installer

When selecting the **Typical** installation option in the installation wizard the following features are enabled (e) and disabled (d) by default:

```
(e) ActivClient
    (e) Digital Certificate Services
        (e) Microsoft Smart Card Mini Driver Support
        (d) Microsoft Outlook Usability Enhancements
        (e) PKCS#11 Support
            (d) Firefox and Thunderbird configuration

    (e) Common Services
        (e) User Console
        (e) PIN Initialization Tool
        (e) Troubleshooting
        (d) Auto-Update Service
        (d) Card auto-update service with ActivID CMS
        (d) US Department of Defense configuration
        (d) Configuration Management
        (e) Online Help
```

The **US Department of Defense configuration** feature can be enabled after selecting the **Custom** option when using the MSI installer user interface. 


msiexec.exe can be used to facilitate automated installation of the feature. msiexec has a command line option, called [ADDLOCAL](https://msdn.microsoft.com/en-us/library/windows/desktop/aa367536(v=vs.85).aspx), that can be used to select which features to install. Using a tool such as [Orca](https://msdn.microsoft.com/en-us/library/windows/desktop/aa370557(v=vs.85).aspx) to inspect the MSI file reveals the following MSI feature names correspond to the above feature names in the installation user interface and can be used by the ADDLOCAL option:

```
(e) ActivClient
    (e) Digital
        (e) MiniDriver
        (d) Outlook
        (e) PKCS
            (d) MozillaSupport

    (e) Common
        (e) UserConsole
        (e) InitTool
        (e) Troubleshooting
        (d) SoftwareAutoUpdate
        (d) CardAutoUpdate
        (d) DeptOfDefenseConfiguration
        (d) SettingsManagement
        (e) Help
```
Use the following command to install the features that would normally be installed by selecting **Typical** while also including the **US Department of Defense configuration** feature from the installer user interface:

```
msiexec.exe /i /qn "ActivID ActivClient x64 7.1.msi" ALLUSERS=1 ADDLOCAL=ActivClient,Common,DeptofDefenseConfiguration,Digital,InitTool,MiniDriver,PKCS,Troubleshooting,UserConsole,Help
```

The US Department of Defense configuration feature from the ActivClient MSI file  appears to make 3 configuration changes to the system:
1. Enables the legacy card edge
1. Enables notification of card expiration
1. Enables notification of certificate expiration

These changes map to the following registry values:
* First change:
    * HKLM\Software\Microsoft\HID Global\SecurityModuleMW\DiscoveryProvider\CardEdge\
    * Name: DefaultCardEdge
    * Value: 1
    * Type: DWORD
* Second change:
    * HKLM\Software\HID Global\ActivClient\Notifications\CardValidity\
    * Name: EnableCardValidityCheck
    * Value: 1
    * Type: DWORD
* Third change:
    * HKLM\Software\HID Global\ActivClient\Notifications\CardValidity\
    * Name: EnableCertificateValidityCheck
    * Value: 1
    * Type: DWORD

### Enabling the US Department of Defense configuration using Group Policy
Once the [ActivClient Group Policy templates](./Group Policy Templates/) have been copied to the PolicyDefinitions folder, local and domain Group Policy editing tools can be used to enable the US Department of Defense configuration. Make 3 policy changes to enable the US Department of Defense configuration, and recreate the same settings that the installer configures, through Group Policy:

* First policy:
    1. Browse to **Computer Configuration** > **Administrative Templates** > **HID Global** > **ActivClient** > **Smart Card**
    1. Double click the **Turn on US Department of Defense configuration** policy 
    1. Select the **Enabled** radio button
    1. Click the **OK** button
* Second policy:
    1. Browse to **Computer Configuration** > **Administrative Templates** > **HID Global** > **ActivClient** > **Notifications Management**
    1. Double click the **Display Card Expiration notification** policy 
    1. Select the **Enabled** radio button
    1. Click the **OK** button
* Third policy:
    1. Browse to **Computer Configuration** > **Administrative Templates** > **HID Global** > **ActivClient** > **Notifications Management**
    1. Double click the **Display Certificate Expiration notification** policy 
    1. Select the **Enabled** radio button
    1. Click the **OK** button

These policies correspond to the following registry values.

* Enabling the **Turn on US Department of Defense configuration** policy configures the following registry value:
    * Path: HKLM\Software\Microsoft\HID Global\SecurityModuleMW\DiscoveryProvider\CardEdge\ 
    * Name: DefaultCardEdge 
    * Value: 1 
    * Type: DWORD 
* Enabling the **Display Card Expiration notification** policy configures the following registry value:
    * Path: HKLM\Software\Policies\HID Global\ActivClient\Notifications\CardValidity\ 
    * Name: EnableCardValidityCheck 
    * Value: 1 
    * Type: DWORD 
* Enabling the **Display Certificate Expiration notification** policy configures the following registry value:
    * Path: HKLM\Software\Policies\HID Global\ActivClient\Notifications\CertificateValidity\ 
    * Name: EnableCertificatesValidityCheck 
    * Value: 1 
    * Type: DWORD 
    

The provided Group Policy Object implements these 3 policies plus the policy from the [Configuring ActivClient as the default logon credential provider](#configuring-activclient-as-the-default-logon-credential-provider) section.

## Configuring ActivClient as the default logon credential provider
In addition to activating the US Department of Defense configuration option for ActivClient, administrators may want the smart card logon prompt to be the default logon prompt. Windows displays a logon prompt that prompts for a password by default but this behavior can be changed by enabling and configuring a Group Policy setting. To enable and configure the ActivClient smart card logon credential provider (NOT the built-in Windows smart card logon  credential provider) through Group Policy:

1. Browse to **Computer Configuration** > **Administrative Templates** > **System** > **Logon**
1. Double click the **Assign a default credential provider** policy
1. Select the **Enabled** radio button
1. Enter the value of **{05A69B2E-F05A-426b-BB43-7895A67B1A56}** in the **Assign the following credential provider as the default credential provider** text box
1. Click the **OK** button

## About the ActivClient smart card logon credential provider
The ActivClient smart card logon credential provider, ac.mscredprov.pincache, has a GUID of {05A69B2E-F05A-426b-BB43-7895A67B1A56}. After installing ActivClient, this GUID can be found as a registered credential provider under:
* HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\
* HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\

The corresponding files on the file system are:
* C:\Program Files\HID Global\ActivClient\ac.mscredprov.pincache.dll
* C:\Program Files (x86)\HID Global\ActivClient\ac.mscredprov.pincache.dll

## Updating the ActivClient Group Policy templates
The Group Policy template files need to be copied to specific a location on the file system. The location to copy the files to varies depending on if it is a domain versus a standalone system.

### Updating the ActivClient Group Policy templates for a domain 

If the domain administrators have configured a [Group Policy Central Store](https://support.microsoft.com/en-us/kb/929841) for the domain, then copy the **HIDGlobal.ActivClient.admx**, **HIDGlobal.admx**, **HIDGlobal.AdvancedDiagnostics.admx**, and **HIDGlobal.Logging.admx** files to **\\\\_Fully Qualified Domain Name_\\SYSVOL\\_Fully Qualified Domain Name_\\Policies\\PolicyDefinitions\\** and copy the copy the **HIDGlobal.ActivClient.adml**, **HIDGlobal.adml**, **HIDGlobal.AdvancedDiagnostics.adml**, and **HIDGlobal.Logging.adml** files to **\\\\_Fully Qualified Domain Name_\\SYSVOL\\_Fully Qualified Domain Name_\\Policies\\PolicyDefinitions\\en-us\\**

If the domain administrators have **not** configured a Group Policy Central Store for the domain, then copy  the **HIDGlobal.ActivClient.admx**, **HIDGlobal.admx**, **HIDGlobal.AdvancedDiagnostics.admx**, and **HIDGlobal.Logging.admx** files to **%SystemRoot%\PolicyDefinitions\\**, typically **C:\\Windows\\PolicyDefinitions\\**, and copy the **HIDGlobal.ActivClient.adml**, **HIDGlobal.adml**, **HIDGlobal.AdvancedDiagnostics.adml**, and **HIDGlobal.Logging.adml** files to **%SystemRoot%\\PolicyDefinitions\\en-us\\** folder on the domain controller.

### Updating the ActivClient Group Policy templates for a standalone system 

**%SystemRoot%\\PolicyDefinitions\\**, typically **C:\\Windows\\PolicyDefinitions\\**, contains Group Policy templates used by Local Group Policy on a standalone system. Copy the **ReaderDC.admx** file to **%SystemRoot%\\PolicyDefinitions\\** and copy the **HIDGlobal.ActivClient.adml**, **HIDGlobal.adml**, **HIDGlobal.AdvancedDiagnostics.adml**, and **HIDGlobal.Logging.adml** files to **%SystemRoot%\\PolicyDefinitions\\en-us\\** folder on the domain controller.

## Importing the ActivClient Group Policy

### Importing the ActivClient domain Group Policy
Use the PowerShell Group Policy commands to import the ActivClient Group Policy into a domain. Run the following command on a domain controller from a PowerShell prompt running as a domain administrator. 

```
Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'ActivClient'
```

### Importing the ActivClient local Group Policy
Use Microsoft's LGPO tool to apply the ActiveClient Group Policy to a standalone system. Run the following command from a command prompt running as a local administrator.

```
Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'ActivClient' -ToolPath '.\LGPO\lgpo.exe'
```