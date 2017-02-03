# ActivClient

[Group Policy Objects](./Group Policy Objects/) for [Computer](./Group Policy Objects/Computer/) policy and [Group Policy template files](./Group Policy Templates/) are included in the SHB for ActivClient. ActivClient is used by those who want additional smart card login features outside of the standard, built-in Windows smart card functionality. The most significant feature is support for the "legacy edge" used by Common Access Cards.



## Activating the Department of Defense configuration
ActivClient does not enable support for the legacy edge, the Department of Defense configuration, by default. This configuration change can be made at install time or made by configuring local or domain Group Policy

### Activating the Department of Defense configuration using the installer

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

msiexec has a command line option, called [ADDLOCAL](https://msdn.microsoft.com/en-us/library/windows/desktop/aa367536(v=vs.85).aspx), that can be used to select which features to install by default. Using a tool such as [Orca](https://support.microsoft.com/en-us/help/255905) to inspect the MSI file reveals the following features names that can be used by the ADDLOCAL option:

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
Use the following command to install the features that would normally be installed by selecting **Typical** while including the **US Department of Defense configuration** feature:

```
msiexec.exe /i /qn "ActivID ActivClient x64 7.1.msi" ALLUSERS=1 ADDLOCAL=ActivClient,Common,DeptofDefenseConfiguration,Digital,InitTool,MiniDriver,PKCS,Troubleshooting,UserConsole,Help
```

### Activating the Department of Defense configuration using Group Policy
Once the [ActivClient Group Policy templates](./Group Policy Templates/) have been copied to the PolicyDefinitions folder, local and domain Group Policy editing tools can be used to enable the US Department of Defense configuration. To  enable the US Department of Defense configuration through Group Policy:

1. Browse to **Computer Configuration** > **Administrative Templates** > **ActivIdentity** > **ActivClient** > **Smart Card**
1. Double click the **Turn on US Department of Defense configuration** policy 
1. Select the **Enabled** radio button
1. Click the **OK** button

## Configuring ActivClient as the default logon credential provider
In addition to activating the US Department of Defense configuration option for ActivClient, administrators may want the smart card logon option to be the default logon prompt. Windows displays a logon prompt that prompts for a password by default but this behavior can be changed by enabling and configuring a Group Policy setting. To enable and configure the ActivClient smart card logon provider through Group Policy:

1. Browse to **Computer Configuration** > **Administrative Templates** > **System** > **Logon**
1. Double click the **Assign a default credential provider** policy
1. Select **Enabled** radio button
1. Enter the value of **{05A69B2E-F05A-426b-BB43-7895A67B1A56}** in the **Assign the following credential provider as the default credential provider** text box
1. Click the **OK** button

The ActivClient smart card logon credential provider (ac.mscredprov.pincache) has a GUID of {05A69B2E-F05A-426b-BB43-7895A67B1A56}. After installing ActivClient, this GUID can be found as a registered credential provider under:
* HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\
* HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\

The corresponding files on the file system are:
* C:\Program Files\HID Global\ActivClient\ac.mscredprov.pincache.dll
* C:\Program Files (x86)\HID Global\ActivClient\ac.mscredprov.pincache.dll