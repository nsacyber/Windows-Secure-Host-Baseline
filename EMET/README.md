# EMET 5.5
[Group Policy Object](./Group Policy Objects/Computer/) and [Group Policy template files](./Group Policy Template/) for EMET 5.5 policies are included in the SHB. [EMET](https://technet.microsoft.com/en-us/security/jj653751) is one way of enabling anti-exploitation features in Windows. [Enabling anti-exploitation features](https://www.iad.gov/iad/library/ia-guidance/security-tips/anti-exploitation-features.cfm) is on of the [Top 10 Information Assurance mitigation strategies](https://www.iad.gov/iad/library/ia-guidance/iads-top-10-information-assurance-mitigation-strategies.cfm).


EMET 5.5 added official support for Windows 10. Other significant changes of interest in EMET 5.5 are:
1. Full support for configuring all EMET features through Group Policy.
1. Changing the system DEP setting through Group Policy no longer causes a BitLocker key recovery prompt since the DEP setting is no longer changed in that case.
1. The ability to selectively override individual application mitigation settings for applications that are configured via one of the "Default Protections for" Group Policy settings.

Note that EMET 5.5 supports ends on [January 27, 2017](https://support.microsoft.com/en-us/kb/2458544).

## Downloads for EMET 5.5

* [EMET 5.5](https://www.microsoft.com/en-us/download/details.aspx?id=50766) 
* [EMET 5.5 User Guide](https://www.microsoft.com/en-us/download/details.aspx?id=50802) 
* [EMET 5.5 converter script](https://www.microsoft.com/en-us/download/details.aspx?id=50801) and [instructions](https://www.microsoft.com/en-us/download/details.aspx?id=50801&fa43d42b-25b5-4a42-fe9b-1634f450f5ee=True) 

## Updating the EMET Group Policy templates

The latest version of the Group Policy template files for EMET are included in **_%ProgramFiles%\\EMET 5.5\\Deployment\\Group Policy Files\\_** or **_%ProgramFiles(x86)%\\EMET 5.5\\Deployment\\Group Policy Files\\_**. Copy the following files:
* EMET.admx
* EMET.adml


The Group Policy template files need to be copied to specific a location on the file system. The location to copy the files to varies depending on if it is a domain versus a standalone system.

### Updating the EMET Group Policy templates for a domain 

If the domain administrators have configured a [Group Policy Central Store](https://support.microsoft.com/en-us/kb/929841) for the domain, then copy the **EMET.admx** file to **\\\\_Fully Qualified Domain Name_\SYSVOL\\_Fully Qualified Domain Name_\Policies\PolicyDefinitions\\** and copy the **EMET.adml** file to **\\\\_Fully Qualified Domain Name_\SYSVOL\\_Fully Qualified Domain Name_\Policies\PolicyDefinitions\en-us\\**


If the domain administrators have **not** configured a Group Policy Central Store for the domain, then copy the **EMET.admx** file to **%SystemRoot%\PolicyDefinitions\\**, typically **C:\Windows\PolicyDefinitions\\**, and copy the **EMET.adml** file to **%SystemRoot%\PolicyDefinitions\en-us\\** folder on the domain controller.

### Updating the EMET Group Policy templates for a standalone system 

**%SystemRoot%\PolicyDefinitions\\**, typically **C:\Windows\PolicyDefinitions\\**, contains Group Policy templates used by Local Group Policy on a standalone system. Copy the **EMET.admx** file to **%SystemRoot%\PolicyDefinitions\\** and copy the **EMET.adml** file to **%SystemRoot%\PolicyDefinitions\en-us\\** folder on the domain controller.

## EMET configuration tips
In EMET 5.5 the Application Configuration policy setting can be used to selectively override individual application mitigation settings for applications that are configured via one of the "Default Protections for" Group Policy settings. Prior to EMET 5.5 administrators would have likely directly edited the EMET.admx file to make changes but that is no longer necessary. The following examples assume these EMET Group Policy settings are enabled:
* Default Protections for Internet Explorer 
* Default Protections for Popular Software
* Default Protections for Recommended Software

### Overriding an application's ASR or EAF+ configuration
Assuming the above policies are enabled, the following example overrides Internet Explorer's default Attack Surface Reduction (ASR) module list configuration of **npjpi\*.dll;jp2iexp.dll;vgx.dll;msxml4\*.dll;wshom.ocx;scrrun.dll;vbscript.dll** to *remove* **vbscript.dll** from the list. This example demonstrates how to change the configuration when a  third-party component is loaded into Internet Explorer that is not compatible with ASR being configured for a specific module.

1. Go to **Computer Policy** > **Administrative Templates** > **Windows Components** > **EMET**
1. Double click **Application Configuration**
1. Select the **Enabled** radio button
1. Click the **Show** button
1. For **Value name** enter **\*\\iexplore.exe**
1. For **Value** enter **+ASR asr_modules:npjpi\*.dll;jp2iexp.dll;vgx.dll;msxml4\*.dll;wshom.ocx;scrrun.dll asr_zones:1;2**
1. Click **OK**
1. Click **OK**
1. Run **gpupdate /force** from the command line on a test system


Another common scenario is using ASR to temporarily disable Flash due to a zero day. Changing the ASR configuration can be used to block Flash from loading in Internet Explorer. Follow the same steps above but change the **Value** entry for Internet Explorer to 
**+ASR asr_modules:npjpi\*.dll;jp2iexp.dll;vgx.dll;msxml4\*.dll;wshom.ocx;scrrun.dll;vbscript.dll;Flash\*.ocx asr_zones:1;2** to block Flash from loading in Internet Explorer. 


Note that the asr_zones option **exempts** certain Internet Explorer security zones from ASR protection. The values for the asr_zones option are:
* 0 = Local Zone
* 1 = Intranet Zone
* 2 = Trusted Zone
* 3 = Internet Zone
* 4 = Untrusted Zone


The **asr_zones:1;2** option with those specific numbers means "Exempt the Intranet Zone and Trusted Zone from ASR protections".


Changing an application's Export Address Table Access Filtering Plus (EAF+) mitigation is similar to changing ASR. For **Value** enter **+EAF+ eaf_modules:npjpi\*.dll;jp2iexp.dll;vgx.dll;msxml4\*.dll;wshom.ocx;scrrun.dll;vbscript.dll;Flash\*.ocx** or whatever value you wish to change the configuration to.


Other examples of how to configure the Application Configuration policy can be taken from the registry path under **HKLM\\Software\\Policies\\Microsoft\\EMET\\Defaults\\**. The **Name** value is what is entered in **Value name** field in the GPO and the **Data** value is what is entered in the **Value** field in the GPO.

### Overriding a specific application mitigation

1. **Computer Configuration** > **Administrative Templates** > **Windows Components** > **EMET**
1. Double click **Application Configuration**
1. Select the **Enabled** radio button
1. Click the **Show** button
1. For **Value name** enter **\*\\iexplore.exe**
1. For **Value** enter **-EAF -EAF+**
1. Click **OK**
1. Click **OK**
1. Run **gpupdate /force** from the command line on a test system


The above example disables Export Address Table Access Filtering (EAF) and Export Address Table Access Filtering Plus (EAF+) for the application.


Other examples of how to configure the Application Configuration policy can be taken from the registry path under **HKLM\\Software\\Policies\\Microsoft\\Defaults\\**. The **Name** value is what is entered in **Value name** field in the GPO and the **Data** value is what is entered in the **Value** field in the GPO.

### Blocking the regsvr32 application whitelisting bypass technique
EMET's ASR protection can be used to block the [regsvr32 application whitelisting bypass technique](http://subt0x10.blogspot.com/2016/04/bypass-application-whitelisting-script.html). This technique is not specific to AppLocker.

1. Go to **Computer Policy** > **Administrative Templates** > **Windows Components** > **EMET**
1. Double click **Application Configuration**
1. Select the **Enabled** radio button
1. Click the **Show** button
1. For **Value name** enter **\*\\regsvr32.exe**
1. For **Value** enter **+ASR asr_modules:scrobj.dll;scrrun.dll**
1. Click **OK**
1. Click **OK**
1. Run **gpupdate /force** from the command line

Below is a screenshot of the Group Policy configuration.
![EMET Group Policy configuration to block regsvr32 application whitelisting bypass](./images/emet group policy block regsvr32 sct file.png?raw=true)

Below is a screenshot of the test of the of the Group Policy configuration and the notification from EMET.
![EMET notification block regsvr32 application whitelisting bypass](./images/emet notification block regsvr32 sct file.png?raw=true)

Below is a screenshot of the EMET event log event as a result of the test.
![EMET event log block regsvr32 application whitelisting bypass](./images/emet event log block regsvr32 sct file.png?raw=true)

### Blocking one rundll32 application whitelisting bypass technique
Another application whitelisting bypass technique uses rundll32.exe to execute Javascript. This technique was used by the Win32\Poweliks malware. This technique is not specific to AppLocker.

1. Go to **Computer Policy** > **Administrative Templates** > **Windows Components** > **EMET**
1. Double click **Application Configuration**
1. Select the **Enabled** radio button
1. Click the **Show** button
1. For **Value name** enter **\*\\rundll32.exe**
1. For **Value** enter **+ASR asr_modules:mshtml.dll**
1. Click **OK**
1. Click **OK**
1. Run **gpupdate /force** from the command line

You can also use **+ASR asr_modules:mshtml.dll;jscript\*.dll** for step 6 but that may block too many legitimate use cases of regsvr32 loading jscript. Administrators may want to test with both combinations to determine the operational impact from additionally blocking jscript from loading.

### Blocking malicious OLE packages in Microsoft Office products
Object Linking and Embedding (OLE) packages can be used to embed executable content in Microsoft Office documents. OLE packages have been shown to be useful in [executing potentially malicious content that Outlook would normally prevent](https://medium.com/@networksecurity/oleoutlook-bypass-almost-every-corporate-security-control-with-a-point-n-click-gui-37f4cbc107d0). The configuration below overrides the built-in default EMET policies for Excel, PowerPoint, Word, Outlook, InfoPath, Publisher, and Visio by adding the OLE unpacking library to the list of modules to block from loading. This configuration prevents this technique from being used in those applications. 

1. Go to **Computer Policy** > **Administrative Templates** > **Windows Components** > **EMET**
1. Double click **Application Configuration**
1. Select the **Enabled** radio button
1. Click the **Show** button
1. For **Value name** enter **\*\\OFFICE1\*\\EXCEL.EXE**
1. For **Value** enter **+ASR asr_modules:flash\*.ocx;packager.dll**
1. For **Value name** enter **\*\OFFICE1\*\POWERPNT.EXE**
1. For **Value** enter **+ASR asr_modules:flash\*.ocx;packager.dll**
1. For **Value name** enter **\*\OFFICE1\*\WINWORD.EXE**
1. For **Value** enter **+ASR asr_modules:flash\*.ocx;packager.dll**
1. For **Value name** enter **\*\OFFICE1\*\OUTLOOK.EXE**
1. For **Value** enter **+ASR asr_modules:packager.dll**
1. For **Value name** enter **\*\OFFICE1\*\INFOPATH.EXE**
1. For **Value** enter **+ASR asr_modules:packager.dll**
1. For **Value name** enter **\*\OFFICE1\*\MSPUB.EXE**
1. For **Value** enter **+ASR asr_modules:packager.dll**
1. For **Value name** enter **\*\OFFICE1\*\VISIO.EXE**
1. For **Value** enter **+ASR asr_modules:packager.dll**
1. Click **OK**
1. Click **OK**
1. Run **gpupdate /force** from the command line

## On EMET bypasses
Over the years there have been techniques published for bypassing EMET. Sometimes a future version of EMET fixes the bypass technique and sometimes it does not. As with any security software, a dedicated and skilled attacker will find a way to bypass it and EMET is no different. The fact that a bypass technique exists for EMET is not an excuse to uninstall EMET from a system. If that was the case, then no one would install anti-virus software or use firewalls since those are bypassed by attackers every day. EMET does not introduce vulnerabilities into a system and EMET bypass techniques are not vulnerabilities since they rely on gaining successful code execution through another vulnerability. EMET has a history of stopping 0-day exploits and a list of example CVEs that EMET has blocked exploits for are listed [here](https://support.microsoft.com/en-us/kb/2909257) under the  **What are the exploits for which CVEs have been blocked by EMET?** heading.


## Guidance

IAD has published a number of EMET guides:
* [Understanding the Enhanced Mitigation Experience Toolkit - Frequently Asked Questions](https://www.iad.gov/iad/library/ia-guidance/security-configuration/operating-systems/understanding-the-emet-faq.cfm)
* [Microsoft's Enhanced Mitigation Experience Toolkit: A Rationale for Enabling Modern Anti-Exploitation Mitigations in Windows](https://www.iad.gov/iad/library/ia-guidance/security-configuration/operating-systems/microsofts-emet-a-rationale-for-enabling-modern.cfm)
* [Microsoft's Enhanced Mitigation Experience Toolkit Guide](https://www.iad.gov/iad/library/ia-guidance/tech-briefs/microsoft-enhanced-mitigation-experience-toolkit-a.cfm)
