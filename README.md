# Windows Secure Host Baseline

## About the Windows Secure Host Baseline

The Windows Secure Host Baseline (SHB) provides an automated and flexible approach for assisting the DoD in deploying the latest releases of Windows 10 using a framework that can be consumed by organizations of all sizes. 


The DoD CIO issued a memo on [November 20, 2015](http://www.esi.mil/download.aspx?id=5542) directing Combatant Commands, Services, Agencies and Field Activities (CC/S/As) to rapidly deploy the Windows 10 operating system throughout their respective organizations with the objective of completing deployment by the end of January 2017. The Deputy Secretary of Defense issued a memo on [February 26, 2016](http://www.esi.mil/download.aspx?id=5543) directing the DoD to complete a rapid deployment and transition to Microsoft Windows 10 Secure Host Baseline by the end of January 2017.[[1](http://www.esi.mil/contentview.aspx?id=685)]


Formal product evaluations also support the move to Windows 10. The [National Information Assurance Partnership](https://www.niap-ccevs.org) (NIAP) and National Institute of Standards and Technology (NIST) oversees evaluations of commercial IT products for use in [National Security Systems](https://www.iad.gov/iad/news/defining-a-national-security-system.cfm). 
* Common Criteria evaluation of Windows 10 against NIAP [Protection Profile for General Purpose Operating Systems](https://www.niap-ccevs.org/Profile/Info.cfm?id=400) completed [April 5, 2016](https://www.niap-ccevs.org/Product/CompliantCC.cfm?CCID=2016.1052) and updated [February 2, 2017](https://www.niap-ccevs.org/Product/CompliantCC.cfm?CCID=2017.1007><https://www.niap-ccevs.org/Product/CompliantCC.cfm?CCID=2017.1007) to include Windows Server 2016. 
* Common Criteria evaluation of Windows 10 against NIAP [Protection Profile for Mobile Device Fundamentals](https://www.niap-ccevs.org/Profile/Info.cfm?id=353) completed [January 29, 2016](https://www.niap-ccevs.org/Product/Compliant.cfm?pid=10677) and updated [April 12, 2017](https://www.niap-ccevs.org/Product/Compliant.cfm?pid=10752) to include Windows Server 2016. 
* Common Criteria evaluation of Windows 10 against NIAP [Protection Profile for IPsec Virtual Private Network (VPN) Clients](https://www.niap-ccevs.org/Profile/Info.cfm?id=333) completed [November 10, 2016](https://www.niap-ccevs.org/Product/Compliant.cfm?pid=10746) and updated [December 29, 2016](https://www.niap-ccevs.org/Product/Compliant.cfm?pid=10753) to include Windows Server 2016. 
* [NIST](http://www.nist.gov/) [FIPS 140-2](http://csrc.nist.gov/groups/STM/cmvp/index.html) validation of Windows 10 cryptographic modules was completed on June 2, 2016 (see certificate numbers [2600](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#2600), [2601](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#2601), [2602](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#2602), [2603](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#2603), [2604](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#2604), [2605](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#2605), [2606](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#2606), and [2607](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#2607)).

Using a [Secure Host Baseline](https://www.iad.gov/iad/library/ia-guidance/security-tips/secure-host-baseline.cfm) is one of [NSA Information Assurance top 10 mitigation strategies](https://www.iad.gov/iad/library/ia-guidance/iads-top-10-information-assurance-mitigation-strategies.cfm). The DoD Secure Host Baseline also exemplifies other IAD top 10 mitigation strategies such as using [application whitelisting](https://www.iad.gov/iad/library/ia-guidance/security-tips/application-whitelisting.cfm), enabling [anti-exploitation features](https://www.iad.gov/iad/library/ia-guidance/security-tips/anti-exploitation-features.cfm), and using the [latest version of the operating system and applications](https://www.iad.gov/iad/library/ia-guidance/security-tips/take-advantage-of-software-improvement.cfm).

## About this repository

This repository hosts Group Policy objects, compliance checks, and configuration tools in support of the DoD Secure Host Baseline (SHB) framework for Windows 10. Administrators of [National Security Systems](https://www.iad.gov/iad/news/defining-a-national-security-system.cfm), such as those who are part of the [Defense Industrial Base](https://www.dhs.gov/defense-industrial-base-sector), can leverage this repository in lieu of access to the [DoD SHB framework for Windows 10](https://disa.deps.mil/ext/cop/iase/dod-images/Pages/Win10.aspx) which requires a Common Access Card (CAC) or Personal Identification Verification (PIV) smart card to access. 

Questions or comments can be submitted to the [repository issue tracker](https://github.com/nsacyber/Windows-Secure-Host-Baseline/issues) or posted on [Windows 10 Secure Host Baseline project](https://software.forge.mil/sf/projects/win10shb) forums on Software Forge which requires a CAC or PIV smart card to access.

## Repository content

### Group Policy Objects

* The [ActivClient folder](./ActivClient/README.md) contains  ActivClient [Computer](./ActivClient/Group%20Policy%20Objects/Computer/) policy for those who use smart card logons with ActivClient software.
* The [Adobe Reader folder](./Adobe%20Reader/README.md) contains Adobe Reader DC [Computer](./Adobe%20Reader/Group%20Policy%20Objects/Computer/) and [User](./Adobe%20Reader/Group%20Policy%20Objects/User/) policies for the latest version of Adobe Reader DC.
* The [AppLocker folder](./AppLocker/README.md) contains AppLocker [Computer](./AppLocker/Group%20Policy%20Objects/Computer/) policy for the latest version of Windows 10.
* The [Certificates folder](./Certificates/README.md) contains [Computer](./Certificates/Group%20Policy%20Objects/Computer/) policy for distributing the DoD Root and Intermediate Certificate Authorities.
* The [Chrome folder](./Chrome/README.md) contains Chrome browser [Computer](./Chrome/Group%20Policy%20Objects/Computer/) policy for the latest version of Chrome.
* The [Internet Explorer folder](./Internet%20Explorer/README.md) contains Internet Explorer 11 [Computer](./Internet%20Explorer/Group%20Policy%20Objects/Computer/) and [User](./Internet%20Explorer/Group%20Policy%20Objects/User/) policies for latest version of Windows 10.
* The [Office folder](./Office/README.md) contains [Office 2013](./Office/Office%202013/) and [Office 2016](./Office/Office%202016/) policy.
* The [Windows folder](./Windows/README.md) contains Windows 10 [User](./Windows/Group%20Policy%20Objects/User) and [Computer](./Windows/Group%20Policy%20Objects/Computer/) policies for the latest version of Windows 10.
* The [Windows Firewall folder](./Windows%20Firewall/README.md) contains Windows Firewall [Computer](./Windows%20Firewall/Group%20Policy%20Objects/Computer/) policy for the latest version of Windows 10.

### Scripts and tools
Scripts for aiding users with the SHB are located in the Scripts sub folders of each component. Scripts available for use so far:

* [Adobe Reader](./Adobe%20Reader/Scripts/)
* [Certificates](./Certificates/Scripts/)
* [Chrome](./Chrome/Scripts/)
* [General](./Scripts/)
* [Windows](./Windows/Scripts/)

### Compliance checks
Nessus (aka [ACAS](http://www.disa.mil/cybersecurity/network-defense/acas) in the DoD) audit files are included in this repository. Compliance checks are available for:

* [Adobe Reader DC](./Adobe%20Reader/Compliance/)
* [Chrome](./Chrome/Compliance/)
* [Internet Explorer](./Internet%20Explorer/Compliance/)
* [Windows](./Windows/Compliance/)
* [Windows Firewall](./Windows%20Firewall/Compliance/)

Instructions for running the compliance checks in a domain or standalone environment can be found on the [Compliance](./Compliance/README.md) page.

## Getting started

To get started using the tools:

1. [Download](#downloading-the-repository) the repository as a zip file 
1. [Configure PowerShell](#configuring-the-powershell-environment) 
1. [Load the code](#loading-the-code) 
1. [Apply the policies](#applying-the-policies) 
1. [Check compliance](#checking-compliance)

## Downloading the repository

Download the [current code](https://github.com/nsacyber/Windows-Secure-Host-Baseline/archive/master.zip) to your **Downloads** folder. It will be saved as **Windows-Secure-Host-Baseline-master.zip** by default.

## Configuring the PowerShell environment
The PowerShell commands are meant to run from a system with at least PowerShell 3.0 installed. PowerShell may need to be configured to run the commands.

### Changing the PowerShell execution policy

Users may need to change the default PowerShell execution policy. This can be achieved in a number of different ways:

* Open a command prompt and run **powershell.exe -ExecutionPolicy Unrestricted** and run scripts from that PowerShell session. 
* Open a PowerShell prompt and run **Set-ExecutionPolicy Unrestricted -Scope Process** and run scripts from the current PowerShell session. 
* Open an administrative PowerShell prompt and run **Set-ExecutionPolicy Unrestricted** and run scripts from any PowerShell session. 

### Unblocking the PowerShell scripts
Users will need to unblock the downloaded zip file since it will be marked as having been downloaded from the Internet which PowerShell will block from executing by default. Open a PowerShell prompt and run the following commands to unblock the PowerShell code in the zip file:

1. `cd $env:USERPROFILE` 
1. `cd Downloads` 
1. `Unblock-File -Path '.\Windows-Secure-Host-Baseline-master.zip'`

Running the PowerShell scripts inside the zip file without unblocking the file will result in the following warning:

*Security warning*
*Run only scripts that you trust. While scripts from the internet can be useful, this script can potentially harm your computer. If you trust this script, use the Unblock-File cmdlet to allow the script to run without this warning message. Do you want to run C:\users\user\Downloads\script.ps1?*
*[D] Do not run [R] Run once [S] Suspend [?] Help (default is "D"):*


If the downloaded zip file is not unblocked before extracting it, then all the individual PowerShell files that were in the zip file will have to be unblocked. You will need to run the following command after Step 5 in the [Loading the code](#loading-the-code) section:

```
Get-ChildItem -Path '.\Windows-Secure-Host-Baseline' -Recurse -Include '*.ps1','*.psm1' | Unblock-File -Verbose
```

See the [Unblock-File command's documentation](https://technet.microsoft.com/en-us/library/hh849924.aspx) for more information on how to use it.

### Loading the code
Now extract the downloaded zip file and load the PowerShell code used for apply the policies.

1. Right click on the zip file and select **Extract All**
1. At the dialog remove **Windows-Secure-Host-Baseline-master** from the end of the path since it will extract the files to a Windows-Secure-Host-Baseline-master folder by default
1. Click the **Extract** button
1. Rename the **Windows-Secure-Host-Baseline-master** folder to **Windows-Secure-Host-Baseline**
1. Open a PowerShell prompt as an administrator
1. Import the [Group Policy PowerShell module](./Scripts/GroupPolicy.psm1) to load the code into the PowerShell session: `Import-Module -Name .\Windows-Secure-Host-Baseline\Scripts\GroupPolicy.psm1`

### Applying the policies

The **Invoke-ApplySecureHostBaseline** command found in the [Group Policy PowerShell module](./Scripts/GroupPolicy.psm1) is the main command for applying policies. By default this command will:
* Import both Computer and User policies. Use the **-PolicyScopes** option and specify only the **'User'** or **'Computer'** value to import only User or Computer policies.
* Import policies, that have an audit option (e.g. AppLocker), in audit mode. To import those policies in enforcement mode, use the **-PolicyMode** option and specify the **'Enforced'** value.
* Make a backup copy of existing imported SHB Group Policy objects (and Group Policy templates if the -UpdateTemplates option is used) if they exist. The backups will be in a directory located at **%UERPROFILE%\\Desktop\\Backup_yyyyMMddHHmmss** corresponding to the time when the command was executed. To change this location use the **-BackupPath** option and specify a path to an existing folder where the Backup_yyyyMMddHHmmss will be created.
* **not** update the Group Policy template files that correspond to the applied Group Policy  objects. Use the **-UpdateTemplates** option to update the Group Policy templates.

Options for the command are:
* **-Path** - Required. The path to the folder containing the downloaded and extracted GitHub SHB repository.
* **-PolicyNames** - Required. The names of the policies to apply. Can be 1 or more policy names. Available names: 'ActivClient', 'Adobe Reader', 'AppLocker', 'Certificates', 'Chrome', 'Internet Explorer', 'Office 2013', 'Office 2016', 'Windows', 'Windows Firewall'.
* **-PolicyScopes** - Optional. The scope of the policies to apply. Available scopes: 'Computer', 'User'. Defaults to 'Computer','User'.
* **-PolicyType** - Optional. The type of policies to apply. Available types: 'Domain', 'Local'. Defaults to 'Domain' when joined to a domain. Defaults to 'Local' when not joined to a domain.
* **-PolicyMode** - Optional. The mode of policies to apply, if supported by the specific policy. For example, AppLocker supports audit and enforcement modes. Available modes: 'Audit', 'Enforced'. Defaults to 'Audit'.
* **-BackupPath** - Optional. The path to a folder to save backups of existing imported SHB Group Policy objects (and Group Policy templates if the -UpdateTemplates option is used) if they exist in case a rollback is needed. Defaults to $env:USERPROFILE\Desktop\Backup_yyyyMMddHHmmss corresponding to when the script was executed.
* **-ToolPath** - Optional. The path to the LGPO tool. Required when PolicyType is 'Local'.
* **-UpdateTemplates** - Optional. Update Group Policy templates that correspond to the applied Group Policy objects.

Type **man Invoke-ApplySecureHostBaseline** at a PowerShell prompt for more help and examples or submit a question to the [repository issue tracker](https://github.com/nsacyber/Windows-Secure-Host-Baseline/issues).

#### Applying the SHB policies to a standalone system

If applying the SHB policies to a standalone system (e.g. not joined to a domain), then download the [LGPO tool](https://msdnshared.blob.core.windows.net/media/TNBlogsFS/prod.evol.blogs.technet.com/telligent.evolution.components.attachments/01/4062/00/00/03/65/94/11/LGPO.zip) from [this Microsoft blog post](http://blogs.technet.com/b/secguide/archive/2016/01/21/lgpo-exe-local-group-policy-object-utility-v1-0.aspx) and extract the executable.

```
Invoke-ApplySecureHostBaseline -Path '.\Windows-Secure-Host-Baseline' -PolicyNames 'Adobe Reader','AppLocker','Certificates','Chrome','Internet Explorer','Office 2013','Office 2016','Windows','Windows Firewall' -ToolPath '.\LGPO\lgpo.exe'
```

#### Applying the SHB policies to a domain

If applying the SHB policies to a domain, note that the Group Policy objects are only loaded into Active Directory. The policies are not linked to any OUs so the settings do not automatically take affect.

```
Invoke-ApplySecureHostBaseline -Path '.\Windows-Secure-Host-Baseline' -PolicyNames 'Adobe Reader','AppLocker','Certificates','Chrome','Internet Explorer','Office 2013','Office 2016','Windows','Windows Firewall'
``` 

### Checking compliance
Once the policies have been applied (and linked to appropriate OUs in the domain case), see the [Compliance page](./Compliance/README.md) for instructions on how to check compliance to the policies.

## License
See [LICENSE](./LICENSE.md).

## Disclaimer
See [DISCLAIMER](./DISCLAIMER.md).
