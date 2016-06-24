# Secure Host Baseline

## About the Secure Host Baseline

The Secure Host Baseline (SHB) provides an automated and flexible approach for assisting the DoD in deploying the latest releases of Windows 10 using a framework that can be consumed by organizations of all sizes. 


The DoD CIO issued a memo on [November 20, 2015](http://www.esi.mil/download.aspx?id=5542) directing Combatant Commands, Services, Agencies and Field Activities (CC/S/As) to rapidly deploy the Windows 10 operating system throughout their respective organizations with the objective of completing deployment by the end of January 2017. The Deputy Secretary of Defense issued a memo on [February 26, 2016](http://www.esi.mil/download.aspx?id=5543) directing the DoD to complete a rapid deployment and transition to Microsoft Windows 10 Secure Host Baseline by the end of January 2017.[[1](http://www.esi.mil/contentview.aspx?id=685)]


Formal product evaluations also support the move to Windows 10. The [National Information Assurance Partnership](https://www.niap-ccevs.org) (NIAP) oversees evaluations of commercial IT products for use in [National Security Systems](https://www.iad.gov/iad/news/defining-a-national-security-system.cfm). The Common Criteria evaluation of Windows 10 against the NIAP [Protection Profile for General Purpose Operating Systems](https://www.niap-ccevs.org/Profile/Info.cfm?id=400) completed [April 5, 2016](https://www.niap-ccevs.org/Product/CompliantCC.cfm?CCID=2016.1052). The Common Criteria evaluation of Windows 10 against the NIAP [Protection Profile for Mobile Device Fundamentals](https://www.niap-ccevs.org/Profile/Info.cfm?id=353) completed [January 29, 2016](https://www.niap-ccevs.org/Product/Compliant.cfm?pid=10677). [NIST](http://www.nist.gov/) [FIPS 140-2](http://csrc.nist.gov/groups/STM/cmvp/index.html) validation of Windows 10 modules was completed on June 2, 2016 as evidenced in certificate numbers [2600](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#2600), [2601](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#2601), [2602](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#2602), [2603](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#2603), [2604](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#2604), [2605](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#2605), [2606](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#2606), and [2607](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#2607).


Using a [Secure Host Baseline](https://www.iad.gov/iad/library/ia-guidance/security-tips/secure-host-baseline.cfm) is one of [IAD's top 10 mitigation strategies](https://www.iad.gov/iad/library/ia-guidance/iads-top-10-information-assurance-mitigation-strategies.cfm). The DoD Secure Host Baseline also exemplifies other IAD top 10 mitigation strategies such as using [application whitelisting](https://www.iad.gov/iad/library/ia-guidance/security-tips/application-whitelisting.cfm), enabling [anti-exploitation features](https://www.iad.gov/iad/library/ia-guidance/security-tips/anti-exploitation-features.cfm), and using the [latest version of the operating system and applications](https://www.iad.gov/iad/library/ia-guidance/security-tips/take-advantage-of-software-improvements.cfm).

## About this repository

This repository hosts Group Policy Objects, configuration tools, and compliance checks in support of the Windows 10 DoD Secure Host Baseline framework. Administrators of [National Security Systems](https://www.iad.gov/iad/news/defining-a-national-security-system.cfm), such as those who are part of the [Defense Industrial Base](https://www.dhs.gov/defense-industrial-base-sector), can leverage this repository in lieu of access to the [DoD SHB framework](https://disa.deps.mil/ext/cop/iase/dod-images/) which requires a Common Access Card (CAC) or Personal Identification Verification (PIV) smart card to access. 

Questions or comments can be submitted to the [issue tracker](https://github.com/iadgov/Secure-Host-Baseline/issues) or posted on Software Forge [Windows 10 Secure Host Baseline project](https://software.forge.mil/sf/projects/win10shb) forums. Access to Software Forge requires a Common Access Card.

## Getting started

1. [Download](#downloads) the repository.
1. [Import](#importing-a-gpo) the Group Policy Objects to your domain or standalone system.

## Downloads

* [Current code](https://github.com/iadgov/Secure-Host-Baseline/archive/master.zip) - Use this until there is an official release.
* [Latest release](https://github.com/iadgov/Secure-Host-Baseline/releases/latest) - There are no official releases yet.

## Repository content

### Group Policy Objects

* The [Windows folder](./Windows/README.md) contains Windows 10 [User](./Windows/Group Policy Objects/User) and [Computer](./Windows/Group Policy Objects/Computer/) policies for the latest version of Windows 10.
* The [Windows Firewall folder](./Windows Firewall/README.md) contains Windows Firewall [Computer](./Windows Firewall/Group Policy Object/Computer/) policy for the latest version of Windows 10.
* The [AppLocker folder](./AppLocker/README.md) contains AppLocker [Computer](./AppLocker/Group Policy Objects/Computer/) policy for the latest version of Windows 10.
* The [BitLocker folder](./BitLocker/README.md) contains BitLocker [Computer](./BitLocker/Group Policy Objects/Computer/) policy for the latest version of Windows 10.
* The [EMET folder](./EMET/README.md) contains EMET 5.5 [Computer](./EMET/Group Policy Objects/Computer/) policy for any version of Windows.
* The [Internet Explorer folder](./Internet Explorer/README.md) contains Internet Explorer 11 [Computer](./Internet Explorer/Group Policy Objects/Computer/) and [User](./Internet Explorer/Group Policy Objects/User/) policies for the latest version of Windows 10.
* The [Office folder](./Office/README.md) contains Office 2013 [Group Policy Object](./Office/Group Policy Objects/).
* The [Chrome folder](./Chrome/README.md) contains Chrome browser [Computer](./Chrome/Group Policy Objects/Computer/) policy for the latest version of Chrome.
* The [Adobe Reader folder](./Adobe Reader/README.md) contains Adobe Reader DC [Computer](./Adobe Reader/Group Policy Objects/Computer/) and [User](./Adobe Reader/Group Policy Objects/User/) policies for the latest version of Adobe Reader DC.

### Scripts and tools
Scripts for aiding users with the SHB are located in the Scripts sub folders of each component. Scripts available for use so far:

* [General](./Scripts/)
* [BitLocker](./BitLocker/Scripts/)
* [Certificates](./Certificates/Scripts/)
* [Chrome](./Chrome/Scripts/)
* [Hardware](./Hardware/Scripts/)

Users may need to perform 3 steps to run the functions defined in the PowerShell scripts:

1. Change the PowerShell execution policy
1. Unblock the PowerShell script
1. Dot source the PowerShell script

##### Changing the PowerShell execution policy

Users may need to change the default PowerShell execution policy. This can be achieved in a number of different ways:
* Open a command prompt and run **powershell.exe -ExecutionPolicy Bypass** and run scripts from that PowerShell session.
* Open a PowerShell prompt and run **Set-ExecutionPolicy Unrestricted -Scope CurrentUser** and run scripts from any PowerShell session.
* Open an administrative PowerShell prompt and run **Set-ExecutionPolicy Unrestricted** and run scripts from any PowerShell session.

##### Unblocking the PowerShell scripts

Users may need to unblock PowerShell files that have been downloaded from the Internet. Open a PowerShell prompt and run the following command **[System.IO.FileInfo[]]@(Get-ChildItem -Path '.\Secure-Host-Baseline') -Recurse -Filter '\*.ps1' | Unblock-File** to unblock all PowerShell files.

##### Dot sourcing the PowerShell scripts

Once the PowerShell execution policy has been configured, and the PowerShell scripts have been unblocked, [dot source](https://technet.microsoft.com/en-us/library/hh847841.aspx) the file to load the PowerShell code.

1. Open a PowerShell prompt
1. Change directory to where the script is located (e.g. **cd .\\Hardware\\Scripts\\**)
1. Dot source the script into the PowerShell session (e.g. **. .\\Hardware.ps1**)
1. Execute the PowerShell function (e.g. **Test-IsCredentialGuardEnabled**)

Eventually the PowerShell scripts will be turned into modules so dot sourcing will not be required.

### Compliance checks
Nessus (aka [ACAS](http://www.disa.mil/cybersecurity/network-defense/acas) in the DoD) audit files and [SCAP](https://en.wikipedia.org/wiki/Security_Content_Automation_Protocol) content will be included in this repository over time. Compliance checks available for use so far:

* [Adobe Reader DC](./Adobe Reader/Compliance/)
* [Chrome](./Chrome/Compliance/)
* [EMET](./EMET/Compliance/)
* [Internet Explorer](./Internet Explorer/Compliance/)
* [Windows](./Windows/Compliance/)

## Importing a GPO
Importing a GPO varies depending on whether it is being imported for a domain versus a standalone system.

### Importing a GPO for a domain

1. On a domain controller, go to **Start** > **Administrative Tools** or **Start** > **Control Panel** > **System and Security** > **Administrative Tools**
1. Select **Group Policy Management**
1. Expand **Forest: _forest name_**, expand **Domains**, expand **_domain name_**, and expand **Group Policy Objects** if these have not been expanded already
1. Create a new empty GPO or skip to the next step if using an existing GPO 
  1. Right click on Group Policy Objects and select New 
  1. Enter a GPO name in the **Name** field 
1. Right click the GPO you want to import settings into and select **Import Settings**
1. Follow the steps in the Import Wizard and select the GPO backup folder for the GPO you want to import

The PowerShell [Group Policy commands](<https://technet.microsoft.com/en-us/library/hh967461(v=wps.630).aspx>) can also be used to import a domain GPO on [systems that have the PowerShell Group Policy module](https://technet.microsoft.com/en-us/library/ee461027.aspx#sectionSection0).

```
Import-Module GroupPolicy

Import-GPO -Path "path to GPO backup folder"
```

### Importing a GPO for a standalone system

1. Download the [LGPO tool](http://blogs.technet.com/cfs-filesystemfile.ashx/__key/telligent-evolution-components-attachments/01-4062-00-00-03-65-94-11/LGPO.zip) from [this Microsoft blog post](http://blogs.technet.com/b/secguide/archive/2016/01/21/lgpo-exe-local-group-policy-object-utility-v1-0.aspx) and copy it to the standalone system
1. Copy the GPO backup folder for the GPO you want to import to the standalone system
1. Open an administrative command prompt and type **lgpo.exe /g "_path to GPO backup folder_"**

## License
This Work was prepared by a United States Government employee and, therefore, is excluded from copyright by Section 105 of the Copyright Act of 1976.

Copyright and Related Rights in the Work worldwide are waived through the [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) [Universal license](https://creativecommons.org/publicdomain/zero/1.0/legalcode).

## Disclaimer of Warranty
This Work is provided "as is." Any express or implied warranties, including but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the United States Government be liable for any direct, indirect, incidental, special, exemplary or consequential damages (including, but not limited to, procurement of substitute goods or services, loss of use, data or profits, or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this Guidance, even if advised of the possibility of such damage.

The User of this Work agrees to hold harmless and indemnify the United States Government, its agents and employees from every claim or liability (whether in tort or in contract), including attorneys' fees, court costs, and expenses, arising in direct consequence of Recipient's use of the item, including, but not limited to, claims or liabilities made for injury to or death of personnel of User or third parties, damage to or destruction of property of User or third parties, and infringement or other violations of intellectual property or technical data rights.

Nothing in this Work is intended to constitute an endorsement, explicit or implied, by the United States Government of any particular manufacturer's product or service.

## Disclaimer of Endorsement
Reference herein to any specific commercial product, process, or service by trade name, trademark, manufacturer, or otherwise, in this Work does not constitute an endorsement, recommendation, or favoring by the United States Government and shall not be used for advertising or product endorsement purposes.
