# Secure Host Baseline

## About The Secure Host Baseline

The Secure Host Baseline (SHB) provides an automated and flexible approach for assisting the DoD in deploying the latest releases of Windows 10 using a framework that can be consumed by organizations of all sizes. 


The [DoD CIO issued a memo on 11/20/2015](http://www.esi.mil/contentview.aspx?id=685) directing Combatant Commands, Services, Agencies and Field Activities (CC/S/As) to rapidly deploy the Windows 10 operating system throughout their respective organizations with the objective of completing deployment by the end of January 2017. The [Deputy Secretary of Defense issued a memo on 02/26/2015](http://www.esi.mil/download.aspx?id=5543) directing the DoD to complete a rapid deployment and transition to Microsoft Windows 10 Secure Host Baseline by the end of January 2017.\[[1](http://www.esi.mil/contentview.aspx?id=685)\]


Using a [Secure Host Baseline](https://www.iad.gov/iad/library/ia-guidance/security-tips/secure-host-baseline.cfm) is one of [IAD's top 10 mitigation strategies](https://www.iad.gov/iad/library/ia-guidance/iads-top-10-information-assurance-mitigation-strategies.cfm). The DoD Secure Host Baseline also includes other IAD top 10 mitigation strategies such as [application whitelisting](https://www.iad.gov/iad/library/ia-guidance/security-tips/application-whitelisting.cfm), enabling [anti-exploitation features](https://www.iad.gov/iad/library/ia-guidance/security-tips/anti-exploitation-features.cfm), and using the [latest version of the operating system and applications](https://www.iad.gov/iad/library/ia-guidance/security-tips/take-advantage-of-software-improvements.cfm).


This repository hosts Group Policy Objects, configuration files, and scripts in support of the Windows 10 DoD Secure Host Baseline framework. Administrators of [National Security Systems](https://www.iad.gov/iad/news/defining-a-national-security-system.cfm), such as those who part of the [Defense Industrial Base](https://www.dhs.gov/defense-industrial-base-sector), can leverage this repository in lieu of access to the [DoD SHB framework](https://disa.deps.mil/ext/cop/iase/dod-images/) which requires a Common Access Card (CAC) or Personal Identification Verification (PIV) smart card to access. 

## Group Policy Objects

* The [Windows folder](./Windows/README.md) contains Windows 10 [User](./Windows/Group Policy Objects/User) and [Computer](./Windows/Group Policy Objects/Computer/) policies for the latest version of Windows 10.
* The [Windows Firewall folder](./Windows Firewall/README.md) contains Windows Firewall [Computer](./Windows Firewall/Group Policy Object/Computer/) policy for the latest version of Windows 10.
* The [AppLocker folder](./AppLocker/README.md) contains AppLocker [Computer](./AppLocker/Group Policy Objects/Computer/) policy for the latest version of Windows 10.
* The [BitLocker folder](./BitLocker/README.md) contains BitLocker [Computer](./BitLocker/Group Policy Objects/Computer/) policy for the latest version of Windows 10.
* The [EMET folder](./EMET/README.md) contains EMET 5.5 [Computer](./EMET/Group Policy Objects/Computer/) policy for any version of Windows.
* The [Internet Explorer folder](./Internet Explorer/README.md) contains Internet Explorer 11 [Computer](./Internet Explorer/Group Policy Objects/Computer/) and [User](./Internet Explorer/Group Policy Objects/User/) policies for the latest version of Windows 10.
* The [Office folder](./Office/README.md) contains Office 2013 [Group Policy Object](./Office/Group Policy Objects/).
* The [Chrome folder](./Chrome/README.md) contains Chrome browser [Computer](./Chrome/Group Policy Objects/Computer/) policy for the latest version of Chrome.
* The [Adobe Reader folder](./Adobe Reader/README.md) contains Adobe Reader DC [Computer](./Adobe Reader/Group Policy Objects/Computer/) and [User](./Adobe Reader/Group Policy Objects/User/) policies for the latest version of Adobe Reader DC.

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

### Importing a GPO for a standalone system

1. Download the [LGPO tool](http://blogs.technet.com/b/secguide/archive/2016/01/21/lgpo-exe-local-group-policy-object-utility-v1-0.aspx) from [this Microsoft blog post](http://blogs.technet.com/b/secguide/archive/2016/01/21/lgpo-exe-local-group-policy-object-utility-v1-0.aspx) and copy it to the standalone system
1. Copy the GPO backup folder for the GPO you want to import to the standalone system
1. Open an administrative command prompt and type **lgpo.exe /g "_path to GPO backup folder_"**

## License
This work was prepared by an U.S. Government employee and, therefore, is excluded from copyright by Section 105 of the Copyright Act of 1976.

Copyright and Related Rights in the Work worldwide are waived through the [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) [Universal license](https://creativecommons.org/publicdomain/zero/1.0/legalcode).

## Disclaimer of Warranty
This Work is provided "as is." Any express or implied warranties, including but not limited to, the
implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event
shall the United States Government be liable for any direct, indirect, incidental, special, exemplary or
consequential damages (including, but not limited to, procurement of substitute goods or services, loss
of use, data or profits, or business interruption) however caused and on any theory of liability, whether
in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of
this Guidance, even if advised of the possibility of such damage.

The User of this Work agrees to hold harmless and indemnify the United States Government, its agents
and employees from every claim or liability (whether in tort or in contract), including attorneys' fees,
court costs, and expenses, arising in direct consequence of Recipient's use of the item, including, but not
limited to, claims or liabilities made for injury to or death of personnel of User or third parties, damage
to or destruction of property of User or third parties, and infringement or other violations of intellectual
property or technical data rights.

Nothing in this Work is intended to constitute an endorsement, explicit or implied, by the U.S.
Government of any particular manufacturer's product or service.

## Disclaimer of Endorsement
Reference herein to any specific commercial product, process, or service by trade name, trademark, manufacturer, or otherwise, in this Work does not constitute an endorsement, recommendation, or favoring by the United States Government and shall not be used for advertising or product endorsement pursposes.
