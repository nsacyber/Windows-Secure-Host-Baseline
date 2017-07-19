# Microsoft AppLocker

Microsoft AppLocker is an [application whitelisting](https://www.iad.gov/iad/library/ia-guidance/security-tips/application-whitelisting.cfm) feature built into Windows. The use of application whitelisting is one of [IAD's top 10 mitigation strategies](https://www.iad.gov/iad/library/ia-guidance/iads-top-10-information-assurance-mitigation-strategies.cfm).

Formal product evaluations also support the use of Microsoft AppLocker. The Common Criteria evaluation of Windows 10 against the NIAP [Protection Profile for General Purpose Operating Systems](https://www.niap-ccevs.org/Profile/Info.cfm?id=400) completed [April 5, 2016](https://www.niap-ccevs.org/Product/CompliantCC.cfm?CCID=2016.1052). The Common Criteria evaluation included the optional FPT_SRP_EXT requirement for Application Whitelisting. The Assurance Activity report shows that Microsoft AppLocker in Windows 10 was evaluated and passed the FPT_SRP_EXT requirement.

Group Policy Objects containing a base whitelisting policy for both [Audit mode](./Group%20Policy%20Objects/Computer/Audit) and [Enforcement mode](./Group%20Policy%20Objects/Computer/Enforced) policy are included in the SHB for Windows 10.

## Importing the AppLocker Group Policy
By default, the AppLocker policy is imported configured in audit mode. To import it in enforcement mode, use the **-PolicyMode** option with the **'Enforced'** value.

### Importing the AppLocker domain Group Policy
Use the PowerShell Group Policy commands to import the AppLocker Group Policy into a domain. Run the following command on a domain controller from a PowerShell prompt running as a domain administrator. 

```
Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'AppLocker'
```

### Importing the AppLocker local Group Policy
Use Microsoft's LGPO tool to apply the AppLocker Group Policy to a standalone system. Run the following command from a command prompt running as a local administrator.

```
Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'AppLocker' -ToolPath '.\LGPO\lgpo.exe'
```

## Guidance
NSA Information Assurance has a security guide for AppLocker called [Application Whitelisting Using Microsoft AppLocker](https://www.iad.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm).

## Links

* [Microsoft Requirements to use AppLocker](https://docs.microsoft.com/en-us/windows/device-security/applocker/requirements-to-use-applocker)
* [Microsoft AppLocker Policies Deployment Guide](https://docs.microsoft.com/en-us/windows/device-security/applocker/applocker-policies-deployment-guide)

