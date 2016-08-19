# Microsoft AppLocker

Microsoft AppLocker is an [application whitelisting](https://www.iad.gov/iad/library/ia-guidance/security-tips/application-whitelisting.cfm) feature built into Windows. The use of application whitelisting is one of [IAD's top 10 mitigation strategies](https://www.iad.gov/iad/library/ia-guidance/iads-top-10-information-assurance-mitigation-strategies.cfm).

Group Policy Objects containing a base whitelisting policy for both [Audit mode](./Group Policy Objects/Computer/Audit) and [Enforcement mode](./Group Policy Objects/Computer/Enforced) policy are included in the SHB for Windows 10.

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

* [Microsoft Requirements to use AppLocker](https://technet.microsoft.com/en-us/itpro/windows/keep-secure/requirements-to-use-applocker)
* [Microsoft AppLocker Policies Deployment Guide](https://technet.microsoft.com/en-us/itpro/windows/keep-secure/applocker-policies-deployment-guide)

