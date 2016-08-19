# Internet Explorer 11

Group Policy Object for the Internet Explorer 11 (IE 11) browser are included in the SHB. Internet Explorer 11 is the only [supported version](https://support.microsoft.com/en-us/lifecycle#gp/Microsoft-Internet-Explorer) of Internet Explorer for Windows 7, 8 and 10.

## Importing the Internet Explorer Group Policy

### Importing the Internet Explorer domain Group Policy
Use the PowerShell Group Policy commands to import the Internet Explorer Group Policy into a domain. Run the following command on a domain controller from a PowerShell prompt running as a domain administrator. 

```
Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'Internet Explorer'
```

### Importing the Internet Explorer local Group Policy
Use Microsoft's LGPO tool to apply the Internet Explorer Group Policy to a standalone system. Run the following command from a command prompt running as a local administrator.

```
Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'Internet Explorer' -ToolPath '.\LGPO\lgpo.exe'
```

## Compliance
The [Compliance](./Compliance/) folder contains a Nessus (aka [ACAS](http://www.disa.mil/cybersecurity/network-defense/acas) in the DoD) .audit file to check compliance with the settings implemented in the Group Policy Object. The compliance check contains a version check which will report the version of Internet Explorer 11. As of 5/10/2016 the current version of IE 11 varies slightly per OS platform as follows:
* Version 11.0.9600.18231 on Windows 7 SP1
* Version 11.0.9600.18123 on Windows Server 2012 R2
* Version 11.0.10586.20 on Windows 10 1511

## Downloads
Latest downloads for [Internet Explorer 11](https://www.microsoft.com/en-us/download/internet-explorer.aspx)
