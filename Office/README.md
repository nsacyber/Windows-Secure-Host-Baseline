# Office
Group Policy Objects for Computer and User policies for Office are included in the SHB. It is recommended to use the most recent version of Office to leverage the latest security improvements and product enhancements. 
 * Office 2016 Group Policy Objects (coming soon). Installing the 64-bit version of Office 2016 is recommended.
 * [Office 2013 Group Policy Objects](./Group Policy Objects/Office 2013).

## Group Policy templates
The Office template files can be downloaded from Microsoft. They are also included in the [Group Policy Templates](./Group Policy Templates/) folder as a convenience.

## Importing the Office Group Policy

### Importing the Office domain Group Policy
Use the PowerShell Group Policy commands to import the Office Group Policy into a domain. Run the following command on a domain controller from a PowerShell prompt running as a domain administrator. 

```
Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'Office 2013'
```

### Importing the Office local Group Policy
Use Microsoft's LGPO tool to apply the Office Group Policy to a standalone system. Run the following command from a command prompt running as a local administrator.

```
Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'Office 2013' -ToolPath '.\LGPO\lgpo.exe'
```
## Office Macros

Office Macros have proven themselves to be an increasingly popular attack vector. In Office 2016 a new group policy setting was added to [Block Macros from the Internet Zone](https://blogs.technet.microsoft.com/mmpc/2016/03/22/new-feature-in-office-2016-can-block-macros-and-help-prevent-infection/). The new setting was backported to Office 2013 in as part of a patch, [MS16-099](https://support.microsoft.com/en-us/kb/3177451). This [Information Assurance Advisory](https://www.iad.gov/iad/library/ia-advisories-alerts/blocking-macros-from-internet-originated-microsoft-office-files.cfm) was developed to recommend blocking Office macros from the Internet Zone.

## Downloads
* [Group Policy templates for Office 2016](https://www.microsoft.com/en-us/download/details.aspx?id=49030)
* [Group Policy templates for Office 2013](https://www.microsoft.com/en-us/download/details.aspx?id=35554)

# Links
* [Office 2013 update history](https://support.microsoft.com/en-us/gp/office-2013-365-update)
* [Office 2016 update history](https://technet.microsoft.com/en-us/office/mt465751)