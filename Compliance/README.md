# Compliance Checks
Nessus (aka [ACAS](http://www.disa.mil/cybersecurity/network-defense/acas) in the DoD) audit files and [SCAP](https://en.wikipedia.org/wiki/Security_Content_Automation_Protocol) content will be included in this repository over time. Compliance checks available for use so far:

* [Adobe Reader DC](./../Adobe Reader/Compliance/)
* [Chrome](./../Chrome/Compliance/)
* [EMET](./../EMET/Compliance/)
* [Internet Explorer](./../Internet Explorer/Compliance/)
* [Windows](./../Windows/Compliance/)

## Running Compliance Checks

### Domain Scan with Nessus

1. Download the above .audit files
1. For each audit file make a new **Policy Compliance Auditing** scan
1. Configure the correct set of machines to scan and provide the correct credentials for the scan
1. On the **Compliance** tab, select **Windows** and then select **Upload a custom Windows audit file**
1. Run the scan and review the results

A paid version of Nessus Professional or Nessus Manager must be used in order to use .audit files with Nessus. The .audit files have been tested and work on Nessus Professional version 6.7. They may work on older versions as well but have not been tested. Alternatively, you can use the provided PowerShell script to locally scan a single system.

### Standalone Scan with PowerShell

The Test-Compliance command in the [Scripts\Compliance.ps1](./Scripts/Compliance.ps1) file can be used to verify system compliance against any of the above listed .audit files. This powershell script makes it simple to scan a single standalone system and verify a configuration has been applied correctly. The following instructions can be used to execute a compliance check locally.

1. Open a PowerShell prompt as an administrator
2. Change directory to the Compliance\Scripts directory (e.g. cd Secure-Host-Baseline\Compliance\Scripts)
3. Dot source the script into the PowerShell session (e.g. . .\Compliance.ps1)
4. Copy and paste the desired line(s) below into the PowerShell prompt and press Enter twice.

```
Test-Compliance "..\..\Adobe Reader\Compliance\AdobeReaderDC.audit"
Test-Compliance "..\..\Chrome\Compliance\GoogleChrome.audit"
Test-Compliance "..\..\EMET\Compliance\EMET_5.5.audit"
Test-Compliance "..\..\Internet Explorer\Compliance\InternetExplorer11.audit"
Test-Compliance "..\..\Windows\Compliance\Windows 10.audit"
```
Below is a screenshot of the [Compliance.ps1](./Scripts/Compliance.ps1) script running the Internet Explorer audit file.
![compliance_script_example](./images/compliance_script_example.jpg?raw=true)

The [Compliance.ps1](./Scripts/Compliance.ps1) script supports a verbose flag which will show details for checks that fail. Without the verbose flag a simple pass/fail is displayed for each compliance check as shown in image above. 

```
Test-Compliance "..\..\Adobe Reader\Compliance\AdobeReaderDC.audit" -verbose
```



## Links
* [Nessus Compliance Checks Reference](https://support.tenable.com/support-center/nessus_compliance_reference.pdf)