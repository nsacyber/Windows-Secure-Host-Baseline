# Compliance Checks
Nessus (aka [ACAS](http://www.disa.mil/cybersecurity/network-defense/acas) in the DoD) audit files are included in this repository. Compliance checks are available for:

* [Adobe Reader DC](./../Adobe Reader/Compliance/)
* [Chrome](./../Chrome/Compliance/)
* [EMET](./../EMET/Compliance/)
* [Internet Explorer](./../Internet Explorer/Compliance/)
* [Windows](./../Windows/Compliance/)
* [Windows Firewall](./../Windows Firewall/Compliance/)

## Running Compliance Checks

### Domain Scan with Nessus

1. Download the above .audit files
1. For each audit file make a new **Policy Compliance Auditing** scan
1. Configure the correct set of machines to scan and provide the correct credentials for the scan
1. On the **Compliance** tab, select **Windows** and then select **Upload a custom Windows audit file**
1. Run the scan and review the results

A paid version of Nessus Professional or Nessus Manager must be used in order to use .audit files with Nessus. The .audit files have been tested and work on Nessus Professional version 6.7. They may work on older versions as well but have not been tested. Alternatively, you can use the provided PowerShell script to locally scan a single system.

### Standalone Scan with PowerShell

The Test-Compliance command in the [Compliance.ps1 file](./Scripts/Compliance.ps1) can be used to verify compliance against using any of the above listed .audit files. This PowerShell script makes it simple to scan a single standalone system and verify a configuration has been applied correctly. The following instructions can be used to execute a compliance check locally.

1. Open a PowerShell prompt as an administrator
1. Change directory to the Compliance\Scripts directory (e.g. **cd Secure-Host-Baseline\Compliance\Scripts**)
1. Dot source the script into the PowerShell session (e.g. **. .\Compliance.ps1**)
1. Copy and paste the desired line(s) below into the PowerShell prompt and press Enter twice.

```
Test-Compliance -Path '..\..\Adobe Reader\Compliance\AdobeReaderDC.audit'
Test-Compliance -Path '..\..\Chrome\Compliance\GoogleChrome.audit'
Test-Compliance -Path '..\..\EMET\Compliance\EMET_5.5.audit'
Test-Compliance -Path '..\..\Internet Explorer\Compliance\InternetExplorer11.audit'
Test-Compliance -Path '..\..\Windows\Compliance\Windows 10.audit'
Test-Compliance -Path '..\..\Windows Firewall\Compliance\WindowsFirewall.audit'
```
Below is a screenshot of the script running the Internet Explorer audit file.
![compliance_script_example](./images/compliance_script_example.jpg?raw=true)

The [Compliance.ps1](./Scripts/Compliance.ps1) script supports a verbose flag which will show details for checks that fail. Without the verbose flag a simple pass/fail is displayed for each compliance check as shown in image above. 

Verbose example:
```
Test-Compliance -Path '..\..\Adobe Reader\Compliance\AdobeReaderDC.audit' -Verbose
```

Verbose example with capturing the output into a file:

```
Test-Compliance -Path '..\..\Adobe Reader\Compliance\AdobeReaderDC.audit' -Verbose .\*>ComplianceReport.txt
```

### Domain Scan with PowerShell


## Links
* [Nessus Compliance Checks Reference](https://support.tenable.com/support-center/nessus_compliance_reference.pdf)