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

A paid version of Nessus Professional or Nessus Manager must be used in order to use .audit files with Nessus. Alternatively, you can use the provided PowerShell script to scan a single system.

### Standalone Scan with PowerShell
