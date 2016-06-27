# Compliance Checks
Nessus (aka [ACAS](http://www.disa.mil/cybersecurity/network-defense/acas) in the DoD) audit files and [SCAP](https://en.wikipedia.org/wiki/Security_Content_Automation_Protocol) content will be included in this repository over time. Compliance checks available for use so far:

### Nessus Audit Files
* [Adobe Reader DC](./Adobe Reader/Compliance/)
* [Chrome](./Chrome/Compliance/)
* [EMET](./EMET/Compliance/)
* [Internet Explorer](./Internet Explorer/Compliance/)
* [Windows](./Windows/Compliance/)

# Run Compliance Checks
### Domain Scan with Nessus
1. Download the above .audit files
2. For each audit file make a new **Policy Compliance Auditing** scan
3. Configure the correct set of machines to scan and provide the correct credentials for the scan
4. On the **Compliance** tab, select **Windows** and then select **Upload a custom Windows audit file**
5. Run the scan and review the results

### Standalone Scan with PowerShell

