# Compliance Checks
Nessus (aka [ACAS](http://www.disa.mil/cybersecurity/network-defense/acas) in the DoD) audit files are included in this repository. Compliance checks are available for:

* [Adobe Reader DC](./../Adobe Reader/Compliance/)
* [Chrome](./../Chrome/Compliance/)
* [EMET](./../EMET/Compliance/)
* [Internet Explorer](./../Internet Explorer/Compliance/)
* [Windows](./../Windows/Compliance/)
* [Windows Firewall](./../Windows Firewall/Compliance/)

## Running Compliance Checks

There are two ways you can check compliance with the provided audit files:
1. Use Nessus
1. Use a the provided Compliance PowerShell script (Nessus not required)

### Domain Scan with Nessus

1. Download the above .audit files
1. For each audit file make a new **Policy Compliance Auditing** scan
1. Configure the correct set of machines to scan and provide the correct credentials for the scan
1. On the **Compliance** tab, select **Windows** and then select **Upload a custom Windows audit file**
1. Run the scan and review the results

A paid version of Nessus Professional or Nessus Manager must be used in order to use .audit files with Nessus. The .audit files have been tested and work on Nessus Professional version 6.7. They may work on older versions as well but they have not been tested. Alternatively, you can use the provided PowerShell script to locally scan a single system.

### Standalone Scan with PowerShell

The **Test-Compliance** command in the [Compliance PowerShell module](./Scripts/) can be used to verify compliance against using any of the above listed .audit files. This PowerShell script makes it simple to scan a single standalone system and verify a configuration has been applied to a system in a non-domain context. Note that Nessus is not required to be installed on the system that is being checked with the script. The following instructions can be used to execute a compliance check locally.

1. Open a PowerShell prompt as an administrator
1. Change directory to the Compliance\Scripts directory (e.g. **cd Secure-Host-Baseline\Compliance\Scripts**)
1. Import the [Compliance PowerShell module](./Scripts/) to load the code into the PowerShell session: `Import-Module -Name .\Secure-Host-Baseline\Compliance\Scripts\Compliance.psm1`
1. Copy and paste the desired line(s) below into the PowerShell prompt and press Enter twice
    * ```Test-Compliance -Path '..\..\Adobe Reader\Compliance\AdobeReaderDC.audit'```
    * ```Test-Compliance -Path '..\..\Chrome\Compliance\GoogleChrome.audit'```
    * ```Test-Compliance -Path '..\..\EMET\Compliance\EMET_5.5.audit'```
    * ```Test-Compliance -Path '..\..\Internet Explorer\Compliance\InternetExplorer11.audit'```    
    * ```Test-Compliance -Path '..\..\Windows\Compliance\Windows10.audit'```
    * ```
Test-Compliance -Path '..\..\Windows Firewall\Compliance\WindowsFirewall.audit'```
    
The Compliance script supports a **-Verbose** option that show details for checks that fail. Without the verbose option a simple pass/fail is displayed for each compliance check as shown in the image below. 

![compliance_script_example](./images/compliance_script_example.jpg?raw=true)

Verbose example:
```
Test-Compliance -Path '..\..\Adobe Reader\Compliance\AdobeReaderDC.audit' -Verbose
```

Verbose example with capturing the output into a file:

```
Test-Compliance -Path '..\..\Adobe Reader\Compliance\AdobeReaderDC.audit' -Verbose .\*>ComplianceReport.txt
```

After capturing the output into a file, the failed STIG checks can be filtered using this PowerShell command:

```
Select-String -Path .\ComplianceReport.txt -Pattern 'FAILED'
```

### Domain Scan with PowerShell


## Links
* [Nessus Compliance Checks Reference](https://support.tenable.com/support-center/nessus_compliance_reference.pdf)