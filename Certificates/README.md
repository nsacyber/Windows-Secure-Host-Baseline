# DoD Certification Authority Certificates

The SHB includes certificates for DoD certification authorities. This folder contains  the certificates for the DoD [Root](./Root/) and [Intermediate](./Intermediate/) certification authorities.


Using the methods described on this page removes the need for running the [InstallRoot](http://iase.disa.mil/pki-pke/Pages/tools.aspx) tool (available under the **Trust Store** tab at that link) that [installs DoD root certificates](http://iase.disa.mil/pki-pke/Documents/InstallRoot%204_1%20NIPRNET_User_Guide_02132015.pdf) on systems.


Using the provided certificates removes the need for running the [FBCA Cross-Certificate Remover](http://iase.disa.mil/pki-pke/Pages/tools.aspx) tool (available under the **Certification Validation** tab at that link) that [removes old DoD cross certificates](http://iasecontent.disa.mil/pki-pke/unclass-fbca_cross_cert_remover_user_guide_v113.pdf) from systems unless an organization is still deploying old DoD certificates.


## Importing DoD certificates manually
Importing certificates varies depending on whether they are being imported for a domain versus a standalone system.

### Importing DoD certificates for a domain

1. On a domain controller, go to **Start** > **Administrative Tools** or **Start** > **Control Panel** > **System and Security** > **Administrative Tools**
1. Select **Group Policy Management**
1. Expand **Computer Configuration**, expand **Windows Settings**, expand **Security Settings**, and expand **Public Key Policies**
1. Right-click **Trusted Root Certification Authorities** and select **Import**
1. Follow the steps in the Certificate Import Wizard to import the certificates from the Root folder
1. Repeat the same steps for **Intermediate Certification Authorities** and import the certificates from the Intermediate folder


### Importing DoD certificates for a standalone system

You can use PowerShell's [Import-Certificate command](https://technet.microsoft.com/en-us/library/hh848630(v=wps.630).aspx) to import the certificates. 

1. Open a PowerShell prompt as an administrator
1. Change directory to the Certificates directory (e.g. **cd Secure-Host-Baseline\\Certificates**)
1. Copy and paste the code below into the PowerShell prompt and press **Enter** twice


```
$certificatesPath = ".\Root"

$certificateFiles = @(Get-ChildItem -Path $certificatesPath -Recurse -Include *.cer | Where-Object { $_.PsIsContainer -eq $false})

$certificateFiles | ForEach {
    Import-Certificate -FilePath $_.FullName -CertStoreLocation cert:\LocalMachine\Root # Trusted Root Certification Authories
}

$certificatesPath = ".\Intermediate"

$certificateFiles = @(Get-ChildItem -Path $certificatesPath -Recurse -Include *.cer | Where-Object { $_.PsIsContainer -eq $false})

$certificateFiles | ForEach {
    Import-Certificate -FilePath $_.FullName -CertStoreLocation cert:\LocalMachine\CA # Intermediate Certification Authories
}
```

You can also use the Microsoft Management Console Certificates snap-in to import the certificates on a standalone system.

1. Click **Start**, type **mmc**, and press **Enter**
1. **File** > **Add/Remove snap-in...**
1. Select **Certificates** and click the **Add** button
1. Select **Computer account**, click **Next**, and then click **Finish**
1. Click the **OK** button
1. Expand **Certificates** and expand **Trusted Root Certification Authorities**
1. Right click on **Certificates** and select **All Tasks** > **Import...**
1. Follow the steps in the Certificate Import Wizard to import the certificates from the Root folder
1. Repeat the same steps for **Intermediate Certification Authorities** and import the certificates from the Intermediate folder

## Importing DoD certificates automatically

### Importing the DoD certificates domain Group Policy
Use the PowerShell Group Policy commands to import the DoD certificates Group Policy into a domain. Run the following command on a domain controller from a PowerShell prompt running as a domain administrator. 

```
Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'Certificates'
```

### Importing the DoD certificates local Group Policy
Use Microsoft's LGPO tool to apply the DoD certificates Group Policy to a standalone system. Run the following command from a command prompt running as a local administrator.

```
Invoke-ApplySecureHostBaseline -Path '.\Secure-Host-Baseline' -PolicyNames 'Certificates' -ToolPath '.\LGPO\lgpo.exe'
```

## Fixing iad.gov certificate warnings
Non-DoD users may not want to import all the DoD Certificate Authority (CA) certificates as outlined above. Non-DoD users who visit https://www.iad.gov will receive a certificate warning (NET:ERR_CERT_AUTHORITY_INVALID) about www.iad.gov being an insecure web site when it is accessed since it does not use a certificate from a commercial CA that is already trusted by the browser. The browser's certificate store does not have the specific DoD CA certificate that issued the www.iad.gov certificate. To fix this issue import the **DoD Root CA 3** and **DoD ID SW CA-37** certificates into the browser certificate store.

Even after importing the correct certificates, users who browse to https://iad.gov rather than https://www.iad.gov will still receive a certificate warning (NET::ERR_CERT_COMMON_NAME_INVALID) since the certificate for www.iad.gov does not have a [Subject Alternative Name](https://en.wikipedia.org/wiki/Subject_Alternative_Name) (SAN) for iad.gov. Only browse to https://www.iad.gov to avoid this certificate warning until this issue has been resolved.

The instructions below will resolve the NET:ERR_CERT_AUTHORITY_INVALID error for Internet Explorer, Microsoft Edge, and Chrome browser on Windows. Users of other browser and operating system combinations may be able to use instructions [here](http://wiki.cacert.org/FAQ/ImportRootCert) and [here](http://wiki.cacert.org/FAQ/BrowserClients) by replacing references to **cacert-root** with **DoD Root CA 3** and references to **cacert-class3** with **DoD ID SW CA-37**.

### Automatically importing iad.gov certificates
1. Download (right click on the link and select Save As/Save Target As/Save Link As) the [iadgov PowerShell module](./Scripts/iadgov.psm1?raw=true) to your **Downloads** folder
1. Open a PowerShell prompt
1. Change directory to the location that you saved the file to (e.g. **cd Downloads**)
1. Type **Unblock-File -Path 'iadgov.ps1'** and press Enter to allow the file to execute
1. Type **Set-ExecutionPolicy Unrestricted -Scope CurrentUser** and press Enter to allow the file to execute
1. Type **. .\\iadgov.ps1** and press Enter to execute the file which will import the correct certificates
1. Browse to www.iad.gov and confirm no warnings are displayed

### Manually importing iad.gov certificates

1. Download (right click on the link and select Save As/Save Target As/Save Link As) the [DoD Root CA 3 certificate file](./Root/DoD_Root_CA_3__01__DoD_Root_CA_3.cer?raw=true) and the [DoD ID SW CA-37 certificate file](./Intermediate/DoD_Root_CA_3__0x12__DOD_ID_SW_CA-37.cer?raw=true) to your **Downloads** folder
1. Open a command prompt
1. Change directory to the folder (e.g. **cd Downloads**)
1. Copy and paste one of the two sets of commands below into the command prompt and press Enter to execute the code which will import the correct certificates
1. Browse to www.iad.gov and confirm no warnings are displayed


#### Importing iad.gov certificates into the system certificate store
This requires administrator privileges but will get rid of the warnings for all users on the system.
```
certutil.exe -addstore root DoD_Root_CA_3__01__DoD_Root_CA_3.cer
certutil.exe -addstore ca DoD_Root_CA_3__0x12__DOD_ID_SW_CA-37.cer
```

or

#### Importing iad.gov certificates into the user certificate store
This does not require administrator privileges but will only get rid of the warnings for the currently logged in user. The user will receive a security warning dialog asking if you want to install the certificate. Click Yes to install the certificate.
```
certutil.exe -user -addstore root DoD_Root_CA_3__01__DoD_Root_CA_3.cer
certutil.exe -user -addstore ca DoD_Root_CA_3__0x12__DOD_ID_SW_CA-37.cer
```