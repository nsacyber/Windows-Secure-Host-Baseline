# DoD Certification Authority Certificates

This folder contains certificates for the DoD [Root](./Root/) and [Intermediate](./Intermediate/) certification authorities.


Using the methods described on this page removes the need for running the [InstallRoot](http://iase.disa.mil/pki-pke/Pages/tools.aspx) tool (available under the **Trust Store** tab at that link) that [installs DoD root certificates](http://iase.disa.mil/pki-pke/Documents/InstallRoot%204_1%20NIPRNET_User_Guide_02132015.pdf) on systems.


Using the provided certificates removes the need for running the [FBCA Cross-Certificate Remover](http://iase.disa.mil/pki-pke/Pages/tools.aspx) tool (available under the **Certification Validation** tab at that link) that [removes old DoD cross certificates](http://iasecontent.disa.mil/pki-pke/unclass-fbca_cross_cert_remover_user_guide_v113.pdf) from systems unless an organization is still deploying old DoD certificates.


## Importing Certificates
Importing certificates varies depending on whether they are being imported for a domain versus a standalone system.

### Importing certificates for a domain

1. On a domain controller, go to **Start** > **Administrative Tools** or **Start** > **Control Panel** > **System and Security** > **Administrative Tools**
1. Select **Group Policy Management**
1. Expand **Computer Configuration**, expand **Windows Settings**, expand **Security Settings**, and expand **Public Key Policies**
1. Right-click **Trusted Root Certification Authorities** and select **Import**
1. Follow the steps in the Certificate Import Wizard to import the certificates from the Root folder
1. Repeat the same steps for **Intermediate Certification Authorities** and import the certificates from the Intermediate folder


### Importing certificates for a standalone system

You can use PowerShell's [Import-Certificate command](https://technet.microsoft.com/en-us/%5Clibrary/hh848630(v=wps.630).aspx) to import the certificates. 

1. Open a PowerShell prompt with administrator privileges 
1. Change directory to the Certificates directory
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

1. Click **Start**, type **mmc**, and and press **Enter**
1. **File** > **Add/Remove snap-in...**
1. Select **Certificates** and click the **Add** button
1. Select **Computer account**, click **Next**, and then click **Finish**
1. Click the **OK** button
1. Expand **Certificates** and expand **Trusted Root Certification Authorities**
1. Right click on **Certificates** and select **All Tasks** > **Import...**
1. Follow the steps in the Certificate Import Wizard to import the certificates from the Root folder
1. Repeat the same steps for **Intermediate Certification Authorities** and import the certificates from the Intermediate folder