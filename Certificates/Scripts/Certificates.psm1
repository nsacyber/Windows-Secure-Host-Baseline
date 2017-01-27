#requires -version 3
Set-StrictMode -Version 3

Function Get-Certificates() {
    <#
    .SYNOPSIS
    Gets certificates.

    .DESCRIPTION
    Gets certificates for a specific certificate store location and certificate store name.

    .PARAMETER StoreLocation
    The certificate store location.

    .PARAMETER StoreName
    The certificate store name.

    .EXAMPLE
    Get-Certificates -StoreLocation 'CurrentUser'

    .EXAMPLE
    Get-Certificates -StoreLocation 'LocalMachine'

    .EXAMPLE
    Get-Certificates -StoreLocation 'CurrentUser' -StoreName 'My'
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Scope='Function')]
    [CmdletBinding()] 
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2[]])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The certificate store location')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('CurrentUser','LocalMachine',IgnoreCase=$true)]
        [string]$StoreLocation,

        [Parameter(Mandatory=$false, HelpMessage='The certificate store name')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('ACRS','ADDRESSBOOK','AuthRoot','CA','ClientAuthIssuer','Disallowed','DPNGRA','EFS','FlightRoot','FVE','FVE_NKP','My','REQUEST','Root','SmartCardRoot','Trust','TrustedDevices','TrustedPeople','TrustedPublisher','UserDS','Windows Live ID Token Issuer',IgnoreCase=$true)]
        [string]$StoreName
    )

     if ($null -eq $StoreName) {
         $certificates = [System.Security.Cryptography.X509Certificates.X509Certificate2[]]@(Get-ChildItem -Path cert:\ -Recurse | Where-Object {$_.PSParentPath -like "*$StoreLocation*" -and $_.PSIsContainer -eq $false})
     } else {
         $certificates = [System.Security.Cryptography.X509Certificates.X509Certificate2[]]@(Get-ChildItem -Path cert:\ -Recurse | Where-Object {$_.PSParentPath -like "*$StoreLocation*" -and $_.PSParentPath -like "*$StoreName"})
     }

     return ,$certificates
}

Function Get-CertificateStoreNames() {
    <#
    .SYNOPSIS
    Gets certificate store names.

    .DESCRIPTION
    Gets the certificate store names for a specific certificate store location.

    .PARAMETER StoreLocation
    The certificate store location.

    .EXAMPLE
    Get-CertificateStoreNames -StoreLocation 'CurrentUser'
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Scope='Function')]
    [CmdletBinding()] 
    [OutputType([string[]])] 
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The certificate store location')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('CurrentUser','LocalMachine',IgnoreCase=$true)]
        [string]$StoreLocation
    )

    $storeNames = [string[]]@((Get-ChildItem -Path cert:\ | Where-Object {$_.Location -ieq $StoreLocation}).StoreNames.Keys)

    return ,$storeNames
}

Function Get-CertificateStoreDisplayName() {
    <#
    .SYNOPSIS
    Gets the certificate store display name based on the programmatic name.

    .DESCRIPTION
    Gets the certificate store display name, as shown in certmgr.msc, based on the programmatic name.

    .PARAMETER StoreName
    The certificate store name.

    .EXAMPLE
    Get-CertificateStoreDisplayName -StoreName 'My'
    #>
    [CmdletBinding()] 
    [OutputType([string])] 
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The certificate store name')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('ACRS','ADDRESSBOOK','AuthRoot','CA','ClientAuthIssuer','Disallowed','DPNGRA','EFS','FlightRoot','FVE','FVE_NKP','My','REQUEST','Root','SmartCardRoot','Trust','TrustedDevices','TrustedPeople','TrustedPublisher','UserDS','Windows Live ID Token Issuer',IgnoreCase=$true)]
        [string]$StoreName
    )

    $displayName = 'Unknown'

    switch ($StoreName.ToLower()) {
        'acrs' { $displayName = 'Automatic Certificate Request Settings' ; break }
        'addressbook' { $displayName = 'Other People' ; break }
        'authroot' { $displayName = 'Third-Party Root Certification Authorities' ; break }
        'ca' { $displayName = 'Intermediate Certification Authorities' ; break }
        'clientauthissuer' { $displayName = 'Client Authentication Issuers' ; break }
        'disallowed' { $displayName = 'Untrusted Certificates' ; break }
        'dpngra = ' { $displayName = 'Data Protection' ; break }
        'efs' { $displayName = 'Encrypting File System' ; break }
        'flightroot' { $displayName = 'Preview Build Roots' ; break }
        'fve' { $displayName = 'BitLocker Drive Encryption' ; break }
        'fve_nkp' { $displayName = 'BitLocker Drive Encryption Network Unlock Certificate' ; break }
        'my' { $displayName = 'Personal' ; break }
        'request' { $displayName = 'Certificate Enrollment Requests' ; break }
        'root' { $displayName = 'Trusted Root Certification Authorities' ; break }
        'smartcardroot' { $displayName = 'Smart Card Trusted Roots' ; break }
        'trust' { $displayName = 'Enterprise Trust' ; break }
        'trusteddevices' { $displayName = 'Trusted Devices' ; break }
        'trustedpeople' { $displayName = 'Trusted People' ; break }
        'trustedpublisher' { $displayName = 'Trusted Publishers' ; break }
        'userds' { $displayName = 'Active Directory User Object' ; break }
        'windows live id token issuer' { $displayName = 'Windows Live ID Token Issuer' ; break }
        default {}

        # other certmgr.msc Display Names seen in screenshots on the Internet (don't know store name yet):
        # MSIEHistoryJournal
        # Remote Desktop
        # SMS
    }

    return $displayName
}