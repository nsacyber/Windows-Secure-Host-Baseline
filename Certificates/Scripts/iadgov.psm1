#requires -version 2
Set-StrictMode -Version 2

Function Import-CertificateDownlevel() {
 <#
    .SYNOPSIS
    Imports a certificate on downlevel operating systems that do not have the Import-Certificate command.

    .DESCRIPTION
    Imports a certificate on downlevel operating systems (Windows 7 and earlier) that do not have the Import-Certificate command.

    .EXAMPLE
    Import-CertificateDownlevel -Path '.\root.cer' -StoreName 'Root' -StoreLocation 'LocalMachine'

    .EXAMPLE
    Import-CertificateDownlevel -Path '.\intermediate.cer' -StoreName 'CertificateAuthority' -StoreLocation 'CurrentUser'
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param (
        [Parameter(Mandatory=$true, HelpMessage='The path of the certificate file.')]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory=$true, HelpMessage='The name of the certificate store to import the certificate to.')]
        [ValidateNotNullOrEmpty()]
        [System.Security.Cryptography.X509Certificates.StoreName]$StoreName,

        [Parameter(Mandatory=$true, HelpMessage='The name of the certificate store location to import the certificate to.')]
        [ValidateNotNullOrEmpty()]
        [System.Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation
    )

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $StoreName,$StoreLocation

    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $Path

    $store.Add($certificate)

    $store.Close()
}

Function Import-IADgovCertificates() {
    <#
    .SYNOPSIS
    Imports the certificates required to view www.iad.gov without receiving warnings in the browser.

    .DESCRIPTION
    Imports the certificates (DoD Root CA 3 and DoD ID SW CA-37) required to view www.iad.gov without receiving warnings in the browser.

    .EXAMPLE
    Import-IADgovCertificates
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Scope='Function')]
    [CmdletBinding()] 
    [OutputType([void])]
    Param()

    $dodRootCA3Certificate = @'
-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgIBATANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwJVUzEY
MBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAKBgNVBAsT
A1BLSTEWMBQGA1UEAxMNRG9EIFJvb3QgQ0EgMzAeFw0xMjAzMjAxODQ2NDFaFw0y
OTEyMzAxODQ2NDFaMFsxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVy
bm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMRYwFAYDVQQDEw1Eb0Qg
Um9vdCBDQSAzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqewUcoro
S3Cj2hADhKb7pzYNKjpSFr8wFVKGBUcgz6qmzXXEZG7v8WAjywpmQK60yGgqAFFo
STfpWTJNlbxDJ+lAjToQzhS8Qxih+d7M54V2c14YGiNbvT8f8u2NGcwD0UCkj6cg
AkwnWnk29qM3IY4AWgYWytNVlm8xKbtyDsviSFHy1DekNdZv7hezsQarCxmG6CNt
MRsoeGXF3mJSvMF96+6gXVQE+7LLK7IjVJGCTPC/unRAOwwERYBnXMXrolfDGn8K
Lb1/udzBmbDIB+QMhjaUOiUv8n3mlzwblLSXWQbJOuQL2erp/DtzNG/955jk86HC
kF8c9T8u1xnTfwIDAQABo0IwQDAdBgNVHQ4EFgQUbIqUonexgHIdgXoWqvLczmbu
RcAwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAJ9xpMC2ltKAQ6BI6R92BPnFPK1mGFhjm8O26GiKhVpCZhK00uaLiH+H
9Jj1qMYJyR/wLB/sgrj0pUc4wTMr30x+mr4LC7HLD3xQKBDPio2i6bqshtfUsZNf
Io+WBbRODHWRfdPy55TClBR2T48MqxCHWDKFB3WGEgte6lO0CshMhJIf6+hBhjy6
9E5BStFsWEdBw4Za8u7p8pgnguouNtb4Bl6C8aBSk0QJutKpGVpYo6hdIG1PZPgw
hxuQE0iBzcqQxw3B1Jg/jvIOV2gzEo6ZCbHw5PYQ9DbySb3qozjIVkEjg5rfoRs1
fOs/QbP1b0s6Xq5vk3aY0vGZnUXEjnI=
-----END CERTIFICATE-----
'@

    $dodIDSWCA37Certificate = @'
-----BEGIN CERTIFICATE-----
MIIEoDCCA4igAwIBAgIBEjANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwJVUzEY
MBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAKBgNVBAsT
A1BLSTEWMBQGA1UEAxMNRG9EIFJvb3QgQ0EgMzAeFw0xNTA5MjMxNTIzMDVaFw0y
MTA5MjMxNTIzMDVaMF0xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVy
bm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMRgwFgYDVQQDEw9ET0Qg
SUQgU1cgQ0EtMzcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCsrnKi
qfWUYvBZ5poN5GMO6qotl7XJ4GGfg/lr8ipbPcgYScw8HLXrxakW0wA+uEk3Yka/
/bfUgtiLCqr2/SMYVISjXisglAHUiK1pnXl6ANJ3FGX4eio9XdbvifXjcMu462T3
XoZAcbbwkk7j5G2P4uJn88h2GmprYJzePNLC38yMgi4FMRsPchVYpX3Fxk2wXEOg
hyeSYvueXWOzEtEDCEyrumQxHfW3Oru0b6JrTZMpztOlaTd9ngKLrIcKaXEyGtrj
lCokBmTALc6xnyKmUNf4R9Imo+lVbwSIycGnePOTrJccRTUbZsfXsFeD0lIWGnHY
rws1w9xarvIN7Gm9AgMBAAGjggFrMIIBZzAfBgNVHSMEGDAWgBRsipSid7GAch2B
ehaq8tzOZu5FwDAdBgNVHQ4EFgQUFiR+9y3B75I/vkTnVF7p/he686EwDgYDVR0P
AQH/BAQDAgGGMEwGA1UdIARFMEMwCwYJYIZIAWUCAQskMAsGCWCGSAFlAgELJzAL
BglghkgBZQIBCyowDAYKYIZIAWUDAgEDDTAMBgpghkgBZQMCAQMRMBIGA1UdEwEB
/wQIMAYBAf8CAQAwDAYDVR0kBAUwA4ABADA3BgNVHR8EMDAuMCygKqAohiZodHRw
Oi8vY3JsLmRpc2EubWlsL2NybC9ET0RST09UQ0EzLmNybDBsBggrBgEFBQcBAQRg
MF4wOgYIKwYBBQUHMAKGLmh0dHA6Ly9jcmwuZGlzYS5taWwvaXNzdWVkdG8vRE9E
Uk9PVENBM19JVC5wN2MwIAYIKwYBBQUHMAGGFGh0dHA6Ly9vY3NwLmRpc2EubWls
MA0GCSqGSIb3DQEBCwUAA4IBAQBZDRYy0oP+yD3OiDqM3liOggDDqJidDSkqmPMB
pxTL9iyXCAqS5OUhzKQ2/N8gRYzO1o7JNIqez7kuwj1HJ0LH94jbjyMnvrWV34mh
m1OzbG1y/88FvheQXLgld+tjojxYVhErbFGHnxMPw1X0VpbRTWrAcetlfMNKdwPU
AH1GDfFmczuSfqwqZcapgJal9BWMIJoCXH1sUOHXmg/6anXx1d30OH9iTYV0to76
oHTg6PEw7nwxNDgGcVgLDVyDAyTpfQCfhV4fSLI9cDTs4nA0SUgUga01d2h1Sp4r
0PtksjJINJlYvLggvRWucI/MokLw5F6m+w6BN+t+kEggLn6T
-----END CERTIFICATE-----
'@

    $rootCertificateFile = Join-Path -Path $env:USERPROFILE -ChildPath 'DoD_Root_CA_3.cer'
    $intermediateCertificateFile = Join-Path -Path $env:USERPROFILE -ChildPath 'DoD_ID_SW_CA-37.cer'

    Set-Content -Path $rootCertificateFile -Value $dodRootCA3Certificate -Encoding Ascii -Force 
    Set-Content -Path $intermediateCertificateFile -Value $dodIDSWCA37Certificate -Encoding Ascii -Force

    $osVersion = [System.Environment]::OSVersion.Version

    $version = [decimal]('{0}.{1}' -f $osVersion.Major,$osVersion.Minor)

    if ($version -ge 6.2) {
        # importing as an administrator into the machine store does not prompt the user
        # user will get a security warning prompt asking if they want to import the certificate which they will be required to answer Yes to
        # Import-Certificate only exists on Windows 8+

        try {
            Import-Certificate -FilePath $rootCertificateFile -CertStoreLocation cert:\LocalMachine\Root | Out-Null
            Import-Certificate -FilePath $intermediateCertificateFile -CertStoreLocation cert:\LocalMachine\CA | Out-Null
        } catch {
            Import-Certificate -FilePath $rootCertificateFile -CertStoreLocation cert:\CurrentUser\Root | Out-Null
            Import-Certificate -FilePath $intermediateCertificateFile -CertStoreLocation cert:\CurrentUser\CA | Out-Null
        }
    } else {
        try {
            Import-CertificateDownlevel -FilePath $rootCertificateFile -StoreName 'Root' -StoreLocation 'LocalMachine'
            Import-CertificateDownlevel -FilePath $intermediateCertificateFile -StoreName 'CertificateAuthority' -StoreLocation 'LocalMachine'
        } catch {
            Import-CertificateDownlevel -FilePath $rootCertificateFile -StoreName 'Root' -StoreLocation 'CurrentUser'
            Import-CertificateDownlevel -FilePath $intermediateCertificateFile -StoreName 'CertificateAuthority' -StoreLocation 'CurrentUser'
        }
    }

    Remove-Item -Path $rootCertificateFile -Force
    Remove-Item -Path $intermediateCertificateFile -Force
}

Import-IADgovCertificates