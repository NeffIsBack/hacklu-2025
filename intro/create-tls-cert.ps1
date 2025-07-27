# GenerateSelfSignedCert.ps1
# Generates a self-signed certificate for the Domain Controller

$domainName = "hack.lu"
$certPass = "ww6vowomLpm4ZMaZ"

param (
    [string]$CertName = "$env:COMPUTERNAME.$domainName",
    [int]$ValidYears = 5,
    [string]$CertPath = "C:\Certs"
)

# Create cert directory if needed
if (!(Test-Path -Path $CertPath)) {
    New-Item -ItemType Directory -Path $CertPath -Force | Out-Null
}

# Set certificate subject and DNS names
$subject = "CN=$CertName"
$dnsNames = @($CertName, "$env:COMPUTERNAME", "$env:COMPUTERNAME.$domainName")

# Generate certificate
$cert = New-SelfSignedCertificate `
    -DnsName $dnsNames `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -Subject $subject `
    -KeyExportPolicy Exportable `
    -KeyLength 2048 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears($ValidYears) `
    -TextExtension @("2.5.29.19={critical}{text}ca=true")

# Export the certificate and private key
$pfxPath = Join-Path $CertPath "$CertName.pfx"
$cerPath = Join-Path $CertPath "$CertName.cer"
$exportPassword = ConvertTo-SecureString -String $certPass -Force -AsPlainText

Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $exportPassword
Export-Certificate -Cert $cert -FilePath $cerPath

Write-Host "Certificate created and saved to:"
Write-Host " - $pfxPath (with private key)"
Write-Host " - $cerPath (public cert)"
