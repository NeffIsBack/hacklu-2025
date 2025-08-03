# GenerateSelfSignedCert.ps1
# Generates a self-signed certificate for the Domain Controller

# --- Custom variables ---
$domainName = "hack.lu"
$certPass = "ww6vowomLpm4ZMaZ"
$certPath = "C:\Certs"
$certCN = "$env:COMPUTERNAME.$domainName"
$validYears = 5

# --- Create folder if needed ---
if (!(Test-Path $certPath)) {
    New-Item -Path $certPath -ItemType Directory -Force | Out-Null
}

Write-Host "[*] Generating self-signed certificate for LDAPS ($certCN)..."

# --- DNS Names for the cert (SANs) ---
$dnsNames = @(
    "$env:COMPUTERNAME",
    "$env:COMPUTERNAME.$domainName",
    "localhost"
)

# --- Create the certificate ---
$cert = New-SelfSignedCertificate `
    -DnsName $dnsNames `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -Subject "CN=$certCN" `
    -KeyExportPolicy Exportable `
    -KeyLength 2048 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears($validYears) `
    -TextExtension @("2.5.29.19={critical}{text}ca=true") `
    -KeyUsage KeyEncipherment, DigitalSignature `
    -Type SSLServerAuthentication

Write-Host "[+] Certificate created successfully."

# --- Export the certificate and private key ---
$pfxPath = Join-Path $certPath "$certCN.pfx"
$cerPath = Join-Path $certPath "$certCN.cer"
$securePass = ConvertTo-SecureString -String $certPass -AsPlainText -Force

Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $securePass
Export-Certificate -Cert $cert -FilePath $cerPath

Write-Host "[*] Exported:"
Write-Host "  - PFX: $pfxPath"
Write-Host "  - CER: $cerPath"

# --- Restart NTDS to apply (or reboot) ---
Write-Host "[*] Restarting to activate LDAPS..."
Restart-Computer -Force
