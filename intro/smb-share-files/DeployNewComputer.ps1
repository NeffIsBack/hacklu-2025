# DeployNewComputer.ps1
# Script to rename a computer, join it to a domain, and place it in an appropriate OU

$DomainName = "hack.lu"

param(
    [string]$NewComputerName = "PC-NEW",
    [string]$DomainName = $DomainName,
    [string]$OU = "OU=Workstations,DC=hack,DC=lu"
)

Write-Host "[*] Renaming computer to $NewComputerName"
Rename-Computer -NewName $NewComputerName -Force -PassThru

# Sleep to allow name change
Start-Sleep -Seconds 5

# Creds
$encoded = "SV9MMHZlX00wbjN5IQ=="
$decodedPassword = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
$securePassword = ConvertTo-SecureString $decodedPassword -AsPlainText -Force

# Build PSCredential object
$username = "$DomainName\\dagobert.duck"
$cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)

# Join the domain
Write-Host "[*] Attempting to join $DomainName domain..."
Add-Computer -DomainName $DomainName -OUPath $OU -Credential $cred -PassThru -Verbose

# Reboot to complete domain join
Write-Host "[*] Rebooting to finalize domain join..."
Restart-Computer
