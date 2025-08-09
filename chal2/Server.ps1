# AD Lab powershell
Rename-Computer -NewName "SRV02" -Restart

$domain = "hack.lu"

# Set DC as DNS server and join to domain
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses "192.168.109.193"
Add-Computer -DomainName $domain -Credential (Get-Credential) -Restart

# Allow SMB in firewall
Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True

# DNS installation
Install-WindowsFeature -Name DNS -IncludeManagementTools
# WebClient installation
Enable-WindowsOptionalFeature -Online -FeatureName "WebDAV-Redirector" -All
Start-Service WebClient
Set-Service WebClient -StartupType Automatic

$sharePath = "C:\shares\EncryptedFiles"
$description = "Denna lagringsplats är avsedd för delning av känsliga dokument. Lagra endast krypterade dokument här."
# Create the folder if it doesn't exist and create smb share
New-Item -Path $sharePath -ItemType Directory -Force
New-SmbShare -Name "Krypterade filer$" -Path $sharePath -FullAccess "$domain\Domain Users" -Description $description


# Enforce SMB Signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1

# Remove PS history
Remove-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -Force -ErrorAction SilentlyContinue


