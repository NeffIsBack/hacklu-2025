# AD Lab powershell
Rename-Computer -NewName "SRV02" -Restart

# Set password never expires for the Administrator account
Set-LocalUser -Name "Administrator" -PasswordNeverExpires $True

$domain = "hack.lu"

# Set DC as DNS server and join to domain
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses "192.168.108.145"
Add-Computer -DomainName $domain -Credential (Get-Credential) -Restart

# Allow SMB in firewall
Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True

# DNS installation
Install-WindowsFeature -Name DNS -IncludeManagementTools
# WebClient installation
Enable-WindowsOptionalFeature -Online -FeatureName "WebDAV-Redirector" -All
Start-Service WebClient
Set-Service WebClient -StartupType Automatic

# Enforce SMB Signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1

# Remove PS history
Remove-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -Force -ErrorAction SilentlyContinue


