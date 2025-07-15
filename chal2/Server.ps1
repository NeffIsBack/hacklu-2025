# AD Lab powershell
Rename-Computer -NewName "SRV02" -Restart

# Set DC as DNS server and join to domain
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses "192.168.108.134"
Add-Computer -DomainName "hack.lu" -Credential (Get-Credential) -Restart

# Allow SMB in firewall
Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True

# DNS installation
Install-WindowsFeature -Name DNS -IncludeManagementTools
#Set-Service -Name "DNS" -StartupType Automatic
#Start-Service -Name "DNS"

# Remove PS history
Remove-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -Force -ErrorAction SilentlyContinue



# Enforce SMB Signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1