# Update System and rename computer
Install-Module -Name PSWindowsUpdate -Force
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
Rename-Computer -NewName "SRV02" -Restart

# Set password never expires for the Administrator account
Set-LocalUser -Name "Administratör" -PasswordNeverExpires $True     # CAREFUL, CHANGED FOR SWEDISH IMAGE: "Administrator" in Swedish

$domain = "hack.lu"

# Set DC as DNS server and join to domain for setup
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses "192.168.108.140"   # TODO: CHANGE IP FOR YOUR SETUP DC
Add-Computer -DomainName $domain -Credential (Get-Credential) -Restart

# Allow SMB in firewall
Set-NetFirewallRule -DisplayGroup "Fil- och skrivardelning" -Enabled True   # CAREFUL, CHANGED FOR SWEDISH IMAGE: "File and Printer Sharing" in Swedish

# WebClient installation
Enable-WindowsOptionalFeature -Online -FeatureName "WebDAV-Redirector" -All
Start-Service WebClient
Set-Service WebClient -StartupType Automatic

# Create Scheduled Task so that the credentials of maja.lindgren are in dpapi
$action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NoProfile -WindowStyle Hidden -Command whoami'
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -WeeksInterval 2 -At 3am
$settings= New-ScheduledTaskSettingsSet -StartWhenAvailable

Register-ScheduledTask -TaskName "ExistentialCrisis" -Action $action -Trigger $trigger -Settings $settings -User "hack.lu\maja.lindgren" -Password "Z4f8hF2t#K3HJsfGJX!&"

# Enforce SMB Signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1

# Remove PS history
Remove-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -Force -ErrorAction SilentlyContinue

# Set IP and Gateway
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses "10.244.0.11"
New-NetIPAddress -IPAddress "10.244.0.11" -PrefixLength 0 -DefaultGateway "10.244.1.2" -InterfaceAlias "Ethernet0"