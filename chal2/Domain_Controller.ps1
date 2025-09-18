# AD Lab powershell
Rename-Computer -NewName "DC01" -Restart

# Install Domain
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName hack.lu

# Set password never expires for the Administrator account
Set-ADUser -Identity "Administrator" -PasswordNeverExpires $true

# Set up low priv user
$LowPrivUser = "ta bort mig"
$LowPrivSAM = "ta_bort.mig"
$LowPrivPassword = "LjtLNg37LdcZin73"
$LowPrivDescription = "LjtLNg37LdcZin73"
$SecurePass = ConvertTo-SecureString $LowPrivPassword -AsPlainText -Force
New-ADUser -Name $LowPrivUser -SamAccountName $LowPrivSAM -AccountPassword $SecurePass -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false -Description $LowPrivDescription -Path "CN=Users,DC=hack,DC=lu"

# Set up DNS Admin for SRV02
$DomainUserDNS = "Øyvind Dennison"
$DomainSAMDNS = "Øyvind.Dennison"
$DomainPasswordDNS = "Z4f8hF2t#K3HJsfGJX!&"
$DomainDescriptionDNS = "Har fler CNAME än vänner. Sorterar sina strumpor efter färg."
$SecurePassDNS = ConvertTo-SecureString $DomainPasswordDNS -AsPlainText -Force
New-ADUser -Name $DomainUserDNS -SamAccountName $DomainSAMDNS -AccountPassword $SecurePassDNS -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false -Description $DomainDescriptionDNS -Path "CN=Users,DC=hack,DC=lu"
Add-ADGroupMember -Identity "DNSAdmins" -Members $DomainSAMDNS

# Set up Fluff Users
$DomainUserFluff1 = " Freja Lund"
$DomainSAMFluff1 = "Freja.Lund"
$DomainPasswordFluff1 = "2r8K7gYE*%wftx"
# TODO: description auf Schwedisch generieren
$DomainDescriptionFluff1 = "Dekorationsguru: Gör hyllor glada. Vattnar växter mer punktligt än cronjobs."
$SecurePassFluff1 = ConvertTo-SecureString $DomainPasswordFluff1 -AsPlainText -Force
New-ADUser -Name $DomainUserFluff1 -SamAccountName $DomainSAMFluff1 -AccountPassword $SecurePassFluff1 -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false -Description $DomainDescriptionFluff1 -Path "CN=Users,DC=hack,DC=lu"

# ============== DNS Service Configuration ==============
# ACL to allow DNS remote control
$service = Get-WmiObject -Class Win32_Service -Filter "Name='DNS'"
$sid = (New-Object System.Security.Principal.NTAccount($DomainSAM)).Translate([System.Security.Principal.SecurityIdentifier]).Value

# Get current SDDL for DNS service
$sddl = sc.exe sdshow "DNS"
$csd = New-Object System.Security.AccessControl.CommonSecurityDescriptor $false, $false, $sddl

# Define access rights: SERVICE_START (0x10), SERVICE_STOP (0x20), SERVICE_QUERY_STATUS (0x04) => 0x34
$accessMask = 0x34

# Add ACE to DACL
$csd.DiscretionaryAcl.AddAccess(
    [System.Security.AccessControl.AccessControlType]::Allow,
    $sid,
    $accessMask,
    [System.Security.AccessControl.InheritanceFlags]::None,
    [System.Security.AccessControl.PropagationFlags]::None
)

# Convert descriptor back to SDDL
$newSddl = $csd.GetSddlForm("All")

# Apply updated SDDL to the service
sc.exe sdset $service.name $newSddl
# ============== DNS Service Configuration ==============

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\SCM"
$valueName = "RemoteAccessCheckExemptionList"
$newEntry = "dns"

# Get current values (if the value exists)
$currentValues = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $valueName -ErrorAction SilentlyContinue
$updatedValues = @($currentValues)
if ($updatedValues -notcontains $newEntry) {
    $updatedValues += $newEntry
}

# Write updated multi-string back to registry
Set-ItemProperty -Path $regPath -Name $valueName -Value $updatedValues -Type MultiString

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
                 -Name "LdapEnforceChannelBinding" `
                 -Value 0

# Allow anonymous access to SAM accounts
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
#                 -Name "RestrictAnonymousSAM" -Value 0


Import-Module ActiveDirectory
$dn = "DC=North,DC=sevenkingdoms,DC=local"
$sid = (New-Object System.Security.Principal.NTAccount("NT AUTHORITY\ANONYMOUS LOGON")).Translate([System.Security.Principal.SecurityIdentifier])
$acl = Get-Acl "AD:\$dn"
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $sid,[System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,"Allow",[System.DirectoryServices.ActiveDirectorySecurityInheritance]::All))
Set-Acl "AD:\$dn" $acl


# GENERATE TLS CERT

# Reboot to apply all changes
Restart-Computer
