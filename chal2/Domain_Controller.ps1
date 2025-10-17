# Update System and rename computer
Install-Module -Name PSWindowsUpdate -Force
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll
Rename-Computer -NewName "DC01" -Restart

# Install Domain
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "hack.lu"

# Set password never expires for the Administrator account
Set-ADUser -Identity "Administrator" -PasswordNeverExpires $true

# Set up low priv user
$LowPrivUser = "ta bort mig"
$LowPrivSAM = "ta_bort.mig"
$LowPrivPassword = "LjtLNg37LdcZin73"
$LowPrivDescription = "Praktikant: Lär sig Active Directory och hämtar kaffe med samma entusiasm. LjtLNg37LdcZin73"
$SecurePass = ConvertTo-SecureString $LowPrivPassword -AsPlainText -Force
New-ADUser -Name $LowPrivUser -SamAccountName $LowPrivSAM -AccountPassword $SecurePass -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false -Description $LowPrivDescription -Path "CN=Users,DC=hack,DC=lu"

# Set up Privileged account
$HighPrivUser = "Maja Lindgren"
$HighPrivSAM = "maja.lindgren"
$HighPrivPassword = "Z4f8hF2t#K3HJsfGJX!&"
$HighPrivDescription = "Helpdesk-hjälte: Frågar alltid 'har du provat att starta om?' innan hon räddar dagen."
$HighPrivSecurePass = ConvertTo-SecureString $HighPrivPassword -AsPlainText -Force
New-ADUser -Name $HighPrivUser -SamAccountName $HighPrivSAM -AccountPassword $HighPrivSecurePass -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false -Description $HighPrivDescription -Path "CN=Users,DC=hack,DC=lu"

# Set up Fluff Users
$DomainUserFluff1 = "Freja Lund"
$DomainSAMFluff1 = "Freja.Lund"
$DomainPasswordFluff1 = "2r8K7gYE*%wftx"
$DomainDescriptionFluff1 = "Dekorationsguru: Gör hyllor glada. Vattnar växter mer punktligt än cronjobs."
$SecurePassFluff1 = ConvertTo-SecureString $DomainPasswordFluff1 -AsPlainText -Force
New-ADUser -Name $DomainUserFluff1 -SamAccountName $DomainSAMFluff1 -AccountPassword $SecurePassFluff1 -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false -Description $DomainDescriptionFluff1 -Path "CN=Users,DC=hack,DC=lu"

$DomainUserFluff2 = "Sven Andersson"
$DomainSAMFluff2 = "Sven.Andersson"
$DomainPasswordFluff2 = "B9!cZ4mEwP3@qy"
$DomainDescriptionFluff2 = "Skruvkung: Monterar problem snabbare än manualen hinner öppnas."
$SecurePassFluff2 = ConvertTo-SecureString $DomainPasswordFluff2 -AsPlainText -Force
New-ADUser -Name $DomainUserFluff2 -SamAccountName $DomainSAMFluff2 -AccountPassword $SecurePassFluff2 -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false -Description $DomainDescriptionFluff2 -Path "CN=Users,DC=hack,DC=lu"

$DomainUserFluff3 = "Björn Ek"
$DomainSAMFluff3 = "Bjorn.Ek"
$DomainPasswordFluff3 = "yP!6hQw9@TmE2b"
$DomainDescriptionFluff3 = "Instruktionsartist: Ritar manualer som ingen läser men alla behöver."
$SecurePassFluff3 = ConvertTo-SecureString $DomainPasswordFluff3 -AsPlainText -Force
New-ADUser -Name $DomainUserFluff3 -SamAccountName $DomainSAMFluff3 -AccountPassword $SecurePassFluff3 -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false -Description $DomainDescriptionFluff3 -Path "CN=Users,DC=hack,DC=lu"

# ============== CONFIGURE PRIV ESC FOR HIGH PRIV USER ==============
# Allow HighPriv user to add new members to Account Operators
### --- 1) Allow maja.lindgren to modify Account Operators membership ---
$GroupSID = 'S-1-5-32-548'              # Account Operators
$User = 'maja.lindgren'                 # Delegated user
$Group = Get-ADGroup -Identity $GroupSID
$Acl = Get-ACL "AD:\$($Group.DistinguishedName)"

$Guid = [GUID]"bf9679c0-0de6-11d0-a285-00aa003049e2"  # 'member' attribute
$Rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    (New-Object System.Security.Principal.NTAccount($User)),
    "WriteProperty",
    "Allow",
    $Guid
)

$Acl.AddAccessRule($Rule)
Set-ACL -Path "AD:\$($Group.DistinguishedName)" -AclObject $Acl

### --- 2) Allow Account Operators to reset DC01 password ---
$dc = Get-ADComputer "DC01"
$aclDC = Get-Acl "AD:$($dc.DistinguishedName)"
$forceChangeGuid = [GUID]"00299570-246d-11d0-a768-00aa006e0529"  # Reset/Force Change Password

$ruleDC = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $group.SID,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow#,
    #$forceChangeGuid    # Uncomment this line and the comma at the previousline to allow only ForceChangePassword instead of full AllExtendedRights
)
$aclDC.AddAccessRule($ruleDC)
Set-Acl -Path "AD:$($dc.DistinguishedName)" -AclObject $aclDC
# ============== CONFIGURE PRIV ESC FOR HIGH PRIV USER ==============

# ============== TODO: GENERATE TLS CERT ==============

# Set LDAP channel binding to 0 (disabled) to allow LDAP relay to work
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
                 -Name "LdapEnforceChannelBinding" `
                 -Value 0

# ============== Allow ANONYMOUS LOGON read ==============
Import-Module ActiveDirectory
$dn = "DC=hack,DC=lu"
$sid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-7")
$acl = Get-Acl "AD:\$dn"

# Define the rights for ANONYMOUS LOGON for samr enum domain users
$rights = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::GenericExecute
$type = [System.Security.AccessControl.AccessControlType]::Allow
$inherit = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All

# Create the new Access Control Entry (ACE) with all the specified parameters.
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, $type, $inherit)

# Add the new ACE to the domain's ACL.
$acl.AddAccessRule($ace)

# Apply the updated ACL to the domain object.
Set-Acl "AD:\$dn" $acl


# Path to LSA key
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

# Disable anonymous SAM restriction (0 = allow anonymous SAMR queries)
Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -Value 0 -Type DWord
# ============== Allow ANONYMOUS LOGON read ==============


# Reboot to apply all changes
Restart-Computer

# Echo Flag into Desktop/flag.txt
$text = Read-Host "Enter Flag"
$text | Out-File -FilePath "$env:USERPROFILE\Desktop\flag.txt"

# Set IP and Gateway
New-NetIPAddress -IPAddress "10.244.0.10" -PrefixLength 32 -DefaultGateway "10.244.1.2" -InterfaceAlias "Ethernet"