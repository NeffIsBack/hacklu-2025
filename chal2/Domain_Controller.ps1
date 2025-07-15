# AD Lab powershell
Rename-Computer -NewName "DC01" -Restart

# Install Domain
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName hack.lu

# Set up DNS Admin for SRV02
$DomainUser = "Øyvind Dennison"
$DomainSAM = "Øyvind.Dennison"
$DomainPassword = "Z4f8hF2t#K3HJsfGJX!&"
$SecurePass = ConvertTo-SecureString $DomainPassword -AsPlainText -Force
New-ADUser -Name $DomainUser -SamAccountName $DomainSAM -AccountPassword $SecurePass -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false -Path "CN=Users,DC=hack,DC=lu"

Add-ADGroupMember -Identity "DNSAdmins" -Members $DomainSAM


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

# Reboot
Restart-Computer