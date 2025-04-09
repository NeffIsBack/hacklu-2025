# AD Lab powershell
Rename-Computer -NewName "DC01" -Restart

# Install Domain
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName hack.lu

# Setup ADCS
Install-WindowsFeature AD-Certificate
Install-AdcsCertificationAuthority -CAType EnterpriseRootCA
# Install Web Enrollment
Install-WindowsFeature ADCS-Enroll-Web-Svc
Install-AdcsEnrollmentWebService

# ADD VULNS
Import-Module ActiveDirectory
# Add ESC1 Template
# Source: https://github.com/GoateePFE/ADCSTemplate/blob/master/ADCSTemplate.psm1
$TemplateName = "köttbullar"

Install-Module -Name ADCSTemplate
($OldTemplate = Export-ADCSTemplate -DisplayName "Computer" | ConvertFrom-Json).'msPKI-Certificate-Name-Flag' = 1
New-ADCSTemplate -DisplayName $TemplateName -JSON ($OldTemplate | ConvertTo-Json) -Publish
Set-ADCSTemplateACL -DisplayName $TemplateName -Type Allow -Identity 'HACK.LU\Domain Computers' -Enroll

# Add computer account
$DomainCN = "DC=hack,DC=lu"
New-ADComputer -Name "dator" -SamAccountName "dator" -Path "CN=Computers,$DomainCN" -AccountPassword (ConvertTo-SecureString "vy6A8VGpN7gMxZ" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
# Add the unixUserPassword attribute
Set-ADObject -Identity "CN=dator,CN=Computers,$DomainCN" -Replace @{unixUserPassword = "vy6A8VGpN7gMxZ"}

# Enable "ANONYMOUS LOGON" logon and query for ldap
# Set dSHeuristics to 0000002 (0x2) to allow anonymous access to the directory service
Set-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$DomainCN" -Replace @{dSHeuristics = "0000002"}

# Set the ACL to allow full Read access to the "ANONYMOUS LOGON" group
$acl = Get-Acl "AD:$DomainCN"
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    (New-Object System.Security.Principal.NTAccount("ANONYMOUS LOGON")).Translate([System.Security.Principal.SecurityIdentifier]),
    [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty,GenericExecute",
    [System.Security.AccessControl.AccessControlType]::Allow,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
)
$acl.AddAccessRule($rule)
Set-Acl -Path "AD:$DomainCN" -AclObject $acl

# Configure the unixUserPassword attribute to be non-CONFIDENTIAL, so that it is readable by "ANONYMOUS LOGON"
$attrName = "unixUserPassword"
$reg = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters";
if ("$env:COMPUTERNAME.$env:USERDNSDOMAIN" -ne (Get-ADForest).SchemaMaster) { throw "Run on Schema Master" }
Set-ItemProperty $reg "Schema Update Allowed" 1
$conn = [ADSI]"LDAP://CN=$attrName,CN=Schema,CN=Configuration,$DomainCN"
$conn.Put("searchFlags", 0)
$conn.SetInfo()
Remove-ItemProperty $reg "Schema Update Allowed" -ErrorAction SilentlyContinue




### JUNK
$schemaMaster = (Get-ADForest).SchemaMaster
$currentHost = "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
$adminCheck = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrator")
$schemaAdminCheck = ([ADSI]"LDAP://CN=Schema Admins,CN=Users,DC=sevenkingdoms,DC=local").member -match $env:USERNAME

[PSCustomObject]@{
    CurrentHost           = $currentHost
    SchemaMaster          = $schemaMaster
    IsAdmin               = $adminCheck
    IsInSchemaAdminsGroup = $schemaAdminCheck
    SchemaWriteEnabled    = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "Schema Update Allowed").'Schema Update Allowed'
}

# Config
$attributeName = "unixUserPassword"
$disableWriteAfter = $true

# Get the Schema Master DC
$schemaMaster = (Get-ADForest).SchemaMaster
$currentHost = "$env:COMPUTERNAME.$env:USERDNSDOMAIN"

if ($currentHost -ne $schemaMaster) {
    Write-Error "This script must be run on the Schema Master: $schemaMaster"
    return
}

# Enable Schema Writing
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
Set-ItemProperty -Path $regPath -Name "Schema Update Allowed" -Value 1

# Modify the attribute's searchFlags
$schemaPath = "LDAP://CN=$attributeName,CN=Schema,CN=Configuration,$DomainCN"
$attr = [ADSI]$schemaPath
$attr.Put("searchFlags", 0)
$attr.SetInfo()
Write-Host "Modified 'searchFlags' of $attributeName to 0"

# Optionally disable schema writing again
if ($disableWriteAfter) {
    Remove-ItemProperty -Path $regPath -Name "Schema Update Allowed" -ErrorAction SilentlyContinue
    Write-Host "Schema writing disabled again."
}



(Get-Acl "AD:CN=Computers,DC=sevenkingdoms,DC=local").Access | Where-Object { $_.IdentityReference -eq "NT AUTHORITY\ANONYMOUS LOGON" }


$ADObject = "$DomainCN"
$acl = Get-Acl "AD:$ADObject"
$anonymousLogon = New-Object System.Security.Principal.NTAccount("ANONYMOUS LOGON")
$sid = $anonymousLogon.Translate([System.Security.Principal.SecurityIdentifier])
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericExecute,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [DirectoryServices.ActiveDirectorySecurityInheritance]::All
)
$acl.AddAccessRule($rule)
Set-ACL -Path "AD:$ADObject" -AclObject $acl






# Define the Distinguished Name (DN) of the Active Directory object
$ADObject = "CN=Computers,$DomainCN"

# Get the current ACL for the object
$acl = Get-Acl "AD:$ADObject"

# List all the access rules (ACLs) on the object
$acl.Access

# Define the Distinguished Name (DN) of the AD object (replace with your own DN)
$ADObject = "CN=Computers,$DomainCN"

# Get the current ACL for the object
$acl = Get-Acl "AD:$ADObject"

# Create the Access Control Rule for "ANONYMOUS LOGON" (anonymous users)
$rule = New-Object DirectoryServices.ActiveDirectoryAccessRule(
    "ANONYMOUS LOGON",          # Identity for anonymous access
    "ReadProperty",             # Permission to read object properties
    "Allow"                   # Propagation (None means it doesn't propagate to child objects)
)

# Add the rule to the ACL
$acl.AddAccessRule($rule)

# Apply the updated ACL back to the AD object
Set-Acl "AD:$ADObject" $acl



# Connect to the schema partition of the domain
$schema = [ADSI]"LDAP://CN=Computers,DC=hack,DC=lu"

$acl = $schema.psbase.ObjectSecurity

# Display the ACL
$acl | Format-List
### JUNK


# PATCH VULNS
# Set MAQ to 0
Set-ADDomain -Identity hack.lu -Replace @{"ms-DS-MachineAccountQuota"="0"}




# OTHER
# Change keyboard to Englisch US International
$Lang = Get-WinUserLanguageList
$Lang[0].InputMethodTips.Clear() 
$Lang[0].InputMethodTips.Add("0409:00020409") # 0409:00020409 = US-International
Set-WinUserLanguageList -LanguageList $Lang -Force