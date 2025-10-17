# Update System and rename computer
Install-Module -Name PSWindowsUpdate -Force
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll
Rename-Computer -NewName "DC01" -Restart

# Install Domain
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "hack.lu"

# Set password never expires for the Administrator account
Set-ADUser -Identity "Administrator" -PasswordNeverExpires $true

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
$str_Computer = "Dator"
$str_DomainComputers = "Domändatorer"

Install-Module -Name ADCSTemplate
($OldTemplate = Export-ADCSTemplate -DisplayName "$str_Computer" | ConvertFrom-Json).'msPKI-Certificate-Name-Flag' = 1
New-ADCSTemplate -DisplayName $TemplateName -JSON ($OldTemplate | ConvertTo-Json) -Publish
Set-ADCSTemplateACL -DisplayName $TemplateName -Type Allow -Identity "HACK.LU\$str_DomainComputers" -Enroll

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
    (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-7")).Translate([System.Security.Principal.SecurityIdentifier]),
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
Remove-ItemProperty $reg "Schema Update Allowed"

# PATCH VULNS
# Set MAQ to 0
Set-ADDomain -Identity hack.lu -Replace @{"ms-DS-MachineAccountQuota"="0"}

# Echo Flag into Desktop/flag.txt
$text = Read-Host "Enter Flag"
$text | Out-File -FilePath "$env:USERPROFILE\Desktop\flag.txt"

# Set IP and Gateway
New-NetIPAddress -IPAddress "10.244.0.10" -PrefixLength 32 -DefaultGateway "10.244.1.2" -InterfaceAlias "Ethernet"