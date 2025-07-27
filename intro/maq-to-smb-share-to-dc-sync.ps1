# AD Lab powershell
Rename-Computer -NewName "DC01" -Restart

$DomainName = "hack.lu"
$DomainCN = "DC=hack,DC=lu"

# Install Domain
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName $DomainName

# Set password never expires for the Administrator account
Set-ADUser -Identity "Administrator" -PasswordNeverExpires $true

# Create SMB share for computer accounts
New-Item -ItemType Directory -Path "C:\IT-Deployment" -Force
$Parameters = @{
    Name = 'IT-Deployment'
    Path = 'C:\IT-Deployment'
    ReadAccess = "$DomainName\Domain Computers"
    FullAccess = "$DomainName\Administrator"
}
New-SmbShare @Parameters

# List of tools to download
$tools = @(
    @{ Name = "7-Zip"; Url = "https://www.7-zip.org/a/7z2500-x64.exe"; File = "7zip.exe" },
    @{ Name = "WinSCP"; Url = "https://winscp.net/download/WinSCP-6.5.3-Setup.exe/download"; File = "winscp.exe" },
    @{ Name = "PuTTY"; Url = "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe"; File = "putty.exe" },
    @{ Name = "Notepad++"; Url = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6.8/npp.8.6.8.Installer.x64.exe"; File = "notepadpp.exe" },
    @{ Name = "Sysinternals Suite"; Url = "https://download.sysinternals.com/files/SysinternalsSuite.zip"; File = "sysinternals.zip" }
)

# Download files
foreach ($tool in $tools) {
    $outPath = Join-Path $Parameters.Path $tool.File
    Invoke-WebRequest -Uri $tool.Url -OutFile $outPath
}

# TODO: CHANGE IP FOR YOUR SETUP CLIENT
# Start web server and download creds file from local server: python -m http.server 8000
Invoke-WebRequest -Uri "http://192.168.108.128:8000/DeployNewComputer.ps1" -OutFile "C:\IT-Deployment\DeployNewComputer.ps1"

# Create a new low priv user
$LowPrivUser = "Donald Duck"
$LowPrivSAM = "Donald.Duck"
$LowPrivPassword = "Daisy4Ever!"
$Description = "I may be short-tempered and unlucky, but I never give up and always give it my all!"
$SecureLowPrivPass = ConvertTo-SecureString $LowPrivPassword -AsPlainText -Force
New-ADUser -Name $LowPrivUser -SamAccountName $LowPrivSAM -AccountPassword $SecureLowPrivPass -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false -Path "CN=Users,$DomainCN" -Description $Description

# Create a new high priv user
$DomainUser = "Dagobert Duck"
$DomainSAM = "Dagobert.Duck"
$DomainPassword = "I_L0ve_M0n3y!"
$Description = "I am the richest duck in the world!"
$SecurePass = ConvertTo-SecureString $DomainPassword -AsPlainText -Force
New-ADUser -Name $DomainUser -SamAccountName $DomainSAM -AccountPassword $SecurePass -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false -Path "CN=Users,$DomainCN" -Description $Description

# Assign DC-sync rights to the high priv user
dsacls $DomainCN /G "$DomainName\$DomainSAM:CA;Replicating Directory Changes"
dsacls $DomainCN /G "$DomainName\$DomainSAM:CA;Replicating Directory Changes All"