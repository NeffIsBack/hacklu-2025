## Attack chain idea
1. Mit null auth --users enumerieren und user mit pw in description finden
2. Mit low priv user DNS Eintrag für HTTP relay erstellen
3. Coercion von SRV02
4. HTTP Relay von SRV02 zu ldap://DC01
5. RBCD um an SRV02$ zu kommen
6. Mit SRV02$ local admin mit s4u2self magic
7. Credential Dump von scheduled tasks um den High Priv user zu bekommen
8. Mit High Priv user selbst zu Kontenoperatoren hinzufügen
9. Mit Kontenoperatoren Passwort von DC01$ auf known Wert setzen

### Befehle
 * Add DNS entry: `python dnstool.py -u hack.lu\\ta_bort.mig -p 'LjtLNg37LdcZin73' ldaps://192.168.108.134 -port 636 -a add -r kali --data 192.168.108.128 -dns-ip 192.168.108.134`
