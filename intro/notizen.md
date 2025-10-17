Ich würde gerne NetExec, Impacket und Bloodhound vorstellen. Das sind so die absoluten Klassiker die man eigentlich immer braucht. Am Ende dann noch verlinken auf Certipy und Responder, weil man die auch super häufig braucht. Mein priv esc path:
- Gestellte Credentials für den easy ersteinstieg
- Ein bisschen enumerieren mit SMB&LDAP
- Dadurch auf einen "Installation-script" share auf den der User aber keinen READ Zugriff hat
- Durch enumeration auch den default MAQ=10 finden => Neuen Computer account anlegen
- Computer haben für "die Erstinstallation" READ privs auf den installationsshare (macht story technisch Sinn für mich)
- Darauf befinden sich installer für alles mögliche und ein klassisches Powershell script mit Zugangsdaten für einen hoch privilegierten aber nicht DA account
- Dann soll man Bloodhound mal anwerfen, der dann entdeckt dass dieser neue account den wir erbeutet haben zwar kein DA ist, aber DCSync privs hat
- Mit dem Account mit DCsync privs dann NTDS.dit mit secretsdump dumpen (damit man mal was anderes als netexec nutzt lol)
- Mit Dom Admin & pass-the-hash (wew such a crazy attack... not) einloggen und letzten part der flag holen


# Description:
You have no idea what **Active Directory** is or how it works? Are you eager to learn how to compromise an Active Directory environment? Then you are in the right place!

Download the zip file and follow the instructions to own your first Active Directory environment.

teaser:How to compromise an Active Directory environment