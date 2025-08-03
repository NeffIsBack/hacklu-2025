# Change keyboard to Englisch US International
$Lang = Get-WinUserLanguageList
$Lang[0].InputMethodTips.Clear() 
$Lang[0].InputMethodTips.Add("0409:00020409") # 0409:00020409 = US-International
Set-WinUserLanguageList -LanguageList $Lang -Force


# Several different checks if the TLS cert is valid for LDAPS
$dcFQDN = "$env:COMPUTERNAME.$((Get-ADDomain).DNSRoot)"
$storePath = "Cert:\LocalMachine\My"

Get-ChildItem -Path $storePath | Where-Object {
    $_.HasPrivateKey -and
    $_.EnhancedKeyUsageList.FriendlyName -contains "Server Authentication"
} | ForEach-Object {
    $subject = $_.Subject
    $san = $_.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" } | ForEach-Object { $_.Format(0) }
    $trusted = ($_.Verify() -eq $true)

    [PSCustomObject]@{
        Subject = $subject
        SANs = $san
        NotAfter = $_.NotAfter
        Trusted = $trusted
        HasPrivateKey = $_.HasPrivateKey
        MatchesFQDN = ($subject -like "*$dcFQDN*" -or $san -like "*$dcFQDN*")
        Thumbprint = $_.Thumbprint
    }
}
