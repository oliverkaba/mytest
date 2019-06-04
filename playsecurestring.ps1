$Key = New-Object Byte[] 32   # You can use 16, 24, or 32 for AES
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
#$Key | out-file $KeyFile

$SecureString = ConvertTo-SecureString "Kennwort1" -AsPlainText -Force

#$SecureString = Read-Host -AsSecureString
#$generic = ConvertFrom-SecureString -SecureString $SecureString -Key (1..16)

$generic = ConvertFrom-SecureString -SecureString $SecureString -Key $Key
