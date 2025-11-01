Get-ChildItem C:\Windows\System32 -Recurse -File | Get-FileHash -Algorithm SHA256 | Export-Csv sys32_hashes.csv -NoTypeInformation
