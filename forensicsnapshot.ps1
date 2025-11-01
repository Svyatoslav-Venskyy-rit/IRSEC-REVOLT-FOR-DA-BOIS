$t=Get-Date -Format 'yyyyMMdd_HHmmss'; New-Item -Path . -Name $t -ItemType Directory; Get-Process | Export-Csv .\$t\processes.csv -NoTypeInformation
