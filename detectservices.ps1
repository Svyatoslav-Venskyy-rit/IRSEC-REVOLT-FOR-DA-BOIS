Get-Service | Select Name,DisplayName,Status,@{n='StartType';e={(Get-CimInstance Win32_Service -Filter "Name='$_'").StartMode}} | Export-Csv services.csv -NoTypeInformation
#make 2 of them make sure to edit the name of it and add a 1 or something
#compare with winmerge
