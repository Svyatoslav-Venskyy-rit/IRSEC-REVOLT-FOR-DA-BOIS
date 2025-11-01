Get-NetTCPConnection -State Listen | Select LocalAddress,LocalPort,@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}
