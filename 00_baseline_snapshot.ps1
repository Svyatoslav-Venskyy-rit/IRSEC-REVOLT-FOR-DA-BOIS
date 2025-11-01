\
    Param(
      [string]$Output = ".\snapshots",
      [switch]$DryRun
    )
    . .\utils.ps1
    if (-not (Test-Path $Output)) { New-Item -Path $Output -ItemType Directory -Force | Out-Null }

    $cfg = Load-Config
    Log-Line "Starting baseline snapshot to $Output"
    $proc = Get-Process | Select-Object Id,ProcessName,Path,StartTime,StartInfo -ErrorAction SilentlyContinue
    $services = Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName
    $tasks = schtasks /Query /FO LIST /V 2>$null

    $ports = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess

    $hashes = @()
    foreach ($p in $cfg.paths_to_hash) {
        $hashes += Get-FileHashRecursive -Path $p
    }

    $proc | ConvertTo-Json -Depth 3 | Out-File (Join-Path $Output "processes_baseline.json") -Force
    $services | ConvertTo-Json -Depth 3 | Out-File (Join-Path $Output "services_baseline.json") -Force
    $ports | ConvertTo-Json -Depth 3 | Out-File (Join-Path $Output "ports_baseline.json") -Force
    $hashes | ConvertTo-Json -Depth 3 | Out-File (Join-Path $Output "hashes_baseline.json") -Force

    Log-Line "Baseline snapshot complete"
    Write-Output "Baseline snapshot saved to $Output"
