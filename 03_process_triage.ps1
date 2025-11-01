\
    Param(
      [string]$Baseline = ".\snapshots\processes_baseline.json",
      [switch]$DryRun,
      [switch]$AutoRemediate
    )
    . .\utils.ps1
    $cfg = Load-Config
    $current = Get-Process | Select-Object Id,ProcessName,Path,StartTime | ForEach-Object {
        $p = $_
        $hash = $null
        try { if ($p.Path) { $hash = (Get-FileHash -Path $p.Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } } catch {}
        [PSCustomObject]@{Id=$p.Id;Name=$p.ProcessName;Path=$p.Path;Hash=$hash}
    }

    $unknown = $current | Where-Object { -not ($cfg.whitelist.processes -contains $_.Name) }

    if ($unknown.Count -gt 0) {
        $unknown | ConvertTo-Json -Depth 2 | Out-File ".\logs\process_triage_$(Get-Date -Format yyyyMMdd_HHmmss).json"
        Write-Output "Unknown processes:"
        $unknown | Format-Table -AutoSize
        if ($AutoRemediate) {
            foreach ($p in $unknown) {
                if ($DryRun) { Write-Output "DRY-RUN would stop process $($p.Name) ($($p.Id))" } else {
                    try { Stop-Process -Id $p.Id -Force -ErrorAction Stop; Log-Line "Stopped process $($p.Name) ($($p.Id))" } catch { Log-Line "Failed to stop $($p.Name): $_" }
                }
            }
        }
    } else {
        Write-Output "No unknown processes found."
    }
