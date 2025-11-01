\
    Param(
      [string]$Baseline = ".\snapshots\services_baseline.json",
      [switch]$DryRun,
      [switch]$AutoRemediate
    )
    . .\utils.ps1
    $cfg = Load-Config
    if (-not (Test-Path $Baseline)) { Write-Error "Baseline not found: $Baseline"; exit 1 }
    $base = Get-Content $Baseline | ConvertFrom-Json
    $current = Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName

    $added = @()
    foreach ($s in $current) {
        if (-not ($base | Where-Object { $_.Name -eq $s.Name })) { $added += $s }
    }

    if ($added.Count -gt 0) {
        Log-Line "Service delta found: $($added | Measure-Object | Select-Object -ExpandProperty Count) new/changed services"
        $added | ConvertTo-Json -Depth 3 | Out-File ".\logs\service_delta_$(Get-Date -Format yyyyMMdd_HHmmss).json"
        Write-Output "New/changed services:"
        $added | Format-Table -AutoSize
        if ($AutoRemediate) {
            foreach ($s in $added) {
                if ($cfg.whitelist.services -contains $s.Name) { Log-Line "Service $($s.Name) is whitelisted; skipping"; continue }
                if ($DryRun) { Write-Output "DRY-RUN would stop and disable $($s.Name)" } else {
                    try { Stop-Service -Name $s.Name -Force -ErrorAction Stop; Set-Service -Name $s.Name -StartupType Disabled; Log-Line "Stopped & disabled $($s.Name)"; Write-Output "Stopped $($s.Name)" } catch { Log-Line "Failed to remediate $($s.Name): $_"; Write-Output "Failed: $_" }
                }
            }
        }
    } else {
        Write-Output "No service delta detected."
    }
