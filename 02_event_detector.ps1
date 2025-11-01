\
    Param(
      [int]$Minutes = 30,
      [switch]$DryRun
    )
    . .\utils.ps1
    $cfg = Load-Config
    $start = (Get-Date).AddMinutes(-$Minutes)
    $events = @()
    foreach ($id in $cfg.event_ids) {
        try {
            $events += Get-WinEvent -FilterHashtable @{LogName='Security';Id=$id;StartTime=$start} -ErrorAction SilentlyContinue
        } catch {}
    }
    if ($events.Count -gt 0) {
        $out = $events | Select-Object TimeCreated,Id,ProviderName,Message | ConvertTo-Json -Depth 2
        $path = ".\logs\events_$(Get-Date -Format yyyyMMdd_HHmmss).json"
        if ($DryRun) { Write-Output "DRY-RUN: would write $path with $($events.Count) events" } else { $out | Out-File $path -Force; Write-Output "Wrote $path" }
    } else {
        Write-Output "No notable events in last $Minutes minutes."
    }
