\
    Param(
      [string]$Source = ".\\evidence_to_package",
      [string]$Out = ".\\evidence_$(Get-Date -Format yyyyMMdd_HHmmss).zip"
    )
    if (-not (Test-Path $Source)) { Write-Error "Source folder not found: $Source"; exit 1 }
    Compress-Archive -Path (Join-Path $Source "*") -DestinationPath $Out -Force
    # Mark readonly
    try { (Get-Item $Out).IsReadOnly = $true } catch {}
    Write-Output "Packaged evidence to $Out"
