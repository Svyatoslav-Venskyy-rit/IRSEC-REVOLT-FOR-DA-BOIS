\
    Param()
    function Load-Config {
        param([string]$Path = ".\config.json")
        if (Test-Path $Path) { return Get-Content $Path | ConvertFrom-Json }
        else { Write-Error "Config not found: $Path"; exit 1 }
    }

    function Log-Line {
        param([string]$Line,[string]$File=".\\logs\\tool.log")
        $t = Get-Date -Format o
        $LineOut = "$t `t $Line"
        Add-Content -Path $File -Value $LineOut -Force
    }

    function Safe-Run {
        param([scriptblock]$Action,[switch]$DryRun)
        if ($DryRun) {
            Log-Line "DRY-RUN: $Action"
            Write-Output "DRY-RUN: $Action"
        } else {
            & $Action
        }
    }

    function Get-FileHashRecursive {
        param([string]$Path,[string]$Algorithm="SHA256")
        Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            try { $h = Get-FileHash -Path $_.FullName -Algorithm $Algorithm -ErrorAction Stop; [PSCustomObject]@{Path=$_.FullName;Hash=$h.Hash} } catch {}
        }
    }
