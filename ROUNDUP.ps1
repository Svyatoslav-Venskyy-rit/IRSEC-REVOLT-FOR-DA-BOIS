<#
.SYNOPSIS
  Compares current local & domain accounts to an allowed list, prompts to delete any extras, and logs everything to CSV.
  Followed by system snapshot collection for IR/forensics: ARP table, services, processes, System32 hashes, RDP sessions, scheduled tasks, and listening TCP connections.

.USAGE
  ./combined_irsec_cleanup_and_snapshot.ps1
  ./combined_irsec_cleanup_and_snapshot.ps1 -IncludeDisabled

.NOTES
  - **ELEVATION IS REQUIRED:** Run as Elevated Administrator for local deletions and some snapshots.
  - **DOMAIN RIGHTS ARE REQUIRED:** For domain checks/deletions, run under a **domain admin account** on a machine with the **ActiveDirectory module** (RSAT) installed.
  - Default behavior only considers ENABLED accounts. Use -IncludeDisabled to include disabled accounts in checks.
  - Logs are written to CSV for IRSEC incident response reporting, including timestamps, actions, and operator username.
  - **FIXED LOGIC:** Implemented universal allowed list checking and cross-list cleanup to prevent duplicate deletion prompts.
  - After cleanup, collects system snapshots into timestamped files/directories for comparison (e.g., via WinMerge).
#>

param(
    [switch]$IncludeDisabled
)

# --- CONFIG: Allowed accounts (parsed from your list) ---
# Domain (Users & Administrators): fathertime, chronos, aion, kairos
# All locals combined (Administrators & Users): merlin, terminator, mrpeabody, jamescole, docbrown, professorparadox, drwho, martymcFly, arthurdent, sambeckett, loki, riphunter, theflash, tonystark, drstrange, barta, len
$allowed = @{
    "Domain" = @(
        "fathertime", "chronos", "aion", "kairos"
    )
    "Local" = @(
        "merlin", "terminator", "mrpeabody", "jamescole", "docbrown", "professorparadox",
        "drwho", "martymcFly", "arthurdent", "sambeckett",
        "loki", "riphunter", "theflash", "tonystark", "drstrange", "barta", "len"
    )
}

# Define built-in local accounts to explicitly avoid deleting (Expanded list for DCs/workstations)
$builtInLocalAccounts = @("administrator", "guest", "defaultaccount", "wdagutilityaccount", "krbtgt")

# Normalize allowed lists to lowercase for case-insensitive comparison
$allowedDomain = $allowed["Domain"] | ForEach-Object { $_.ToLower() }
$allowedLocal  = $allowed["Local"] | ForEach-Object { $_.ToLower() }
# **CRITICAL FIX:** Combine all allowed names into one list for robust checking
$allAllowed = $allowedDomain + $allowedLocal

# --- Log file setup ---
$ts = (Get-Date).ToString("yyyyMMdd-HHmmss")
$logPath = Join-Path -Path (Get-Location) -ChildPath "irsec_account_audit_$ts.csv"

# Use a robust way to get the full operator name for the IR report
$currentUser = "$([Environment]::UserDomainName)\$([Environment]::UserName)"

$log = @()
function Add-Log {
    param($AccountName, $Scope, $IsEnabled, $Action, $Note)
    $log += [PSCustomObject]@{
        Timestamp   = (Get-Date).ToString("o")
        Account     = $AccountName
        Scope       = $Scope        # "Domain" or "Local"
        Enabled     = $IsEnabled
        Action      = $Action        # "Found", "PromptedDelete", "Deleted", "Skipped", "Error", "Reported"
        Note        = $Note
        PerformedBy = $currentUser
    }
}

# --- Helpers ---
function Test-Elevation {
    $current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Try-GetADModule {
    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory) { return $true }
        else { return $false }
    } catch {
        return $false
    }
}

# --- Collect domain accounts ---
Write-Host "--- Checking Domain Accounts (requires AD rights) ---" -ForegroundColor Yellow
$haveADModule = Try-GetADModule
$domainUsers = @()

if ($haveADModule) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        # Filter out built-in/service accounts starting with $
        $filter = if ($IncludeDisabled) { "SamAccountName -notlike '*$'" } else { "Enabled -eq `$true -and SamAccountName -notlike '*$'" }
        $adUsers = Get-ADUser -Filter $filter -Properties Enabled, SamAccountName | Select-Object SamAccountName, Enabled

        foreach ($u in $adUsers) {
            $domainUsers += [PSCustomObject]@{ Name = $u.SamAccountName; Enabled = $u.Enabled }
        }
    } catch {
        Write-Warning "Failed to query AD with ActiveDirectory module: $($_.Exception.Message). Domain queries will be skipped."
        Add-Log -AccountName "DOMAIN_ENUM_ERROR" -Scope "Domain" -IsEnabled $false -Action "Error" -Note $_.ToString()
    }
} else {
    # Fallback to ADSI (limited; may be slow)
    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $context = $rootDSE.defaultNamingContext
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = "LDAP://$context"
        $searcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null
        $searcher.PropertiesToLoad.Add("userAccountControl") | Out-Null

        if ($IncludeDisabled) {
            $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(!(sAMAccountName=*$)))"
        } else {
            $searcher.Filter = "(&(&(objectCategory=person)(objectClass=user))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=*$)))"
        }
        $searcher.PageSize = 1000
        $results = $searcher.FindAll()

        foreach ($r in $results) {
            $name = $r.Properties["samaccountname"][0]
            if ($name) {
                $uac = $r.Properties["useraccountcontrol"][0]
                $enabled = ($uac -band 2) -eq 0
                $domainUsers += [PSCustomObject]@{ Name = $name; Enabled = $enabled }
            }
        }
    } catch {
        Write-Warning "ADSI domain query failed: $($_.Exception.Message). Domain enumeration skipped."
        Add-Log -AccountName "DOMAIN_ENUM_ERROR" -Scope "Domain" -IsEnabled $false -Action "Error" -Note $_.ToString()
    }
}

# --- Collect local accounts ---
Write-Host "--- Checking Local Accounts (requires Elevation) ---" -ForegroundColor Yellow
$localUsers = @()
try {
    if (Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue) {
        $locals = Get-LocalUser
        foreach ($l in $locals) {
            if ($IncludeDisabled -or $l.Enabled) {
                 $localUsers += [PSCustomObject]@{ Name = $l.Name; Enabled = $l.Enabled }
            }
        }
    } else {
        # Fallback using WMI/Win32_UserAccount (local only)
        $wmi = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount = TRUE" -ErrorAction Stop
        foreach ($w in $wmi) {
            $enabled = -not $w.Disabled
            if ($IncludeDisabled -or $enabled) {
                $localUsers += [PSCustomObject]@{ Name = $w.Name; Enabled = $enabled }
            }
        }
    }
} catch {
    Write-Error "Failed to enumerate local users: $($_.Exception.Message)"
    Add-Log -AccountName "LOCAL_ENUM_ERROR" -Scope "Local" -IsEnabled $false -Action "Error" -Note $_.ToString()
}

# --- Evaluate allowed vs discovered (THE FIXED LOGIC) ---
Write-Host "--- Evaluating discovered accounts against ALL allowed accounts ---" -ForegroundColor Yellow

# Domain extras
$domainExtras = @()
foreach ($u in $domainUsers) {
    $uname = $u.Name.ToLower()
    Add-Log -AccountName $u.Name -Scope "Domain" -IsEnabled $u.Enabled -Action "Found" -Note "Domain account discovered"
    
    # Check against the universal $allAllowed list
    if (-not ($allAllowed -contains $uname)) {
        $domainExtras += $u
    }
}

# Local extras
$localExtras = @()
foreach ($u in $localUsers) {
    $uname = $u.Name.ToLower()
    Add-Log -AccountName $u.Name -Scope "Local" -IsEnabled $u.Enabled -Action "Found" -Note "Local account discovered"
    
    # Check against the universal $allAllowed list AND built-in accounts
    if (-not ($allAllowed -contains $uname) -and -not ($builtInLocalAccounts -contains $uname)) {
        $localExtras += $u
    }
}

# --- Show summary to operator ---
Write-Host "`n==== IRSEC ACCOUNT AUDIT REPORT ====" -ForegroundColor Cyan
Write-Host "Timestamp: $ts" -ForegroundColor Cyan
Write-Host "Performed by: $currentUser" -ForegroundColor Cyan
Write-Host ""
Write-Host "Domain accounts found: $($domainUsers.Count)" -ForegroundColor White
Write-Host "Local accounts found: $($localUsers.Count)" -ForegroundColor White
Write-Host ""
Write-Host "🚨 Extra DOMAIN accounts (not in allowed list): $($domainExtras.Count)" -ForegroundColor Red
if ($domainExtras.Count -gt 0) {
    $domainExtras | ForEach-Object { Write-Host "  - $($_.Name) (Enabled: $($_.Enabled))" -ForegroundColor Red }
}
Write-Host ""
Write-Host "🚨 Extra LOCAL accounts (not in allowed list): $($localExtras.Count)" -ForegroundColor Red
if ($localExtras.Count -gt 0) {
    $localExtras | ForEach-Object { Write-Host "  - $($_.Name) (Enabled: $($_.Enabled))" -ForegroundColor Red }
}
Write-Host ""
Write-Host "A CSV log will be written to: $logPath" -ForegroundColor Cyan
Write-Host ""

# Warn about elevation and domain rights
if (-not (Test-Elevation)) {
    Write-Warning "This script is NOT running elevated. Local deletions WILL FAIL."
    Add-Log -AccountName "ELEVATION" -Scope "Script" -IsEnabled $false -Action "Warning" -Note "Not running elevated - local deletions will be skipped"
}

if (($domainExtras.Count -gt 0) -and -not $haveADModule) {
    Write-Warning "ActiveDirectory module (RSAT) not detected. Domain deletions WILL BE SKIPPED."
    Add-Log -AccountName "ADMODULE_MISSING" -Scope "Script" -IsEnabled $false -Action "Warning" -Note "ActiveDirectory module not available - domain deletions skipped"
}

# --- Interactive deletion for local extras ---
if ($localExtras.Count -gt 0) {
    Write-Host "--- Proceeding to LOCAL deletion prompts ---" -ForegroundColor Yellow
    foreach ($acc in $localExtras) {
        $prompt = "Delete LOCAL account '$($acc.Name)' (Enabled: $($acc.Enabled))? (y/N): "
        $resp = Read-Host $prompt
        if ($resp.Trim().ToLower() -in @("y", "yes")) {
            if (Test-Elevation) {
                try {
                    # Try Remove-LocalUser (preferred)
                    if (Get-Command -Name Remove-LocalUser -ErrorAction SilentlyContinue) {
                        Remove-LocalUser -Name $acc.Name -ErrorAction Stop
                        Write-Host "  ✅ Deleted local user $($acc.Name)." -ForegroundColor Green
                        Add-Log -AccountName $acc.Name -Scope "Local" -IsEnabled $acc.Enabled -Action "Deleted" -Note "Deleted by operator confirmation (Remove-LocalUser)"
                    } else {
                        # Fallback to net user
                        $result = & net user $acc.Name /delete 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            Write-Host "  ✅ Deleted local user $($acc.Name) via net user." -ForegroundColor Green
                            Add-Log -AccountName $acc.Name -Scope "Local" -IsEnabled $acc.Enabled -Action "Deleted" -Note "Deleted via net user by operator confirmation"
                        } else {
                            throw "net user failed: $result (exit code $LASTEXITCODE)"
                        }
                    }
                    
                    # **FIXED STEP 1:** Clean the Domain Extras list if this account was also listed there
                    $domainExtras = $domainExtras | Where-Object { $_.Name.ToLower() -ne $acc.Name.ToLower() }

                } catch {
                    Write-Warning "  ❌ Failed to delete local user $($acc.Name): $($_.Exception.Message)"
                    Add-Log -AccountName $acc.Name -Scope "Local" -IsEnabled $acc.Enabled -Action "Error" -Note $_.ToString()
                }
            } else {
                Write-Warning "  ❌ Skipping deletion of $($acc.Name) - not elevated."
                Add-Log -AccountName $acc.Name -Scope "Local" -IsEnabled $acc.Enabled -Action "Skipped" -Note "Not elevated"
            }
        } else {
            Write-Host "  🟡 Kept local user $($acc.Name) (operator declined)." -ForegroundColor Yellow
            Add-Log -AccountName $acc.Name -Scope "Local" -IsEnabled $acc.Enabled -Action "Skipped" -Note "Operator chose not to delete"
        }
    }
} else {
    Write-Host "No extra local accounts found." -ForegroundColor Green
}

# --- Interactive deletion for domain extras (only if AD module present) ---
if ($domainExtras.Count -gt 0) {
    if ($haveADModule) {
        Write-Host "--- Proceeding to DOMAIN deletion prompts ---" -ForegroundColor Yellow
        foreach ($acc in $domainExtras) {
            $prompt = "Delete DOMAIN account '$($acc.Name)' (Enabled: $($acc.Enabled))? (y/N): "
            $resp = Read-Host $prompt
            if ($resp.Trim().ToLower() -in @("y", "yes")) {
                try {
                    Remove-ADUser -Identity $acc.Name -Confirm:$false -ErrorAction Stop
                    Write-Host "  ✅ Deleted domain user $($acc.Name)." -ForegroundColor Green
                    Add-Log -AccountName $acc.Name -Scope "Domain" -IsEnabled $acc.Enabled -Action "Deleted" -Note "Deleted by operator confirmation"

                    # **FIXED STEP 2:** Clean the Local Extras list if this account was also listed there
                    $localExtras = $localExtras | Where-Object { $_.Name.ToLower() -ne $acc.Name.ToLower() }

                } catch {
                    Write-Warning "  ❌ Failed to delete domain user $($acc.Name): $($_.Exception.Message). Check your domain admin rights."
                    Add-Log -AccountName $acc.Name -Scope "Domain" -IsEnabled $acc.Enabled -Action "Error" -Note $_.ToString()
                }
            } else {
                Write-Host "  🟡 Kept domain user $($acc.Name) (operator declined)." -ForegroundColor Yellow
                Add-Log -AccountName $acc.Name -Scope "Domain" -IsEnabled $acc.Enabled -Action "Skipped" -Note "Operator chose not to delete"
            }
        }
    } else {
        Write-Warning "Skipping domain deletions - ActiveDirectory module unavailable. Extras reported only."
        foreach ($acc in $domainExtras) {
            Add-Log -AccountName $acc.Name -Scope "Domain" -IsEnabled $acc.Enabled -Action "Reported" -Note "AD module missing; deletion skipped"
        }
    }
} else {
    Write-Host "No extra domain accounts found (or domain enumeration skipped)." -ForegroundColor Green
}

# --- Finalize log ---
try {
    # Using UTF8 for broader compatibility
    $log | Export-Csv -Path $logPath -NoTypeInformation -Force -Encoding UTF8
    Write-Host "`n✅ Audit log written to: $logPath" -ForegroundColor Cyan
    Write-Host "Use this CSV for your IRSEC incident response report." -ForegroundColor Cyan
} catch {
    Write-Warning "`n❌ Failed to write CSV log: $($_.Exception.Message). Logging results to console now."
    $log | Format-Table -AutoSize
}

Write-Host "`nScript complete. Run your password change script next." -ForegroundColor Green

# --- System Snapshot Section ---
Write-Host "`n--- Starting System Snapshots for IR/Forensics ---" -ForegroundColor Yellow
$ts = (Get-Date).ToString("yyyyMMdd-HHmmss")  # Reuse timestamp for consistency

# ARP table
Write-Host "Capturing ARP table..." -ForegroundColor White
arp -a > "arp_table_$ts.txt"

# Services (generate two versions for comparison, e.g., via WinMerge)
Write-Host "Capturing services (version 1)..." -ForegroundColor White
Get-Service | Select Name,DisplayName,Status,@{n='StartType';e={(Get-CimInstance Win32_Service -Filter "Name='$_'").StartMode}} | Export-Csv "services_$ts.csv" -NoTypeInformation
Write-Host "Capturing services (version 2)..." -ForegroundColor White
Get-Service | Select Name,DisplayName,Status,@{n='StartType';e={(Get-CimInstance Win32_Service -Filter "Name='$_'").StartMode}} | Export-Csv "services1_$ts.csv" -NoTypeInformation
#make 2 of them make sure to edit the name of it and add a 1 or something
#compare with winmerge

# Processes (timestamped directory)
Write-Host "Capturing processes..." -ForegroundColor White
$t=Get-Date -Format 'yyyyMMdd_HHmmss'; New-Item -Path . -Name $t -ItemType Directory; Get-Process | Export-Csv ".\$t\processes.csv" -NoTypeInformation

# System32 hashes
Write-Host "Computing System32 file hashes (this may take a while)..." -ForegroundColor White
Get-ChildItem C:\Windows\System32 -Recurse -File | Get-FileHash -Algorithm SHA256 | Export-Csv "sys32_hashes_$ts.csv" -NoTypeInformation

# RDP sessions
Write-Host "Capturing RDP sessions..." -ForegroundColor White
quser | Out-File "rdp_sessions_$ts.txt"

# Scheduled tasks (generate two versions for comparison)
Write-Host "Capturing scheduled tasks (version 1)..." -ForegroundColor White
schtasks /query /fo LIST /v > "scheduled_tasks_snapshot_$ts.txt"
Write-Host "Capturing scheduled tasks (version 2)..." -ForegroundColor White
schtasks /query /fo LIST /v > "scheduled_tasks_snapshot1_$ts.txt"
#when you have 2 files then compare them using file compare
#DOWNLOAD WINMERGE

# Listening TCP connections
Write-Host "Capturing listening TCP connections..." -ForegroundColor White
Get-NetTCPConnection -State Listen | Select LocalAddress,LocalPort,@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Export-Csv "listening_tcp_$ts.csv" -NoTypeInformation

Write-Host "`n--- System Snapshots Complete. All files timestamped with $ts for easy comparison. ---" -ForegroundColor Green
Write-Host "Account cleanup log: $logPath" -ForegroundColor Cyan
