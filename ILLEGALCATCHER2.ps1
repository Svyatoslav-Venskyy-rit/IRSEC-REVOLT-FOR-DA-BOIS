<#
.SYNOPSIS
    Detect anomalous processes/services on Windows hosts based on expected configurations.
    Prompts to stop/kill anomalies and notifies via console/toast/SMTP.

.DESCRIPTION
    - Dynamically loads allowlist based on hostname ($env:COMPUTERNAME).
    - Detects running processes/services not on the dynamic allowlist.
    - Prompts y/n before killing/stopping each anomaly (configurable).
    - Logs to timestamped file; supports console, BurntToast, and SMTP notifications.
    - Optimized for Windows hosts in the provided inventory table.

USAGE
    # Run as Admin on target Windows host:
    .\Detect-AnomalousWindows.ps1 -Action Prompt -NotifyMethods @("Console","Toast")

    # For auto-removal (use with caution!):
    .\Detect-AnomalousWindows.ps1 -Action AutoRemove -NotifyMethods @("Console","SMTP")

REQUIREMENTS
    - Run as Administrator.
    - For toast: Install-Module -Name BurntToast -Scope CurrentUser
    - For SMTP: Configure params (SmtpServer, etc.).
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Prompt","AutoRemove","ReportOnly")]
    [string]$Action = "Prompt",

    [string[]]$NotifyMethods = @("Console"), # "Console","Toast","SMTP"

    # SMTP configuration (EDIT THESE PLACEHOLDERS)
    [string]$SmtpServer = "smtp.example.com",
    [int]$SmtpPort = 587,
    [string]$SmtpFrom = "alerts@yourdomain.com",
    [string]$SmtpTo = "admin@yourdomain.com",
    [string]$SmtpUser = "your-smtp-user",
    [string]$SmtpPassword = "your-smtp-pass"
)

# -----------------------
# Helper: Ensure elevated
# -----------------------
function Assert-Elevated {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "ERROR: Must run as Administrator!" -ForegroundColor Red
        exit 1
    }
}

# -----------------------
# Logging/Notify helpers
# -----------------------
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir = "$PSScriptRoot\anomaly_logs"
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
# FIX: Use Join-Path directly since New-Item Force ensures directory exists, eliminating the Resolve-Path error
$logFile = Join-Path $logDir "anomalies_$timestamp.log"
$hostname = $env:COMPUTERNAME
$scriptProcessName = "powershell"  # Self-exclude to avoid detecting this script run

function Log {
    param($msg)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$hostname] $msg"
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    if ($NotifyMethods -contains "Console") { Write-Host $line -ForegroundColor Yellow }
}

function Send-Toast {
    param($title, $body)
    if (-not (Get-Module -ListAvailable -Name BurntToast)) {
        Log "BurntToast not installed. Install with: Install-Module BurntToast -Scope CurrentUser"
        return
    }
    try {
        Import-Module BurntToast -ErrorAction SilentlyContinue
        New-BurntToastNotification -Text $title, $body
        Log "Toast sent: $title"
    } catch {
        Log "Toast failed: $_"
    }
}

function Send-SMTP {
    param($subject, $body)
    if (-not $SmtpServer -or -not $SmtpTo) {
        Log "SMTP not configured (SmtpServer/SmtpTo empty)."
        return
    }
    try {
        # Warning: Storing password here is for quick competition use, not production.
        $securePass = ConvertTo-SecureString $SmtpPassword -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($SmtpUser, $securePass)
        Send-MailMessage -SmtpServer $SmtpServer -Port $SmtpPort -From $SmtpFrom -To $SmtpTo -Subject "[$hostname] $subject" -Body $body -Credential $cred -UseSsl -BodyAsHtml
        Log "SMTP sent to $SmtpTo"
    } catch {
        Log "SMTP failed: $_"
    }
}

# -----------------------
# Dynamic Whitelist based on hostname (expanded for stability)
# -----------------------
function Get-Whitelist {
    # --- CRITICAL SYSTEM PROCESSES (Must be whitelisted) ---
    $commonProcesses = @(
        "system", "smss", "csrss", "wininit", "services", "lsass", "lsm", "explorer", "dwm", "spoolsv", 
        "svchost", "taskhostw", "taskhostex", "runtimebroker", "searchindexer", "wmiaprvse", "wmiprvse", 
        "sihost", "conhost", "cmd", "powershell", "powershell_ise", "mmc", "msmpeng", "wuauclt",
        
        # ADDED COMMON PROCESSES (from your run output and standard Windows processes)
        "AggregatorHost", "ctfmon", "dllhost", "fontdrvhost", "Idle", "MicrosoftEdgeUpdate",
        "MpDefenderCoreService", "MoUsoCoreWorker", "musnotifyicon", "notepad", "msiexec", "LogonUI",
        "SecurityHealthService", "SearchProtocolHost", "SearchFilterHost", "audiodg", "dasHost", "OneDrive"
    )

    # --- CRITICAL SYSTEM SERVICES (Whitelisted by Service Name) ---
    $commonServices = @(
        "Appinfo", "AudioEndpointBuilder", "AudioSrv", "BITS", "BrokerInfrastructure", "CryptSvc", "DcomLaunch", 
        "Dhcp", "Dnscache", "EventLog", "EventSystem", "FontCache", "TimeBrokerSvc", "WdiServiceHost", 
        "WdiSystemHost", "WpnService", "BFE", "MpsSvc", "ProfSvc", "RpcEptMapper", "RpcSs", "Schedule", 
        "SecurityHealthService", "SysMain", "TermService", "UserManager", "Themes", "ShellHWDetection",
        "DoSvc", "iphlpsvc", # IP Helper included for Silk Road/general connectivity
        
        # ADDED COMMON SERVICES (from your run output and standard Windows services)
        "WerSvc", "wuauserv", "WSService", "DiagTrack", "PcaSvc", "TokenBroker", "PushToInstall",
        "InstallService", "AppXSvc", "DoSvc", "UsoSvc"
    )

    $hostSpecificServices = @{}
    # --- Host-specific services based on the inventory table ---
    switch ($hostname) {
        "Wright Brothers" { 
            $hostSpecificServices["LanmanServer"] = $true # SMB (Server service)
            $hostSpecificServices["Netlogon"] = $true # Domain Members/Servers
        } 
        "Moon Landing" { 
            $hostSpecificServices["W3SVC"] = $true         # IIS (World Wide Web Publishing)
            $hostSpecificServices["MSFTPSVC"] = $true     # FTP
        }
        "Pyramids" { 
            $hostSpecificServices["NTDS"] = $true     # AD DS (NT Directory Services)
            $hostSpecificServices["DNS"] = $true      # DNS Server
            $hostSpecificServices["DFSR"] = $true      # DFS Replication (DFSRs.exe process)
            $hostSpecificServices["Dfs"] = $true       # DFS Namespace (dfssvc.exe process)
            $hostSpecificServices["ADWS"] = $true      # Active Directory Web Services
            $hostSpecificServices["IsmServ"] = $true   # Intersite Messaging (ismserv.exe process)
            $hostSpecificServices["Netlogon"] = $true   # Domain Controller service
        }
        "First Olympics" { $hostSpecificServices["WinRM"] = $true }        # WinRM
        "Silk Road" { $hostSpecificServices["iphlpsvc"] = $true }         # IP Helper (for ICMP)
        default { 
            # ADDED: Handling for unlisted DC hostname (like 'DC1')
            if ($hostname -like "*DC*") {
                Log "INFO: Hostname '$hostname' suggests a Domain Controller. Adding DC-specific services."
                $hostSpecificServices["NTDS"] = $true
                $hostSpecificServices["DNS"] = $true
                $hostSpecificServices["DFSR"] = $true
                $hostSpecificServices["Dfs"] = $true
                $hostSpecificServices["ADWS"] = $true
                $hostSpecificServices["IsmServ"] = $true
                $hostSpecificServices["Netlogon"] = $true
            } else {
                Log "WARNING: Unknown hostname '$hostname'. Using only common allowlist."
            }
        }
    }

    $allowedProcesses = @{}
    foreach ($proc in $commonProcesses) { 
        $allowedProcesses["$($proc).exe".ToLower()] = $true
        $allowedProcesses[$proc.ToLower()] = $true 
    }
    
    # ADDED: Explicitly whitelist critical server process executables (DFSRs.exe, dns.exe, dfssvc.exe, ismserv.exe, Microsoft.ActiveDirectory.WebServices.exe)
    # Note: These are covered by the services being added, but this adds a redundant safety check for processes
    $serverProcesses = @("DFSRs.exe", "dns.exe", "dfssvc.exe", "ismserv.exe", "Microsoft.ActiveDirectory.WebServices.exe")
    foreach ($proc in $serverProcesses) { $allowedProcesses[$proc.ToLower()] = $true }

    $allowedServices = @{}
    foreach ($svc in $commonServices) { $allowedServices[$svc.ToLower()] = $true }
    foreach ($svc in $hostSpecificServices.Keys) { $allowedServices[$svc.ToLower()] = $true }

    return @{
        Processes = $allowedProcesses
        Services = $allowedServices
    }
}

# -----------------------
# Main Execution Logic
# -----------------------
Assert-Elevated
Log "=== Anomaly Detection Started on $hostname (Action: $Action) ==="

$allow = Get-Whitelist
Log "Loaded $($allow.Processes.Count) allowed process names, $($allow.Services.Count) allowed services."

# Get running items, suppressing non-critical errors (e.g., access denied to certain processes)
$procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -and $_.ProcessName -ne $scriptProcessName } | Select-Object Id, ProcessName, Path
$svcs = Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object Name, DisplayName, Status

# Find anomalous processes: Check if ProcessName (with or without .exe) is NOT in the whitelist
$anomalousProcs = $procs | Where-Object { 
    $name = $_.ProcessName.ToLower()
    $nameExe = "$($name).exe"
    -not $allow.Processes.ContainsKey($name) -and -not $allow.Processes.ContainsKey($nameExe)
}

# Find anomalous services: Check if ServiceName is NOT in the whitelist
$anomalousServices = $svcs | Where-Object { 
    $sName = $_.Name.ToLower()
    -not $allow.Services.ContainsKey($sName)
}

# Report summary
$totalAnoms = $anomalousProcs.Count + $anomalousServices.Count
if ($totalAnoms -eq 0) {
    $msg = "No anomalies on $hostname."
    Log $msg
    if ($NotifyMethods -contains "Toast") { Send-Toast -title "Clean Host" -body $msg }
    if ($NotifyMethods -contains "SMTP") { Send-SMTP -subject "No Anomalies" -body $msg }
    exit 0
}

$summary = "Anomalous: $($anomalousProcs.Count) processes, $($anomalousServices.Count) services on $hostname."
Log $summary
if ($NotifyMethods -contains "Toast") { Send-Toast -title "Anomalies Detected!" -body $summary }
if ($NotifyMethods -contains "SMTP") { Send-SMTP -subject "Anomalies Alert" -body "$summary<br>See log: $logFile" }

# -----------------------
# Handle anomalous process (Kill)
# -----------------------
function Handle-Process {
    param($proc)
    $info = "PROC: $($proc.ProcessName) (PID: $($proc.Id)) Path: $($proc.Path)"
    Log "ANOMALY $info"

    if ($NotifyMethods -contains "Toast") { Send-Toast -title "Anomalous Process [$hostname]" -body "$($proc.ProcessName) (PID $($proc.Id))" }
    if ($NotifyMethods -contains "SMTP") { Send-SMTP -subject "Anomalous Process" -body "$info<br>Host: $hostname" }

    switch ($Action) {
        "ReportOnly" { Log "[ReportOnly] Skipped action on $($proc.ProcessName)"; break }
        "AutoRemove" {
            try { Stop-Process -Id $proc.Id -Force -ErrorAction Stop; Log "[Auto] Killed $($proc.ProcessName) (PID $($proc.Id))" } 
            catch { Log "[Auto] Failed to kill $($proc.ProcessName): $_" }
            break
        }
        "Prompt" {
            $response = Read-Host "Kill '$($proc.ProcessName)' (PID $($proc.Id))? [y/N]"
            if ($response -match '^[Yy]') {
                try { Stop-Process -Id $proc.Id -Force -ErrorAction Stop; Log "[User] Killed $($proc.ProcessName) (PID $($proc.Id))" } 
                catch { Log "[User] Failed to kill $($proc.ProcessName): $_" }
            } else { Log "[User] Skipped $($proc.ProcessName)" }
        }
    }
}

# -----------------------
# Handle anomalous service (Stop)
# -----------------------
function Handle-Service {
    param($svc)
    $info = "SERVICE: $($svc.Name) '$($svc.DisplayName)' (Status: $($svc.Status))"
    Log "ANOMALY $info"

    if ($NotifyMethods -contains "Toast") { Send-Toast -title "Anomalous Service [$hostname]" -body "$($svc.DisplayName) ($($svc.Name))" }
    if ($NotifyMethods -contains "SMTP") { Send-SMTP -subject "Anomalous Service" -body "$info<br>Host: $hostname" }

    switch ($Action) {
        "ReportOnly" { Log "[ReportOnly] Skipped action on $($svc.Name)"; break }
        "AutoRemove" {
            try { Stop-Service -Name $svc.Name -Force -ErrorAction Stop; Log "[Auto] Stopped $($svc.Name)" } 
            catch { Log "[Auto] Failed to stop $($svc.Name): $_" }
            break
        }
        "Prompt" {
            $response = Read-Host "Stop '$($svc.DisplayName)' ($($svc.Name))? [y/N]"
            if ($response -match '^[Yy]') {
                try { Stop-Service -Name $svc.Name -Force -ErrorAction Stop; Log "[User] Stopped $($svc.Name)" } 
                catch { Log "[User] Failed to stop $($svc.Name): $_" }
            } else { Log "[User] Skipped $($svc.Name)" }
        }
    }
}

# -----------------------
# Execute actions
# -----------------------
Log "Handling $($anomalousProcs.Count) anomalous processes..."
$anomalousProcs | ForEach-Object { Handle-Process -proc $_ }

Log "Handling $($anomalousServices.Count) anomalous services..."
$anomalousServices | ForEach-Object { Handle-Service -svc $_ }

$completeMsg = "Scan complete on $hostname. Total anomalies: $totalAnoms. Log: $logFile"
Log $completeMsg
if ($NotifyMethods -contains "Toast") { Send-Toast -title "Scan Complete" -body $completeMsg }
if ($NotifyMethods -contains "SMTP") { Send-SMTP -subject "Scan Complete" -body "$completeMsg<br>Details in log." }

Write-Host "Done! Check $logFile" -ForegroundColor Green
