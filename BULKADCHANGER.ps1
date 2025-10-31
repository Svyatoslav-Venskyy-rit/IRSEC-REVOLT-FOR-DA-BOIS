<#
.SYNOPSIS
  Bulk reset AD account passwords from a CSV (one password per row) for enabled user accounts.

.NOTES
  - Assumes the CSV contains one password per line (no header by default).
  - Produces a mapping CSV containing SamAccountName, DistinguishedName, Password, Timestamp, Result, ErrorMessage.
  - Use -DryRun to simulate without changing anything.
  - Use -RecyclePasswords to reuse passwords cyclically if you have fewer passwords than accounts.
  - Run as an account with permission to reset AD passwords (e.g., Domain Admin) and on a machine with ActiveDirectory module.

.EXAMPLE
  .\Bulk-Reset-ADPasswords.ps1 -PasswordCsvPath "C:\IRSEC\pwlist.csv" -OutputMappingPath "C:\IRSEC\mapping.csv"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$PasswordCsvPath,

    [Parameter(Mandatory=$true)]
    [string]$OutputMappingPath,

    [string]$SearchBase = "",                    # optional: "OU=Students,DC=domain,DC=com"
    [switch]$HasHeader = $false,                 # set to $true if the CSV has a header row that should be skipped
    [switch]$RecyclePasswords = $false,          # if set, will reuse passwords cyclically if fewer passwords than users
    [switch]$DryRun = $false                     # if set, will only show planned actions without making changes
)

# --- Pre-checks ---
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "ActiveDirectory module not found. Install RSAT/ActiveDirectory module or run on a DC."
    return
}

if (-not (Test-Path -Path $PasswordCsvPath)) {
    Write-Error "Password CSV not found: $PasswordCsvPath"
    return
}

# Read passwords (one per line). Skip blank lines.
$passwordLines = Get-Content -Path $PasswordCsvPath | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

if ($passwordLines.Count -eq 0) {
    Write-Error "No passwords found in CSV."
    return
}

# Improved header skip logic
if ($HasHeader -and $passwordLines.Count -gt 0) {
    # Skips the first line (index 0) if HasHeader is true
    $passwordLines = $passwordLines[1..($passwordLines.Count - 1)]
}

if ($passwordLines.Count -eq 0) {
    Write-Error "No passwords present after header removal."
    return
}

# --- Get enabled users ---
# CRITICAL: Ensure SamAccountName and DistinguishedName are retrieved for use in the loop
$propertiesToRetrieve = "DistinguishedName", "SamAccountName"

if ([string]::IsNullOrWhiteSpace($SearchBase)) {
    $users = Get-ADUser -Filter { Enabled -eq $true } -Properties $propertiesToRetrieve | Sort-Object SamAccountName
} else {
    $users = Get-ADUser -Filter { Enabled -eq $true } -SearchBase $SearchBase -Properties $propertiesToRetrieve | Sort-Object SamAccountName
}

if ($users.Count -eq 0) {
    Write-Warning "No enabled users found (searchbase='$SearchBase'). Exiting."
    return
}

Write-Host "Found $($users.Count) enabled user(s). Password list contains $($passwordLines.Count) password(s)."

if (-not $RecyclePasswords -and $passwordLines.Count -lt $users.Count) {
    Write-Warning "There are fewer passwords than enabled users and -RecyclePasswords was NOT specified. Either add more passwords or use -RecyclePasswords."
    return
}

# Confirmation prompt (safety measure)
if (-not $DryRun) {
    $confirm = Read-Host "You are about to reset passwords for $($users.Count) accounts. This will modify AD. Proceed? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "Aborted by user."
        return
    }
}

# --- Perform resets / Dry-run ---
$results = @()
for ($i = 0; $i -lt $users.Count; $i++) {
    $u = $users[$i]
    if ($RecyclePasswords) {
        $pw = $passwordLines[$i % $passwordLines.Count]
    } else {
        if ($i -ge $passwordLines.Count) {
            Write-Error "Ran out of passwords at index $i and -RecyclePasswords is not set. Aborting further changes."
            break
        }
        $pw = $passwordLines[$i]
    }

    $entry = [PSCustomObject]@{
        SamAccountName  = $u.SamAccountName
        DistinguishedName = $u.DistinguishedName
        Password        = $pw
        Timestamp       = (Get-Date).ToString("s")
        Result          = ""
        ErrorMessage    = ""
    }

    if ($DryRun) {
        $entry.Result = "DryRun: Would set password"
        Write-Host "DRYRUN -> $($u.SamAccountName) => [password length $($pw.Length)]"
        $results += $entry
        continue
    }

    try {
        # Convert to securestring
        $securePw = ConvertTo-SecureString -String $pw -AsPlainText -Force

        # Reset password
        Set-ADAccountPassword -Identity $u.SamAccountName -Reset -NewPassword $securePw -ErrorAction Stop

        # Force change at next logon (essential security measure)
        Set-ADUser -Identity $u.SamAccountName -ChangePasswordAtLogon $true -ErrorAction Stop

        # Ensure PasswordNeverExpires is False (Good practice)
        Set-ADUser -Identity $u.SamAccountName -PasswordNeverExpires $false -ErrorAction Stop

        $entry.Result = "Success"
        Write-Host "OK -> $($u.SamAccountName)"
    } catch {
        $entry.Result = "Failed"
        $entry.ErrorMessage = $_.Exception.Message
        Write-Warning "Failed -> $($u.SamAccountName): $($_.Exception.Message)"
    }
    $results += $entry
}

# --- Export mapping & secure it ---
# Export plaintext mapping (this is highly sensitive).
try {
    $results | Select-Object SamAccountName, DistinguishedName, Password, Timestamp, Result, ErrorMessage | Export-Csv -Path $OutputMappingPath -NoTypeInformation -Force
    Write-Host "Mapping exported to: $OutputMappingPath"
} catch {
    Write-Error "Failed to export mapping: $($_.Exception.Message)"
    return
}

# Attempt to set file ACL so only current user + Administrators have access.
try {
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $ruleAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","Allow")
    $ruleMe = New-Object System.Security.AccessControl.FileSystemAccessRule($me,"FullControl","Allow")
    $acl.SetAccessRuleProtection($true, $false)   # disable inheritance and remove existing rules
    $acl.AddAccessRule($ruleAdmin)
    $acl.AddAccessRule($ruleMe)
    [System.IO.File]::SetAccessControl($OutputMappingPath, $acl)
    Write-Host "Restricted file ACL to Administrators and $me (inheritance removed)."
} catch {
    Write-Warning "Could not set ACL on mapping file automatically. Please secure $OutputMappingPath manually. Error: $($_.Exception.Message)"
}

# --- Summary ---
$successCount = ($results | Where-Object { $_.Result -eq "Success" }).Count
$failCount = ($results | Where-Object { $_.Result -eq "Failed" }).Count
Write-Host "Done. Successes: $successCount. Failures: $failCount. Mapping written to $OutputMappingPath."

if ($failCount -gt 0) {
    Write-Warning "Check $OutputMappingPath for failures and error messages."
}
