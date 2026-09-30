# harden.ps1
# Run as Administrator on Alderaan (10.110.20.15).
# Requires SqlServer PowerShell module OR sqlcmd on PATH - checks below.
#
# This script does NOT need editing. Fill in config.ps1 instead.

. "$PSScriptRoot\config.ps1"

$ErrorActionPreference = "Stop"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

function Write-Section($msg) {
    Write-Host "`n=== $msg ===" -ForegroundColor Cyan
}

# --- 0. Sanity checks ---
Write-Section "Checking prerequisites"

if (-not (Get-Command sqlcmd -ErrorAction SilentlyContinue)) {
    Write-Warning "sqlcmd not found on PATH. Install SQL Server command line tools, or run these steps manually via SSMS."
    return
}

if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

# --- 1. Back up current state before touching anything (rule 15) ---
Write-Section "Backing up current config"

$BackupFile = Join-Path $BackupDir "sp_configure_backup_$Timestamp.txt"
sqlcmd -S localhost -E -Q "EXEC sp_configure;" -o $BackupFile
Write-Host "Saved sp_configure output to $BackupFile"

$LoginsBackupFile = Join-Path $BackupDir "logins_backup_$Timestamp.txt"
sqlcmd -S localhost -E -Q "SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type IN ('S','U','G');" -o $LoginsBackupFile
Write-Host "Saved current logins list to $LoginsBackupFile"

$SysadminBackupFile = Join-Path $BackupDir "sysadmin_role_backup_$Timestamp.txt"
sqlcmd -S localhost -E -Q "SELECT name FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1;" -o $SysadminBackupFile
Write-Host "Saved current sysadmin role members to $SysadminBackupFile"

# --- 2. Audit sysadmin role membership against known-good list ---
Write-Section "Auditing sysadmin role membership"

$CurrentSysadmins = sqlcmd -S localhost -E -h -1 -Q "SET NOCOUNT ON; SELECT name FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1;" |
    ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

foreach ($login in $CurrentSysadmins) {
    if ($KnownSysadminLogins -notcontains $login) {
        Write-Warning "UNEXPECTED sysadmin login found: $login  -- investigate before removing anything"
    } else {
        Write-Host "OK: $login is expected sysadmin"
    }
}

# --- 3. Harden sa account ---
Write-Section "Hardening sa account"

$saPw1 = Read-Host "New sa password (input hidden)" -AsSecureString
$saPw2 = Read-Host "Confirm sa password" -AsSecureString
$saPlain1 = [System.Net.NetworkCredential]::new("", $saPw1).Password
$saPlain2 = [System.Net.NetworkCredential]::new("", $saPw2).Password

if ($saPlain1 -ne $saPlain2) {
    Write-Warning "Passwords did not match - SKIPPING sa password reset. Re-run this step."
} elseif ([string]::IsNullOrWhiteSpace($saPlain1)) {
    Write-Warning "Empty password entered - SKIPPING sa password reset."
} else {
    sqlcmd -S localhost -E -Q "ALTER LOGIN sa WITH PASSWORD = '$saPlain1';"
    sqlcmd -S localhost -E -Q "ALTER LOGIN sa ENABLE;"  # don't disable it, rule 13 - just secure it
    Write-Host "sa password reset. sa left enabled per rule 13 (cannot delete/disable required users)."
}
# Plaintext only existed in memory for this block - not written to disk or logged.
# PowerShell strings are immutable so this isn't a hard security guarantee, just
# best-effort: clear the variables now rather than leave them referenced longer than needed.
$saPlain1 = $null; $saPlain2 = $null; $saPw1 = $null; $saPw2 = $null

# --- 4. Disable xp_cmdshell (common red-team pivot) ---
if ($DisableXpCmdshell) {
    Write-Section "Disabling xp_cmdshell"
    sqlcmd -S localhost -E -Q "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;"
    Write-Host "xp_cmdshell disabled."
} else {
    Write-Section "Skipping xp_cmdshell change (DisableXpCmdshell = false in config.ps1)"
}

# --- 4b. Make sure the firewall is actually ON before bothering to add rules ---
# Rules do nothing if the service is stopped or the profile is disabled -
# this was never checked anywhere before, so a rule could sit there doing
# nothing while everyone assumes it's enforcing something.
Write-Section "Checking Windows Firewall is actually active"

$fwService = Get-Service -Name "MpsSvc" -ErrorAction SilentlyContinue
if (-not $fwService) {
    Write-Warning "MpsSvc (Windows Firewall service) not found - something is very wrong, rules below won't do anything."
} elseif ($fwService.Status -ne "Running") {
    try {
        Start-Service -Name "MpsSvc" -ErrorAction Stop
        Write-Host "MpsSvc was stopped - started it."
    } catch {
        Write-Warning "MpsSvc is stopped and could not be started: $($_.Exception.Message) - rules below won't do anything until this is fixed."
    }
} else {
    Write-Host "MpsSvc running."
}

$disabledProfiles = Get-NetFirewallProfile | Where-Object { -not $_.Enabled }
if ($disabledProfiles) {
    Write-Warning "Disabled firewall profile(s) found: $($disabledProfiles.Name -join ', ') - enabling them."
    Set-NetFirewallProfile -Profile $disabledProfiles.Name -Enabled True
} else {
    Write-Host "All firewall profiles enabled."
}

# --- 5. Restrict MSSQL port to specific known-good source IPs ---
Write-Section "Applying host-specific firewall rules (no subnet/range rules per rule 12)"

$RuleNamePrefix = "CompBlue-MSSQL-Allow-"

# Remove any old rules from previous runs first so re-running this script is idempotent
Get-NetFirewallRule -DisplayName "$RuleNamePrefix*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

# Remove the team's shared Ansible playbook's rule for this box, if it's already run here.
# That rule has no remoteip restriction (open to "any") - leaving it in place makes our
# restricted rules below pointless, since Windows Firewall allows traffic if ANY rule
# matches. This only holds until the playbook runs again - if it gets re-applied to this
# box later, its unrestricted rule comes back and this needs to be re-run after it.
$SharedPlaybookRuleName = "BlueTeam - Database - MSSQL"
$sharedRule = Get-NetFirewallRule -DisplayName $SharedPlaybookRuleName -ErrorAction SilentlyContinue
if ($sharedRule) {
    $sharedRule | Remove-NetFirewallRule
    Write-Host "Removed unrestricted rule '$SharedPlaybookRuleName' from the shared playbook."
    Write-Warning "If the shared playbook runs on this box again later, that rule comes back open. Re-run this step after it does."
} else {
    Write-Host "Shared playbook rule '$SharedPlaybookRuleName' not present yet - nothing to remove."
}

foreach ($ip in $AllowedSourceIPs) {
    if ($ip -like "CHANGEME*") {
        Write-Warning "Skipping unset IP placeholder - fill in AllowedSourceIPs in config.ps1"
        continue
    }
    New-NetFirewallRule -DisplayName "$RuleNamePrefix$ip" `
        -Direction Inbound -Protocol TCP -LocalPort $MSSQLPort `
        -RemoteAddress $ip -Action Allow | Out-Null
    Write-Host "Allowed $ip on port $MSSQLPort"
}

Write-Host "`nNote: this only ADDS allow rules for specific hosts. It does not block everyone else -"
Write-Host "if you need a default-deny on this port, that's a broader firewall policy decision,"
Write-Host "confirm with gray team it's not effectively a subnet-range block before applying it."

# --- 6. Self-test the scoring account can still connect ---
Write-Section "Self-test: scoring account connectivity"

if ($ScoringAccount -like "CHANGEME*") {
    Write-Warning "ScoringAccount not set in config.ps1 - skipping self-test"
} else {
    Write-Host "Manually verify with: sqlcmd -S localhost -U $ScoringAccount -P <password> -Q `"SELECT 1`""
    Write-Host "(not run automatically here since it needs the scoring account's password)"
}

Write-Section "Done"
Write-Host "Backups saved in $BackupDir"
