# additional-hardening.ps1
# Run after harden.ps1. Covers things that need eyes-on-the-box first -
# this script checks and reports, and only changes things where the fix
# is unambiguous. Read the output before assuming everything's fine.

. "$PSScriptRoot\config.ps1"

$ErrorActionPreference = "Stop"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

function Write-Section($msg) {
    Write-Host "`n=== $msg ===" -ForegroundColor Cyan
}

if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

# --- 1. SQL auth mode ---
Write-Section "Checking SQL authentication mode"

$authMode = sqlcmd -S localhost -E -h -1 -Q "SET NOCOUNT ON; EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode';"
Write-Host $authMode
Write-Host "LoginMode 1 = Windows only, 2 = Mixed (SQL + Windows). If the scoring account is a SQL login and this is 1, scoring WILL fail - fix in SSMS/Server Properties > Security, or ask gray team which mode is expected."

# --- 2. Password policy enforcement on SQL logins ---
Write-Section "Checking password policy enforcement on SQL logins"

$policyCheck = "SELECT name, is_disabled, is_policy_checked, is_expiration_checked FROM sys.sql_logins;"
sqlcmd -S localhost -E -Q $policyCheck
Write-Host "is_policy_checked / is_expiration_checked should be 1 for real accounts. If 0, a weak/stale password on that login won't get flagged by Windows policy."
Write-Host "To fix a specific login: ALTER LOGIN <name> WITH CHECK_POLICY = ON, CHECK_EXPIRATION = ON;"
Write-Host "(not applied automatically - some scoring/service accounts are deliberately exempted, confirm before changing)"

# --- 3. Linked servers (lateral movement path) ---
Write-Section "Checking linked servers"

$linkedServers = sqlcmd -S localhost -E -h -1 -Q "SET NOCOUNT ON; SELECT name, product, provider, data_source FROM sys.servers WHERE is_linked = 1;"
if ($linkedServers -match "\S") {
    Write-Warning "Linked servers found - these are a lateral movement path if credentials are stored insecurely:"
    Write-Host $linkedServers
} else {
    Write-Host "No linked servers configured."
}

# --- 4. Enable login auditing (failed + successful) ---
Write-Section "Enabling login auditing"

sqlcmd -S localhost -E -Q "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel', REG_DWORD, 3;"
Write-Host "AuditLevel set to 3 (both failed and successful logins). Requires a SQL Server service restart to take effect - restarting now will drop current connections, confirm timing before restarting."

# --- 5. Local Windows admin audit (separate from SQL logins) ---
Write-Section "Local Windows administrators group membership"

$localAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
$localAdmins | ForEach-Object { Write-Host $_.Name }
Write-Host "Compare this list against what you expect. A Windows-level local admin bypasses all SQL-level hardening entirely."

$adminBackupFile = Join-Path $BackupDir "local_admins_backup_$Timestamp.txt"
$localAdmins | Out-File $adminBackupFile
Write-Host "Saved to $adminBackupFile"

Write-Section "Done - review warnings above before making further changes"
