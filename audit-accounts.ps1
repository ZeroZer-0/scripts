# audit-accounts.ps1
# READ ONLY. Changes nothing (rule 13: no deleting required users,
# rule 3: grey team accounts are off limits).
#
# Compares accounts on this box against the packet account list in
# config.ps1 and flags anything enabled that isn't on it.
#
# UNKNOWN does not mean malicious. The scorebot's account may not be on the
# packet list. Ask grey team before disabling anything you can't explain.
#
# Run on setup day, then again periodically. New UNKNOWN entries that
# appear mid-competition are the interesting ones.

. "$PSScriptRoot\config.ps1"

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
$LogFile = Join-Path $BackupDir "account_audit_$Timestamp.txt"

function Norm([string]$n) {
    return ((($n -split '\\')[-1]).ToLower()) -replace '[^a-z0-9]', ''
}

$adminSet   = @($PacketAdmins     | ForEach-Object { Norm $_ })
$userSet    = @($PacketUsers      | ForEach-Object { Norm $_ })
$greySet    = @($GreyTeamAccounts | ForEach-Object { Norm $_ })
$builtinSet = @($BuiltinNames     | ForEach-Object { Norm $_ })
$ownAdminName = Norm $LocalAdminUsername

function Classify([string]$name) {
    $n = Norm $name
    if ($adminSet -contains $n)   { return "PACKET-ADMIN" }
    if ($userSet -contains $n)    { return "PACKET-USER" }
    if ($greySet -contains $n)    { return "GREY-TEAM" }
    if ($builtinSet -contains $n) { return "BUILTIN" }
    foreach ($p in $BuiltinRawPatterns) {
        if ($name -match $p) { return "BUILTIN" }
    }
    return "UNKNOWN"
}

function Emit([string]$line, [string]$level) {
    $color = switch ($level) {
        "UNKNOWN" { "Red" }
        "FLAG"    { "Yellow" }
        "GREY"    { "DarkGray" }
        default   { "Gray" }
    }
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $LogFile -Value $line
}

function Write-Section($msg) {
    Write-Host "`n=== $msg ===" -ForegroundColor Cyan
    Add-Content -Path $LogFile -Value "`n=== $msg ==="
}

$unknownCount = 0

# --- 1. Local user accounts ---
# The 10 required accounts are domain accounts (managed on Coruscant/AD),
# not local to this box. They will never show up in Get-LocalUser, so
# don't try to match them here - any enabled local account that isn't a
# Windows builtin is an outsider by definition per the "any other user
# is treated as an outsider" rule.
Write-Section "Local user accounts"
foreach ($u in (Get-LocalUser)) {
    $isBuiltin = $false
    $n = Norm $u.Name
    if ($builtinSet -contains $n) { $isBuiltin = $true }
    if ($n -eq $ownAdminName -and $ownAdminName -notlike "changeme*") { $isBuiltin = $true }
    foreach ($p in $BuiltinRawPatterns) {
        if ($u.Name -match $p) { $isBuiltin = $true }
    }

    $flag = ""
    $level = "OK"
    $class = if ($n -eq $ownAdminName -and $ownAdminName -notlike "changeme*") { "OWN-ADMIN" } elseif ($isBuiltin) { "BUILTIN" } else { "OUTSIDER" }
    if (-not $isBuiltin -and $u.Enabled) {
        $flag = "  <-- enabled local account, not a builtin - should not exist here"
        $level = "UNKNOWN"
        $unknownCount++
    }
    $line = "{0,-28} {1,-13} enabled={2,-5} pwdSet={3}{4}" -f $u.Name, $class, $u.Enabled, $u.PasswordLastSet, $flag
    Emit $line $level
}

# --- 2. Local Administrators group ---
Write-Section "Local Administrators group"
foreach ($m in (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue)) {
    $class = Classify $m.Name
    $flag = ""
    $level = "OK"
    if ($class -eq "UNKNOWN") {
        $flag = "  <-- unexpected local admin"
        $level = "UNKNOWN"
        $unknownCount++
    } elseif ($class -eq "PACKET-USER") {
        $flag = "  <-- packet lists this account as NON-admin"
        $level = "FLAG"
    }
    $line = "{0,-34} {1,-13} {2}{3}" -f $m.Name, $class, $m.ObjectClass, $flag
    Emit $line $level
}

# --- 3. SQL Server logins ---
Write-Section "SQL Server logins"
if (-not (Get-Command sqlcmd -ErrorAction SilentlyContinue)) {
    Write-Warning "sqlcmd not found, skipping SQL login audit"
} else {
    $q = "SET NOCOUNT ON; SELECT name + '|' + type_desc + '|' + CAST(is_disabled AS varchar(1)) + '|' + CAST(ISNULL(IS_SRVROLEMEMBER('sysadmin', name), 0) AS varchar(1)) FROM sys.server_principals WHERE type IN ('S','U','G') ORDER BY name;"
    $rows = sqlcmd -S localhost -E -h -1 -W -Q $q
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "sqlcmd failed: $rows"
    } else {
        foreach ($row in $rows) {
            if ([string]::IsNullOrWhiteSpace($row) -or $row -notmatch '\|') { continue }
            $name, $type, $disabled, $sysadmin = $row.Trim() -split '\|'

            $class = Classify $name
            $flag = ""
            $level = "OK"
            if ($class -eq "UNKNOWN" -and $disabled -eq "0") {
                $flag = "  <-- enabled login, not in packet"
                if ($sysadmin -eq "1") { $flag += " AND sysadmin" }
                $level = "UNKNOWN"
                $unknownCount++
            } elseif ($class -eq "PACKET-USER" -and $sysadmin -eq "1") {
                $flag = "  <-- packet lists this account as non-admin but it has sysadmin"
                $level = "FLAG"
            } elseif ($class -eq "GREY-TEAM") {
                $level = "GREY"
            }
            $line = "{0,-34} {1,-13} {2,-16} disabled={3} sysadmin={4}{5}" -f $name, $class, $type, $disabled, $sysadmin, $flag
            Emit $line $level
        }
    }
}

Write-Section "Summary"
Emit "Enabled accounts not in the packet: $unknownCount" $(if ($unknownCount -gt 0) { "UNKNOWN" } else { "OK" })
Emit "Log saved to $LogFile" "OK"
