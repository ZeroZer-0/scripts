# lock-down-folders.ps1
# Run EARLY - before harden.ps1/audit-accounts.ps1/etc. start writing
# files into BackupDir. Restricts BackupDir, ToolsDir, and the scripts
# folder itself (which holds config.ps1 - real sa/local-admin passwords
# in plaintext) to Administrators + SYSTEM only, removing default
# inherited access for everyone else.
#
# Uses /T so this applies retroactively to anything already inside these
# folders, not just files created afterward - matters because
# check-environment.ps1 (which runs before this, per run-setup.ps1's
# order) can create a sqlcmd install in ToolsDir before this step locks
# it down. Without /T, icacls only touches the folder itself and doesn't
# reach pre-existing children.
#
# HONEST LIMIT: this protects against a lower-privilege foothold reading
# these files. It does NOT protect against red team achieving actual
# admin/SYSTEM-level compromise - at that point they can read anything
# regardless of ACLs, same as you can. This buys you a barrier, not a
# guarantee.

. "$PSScriptRoot\config.ps1"

$ErrorActionPreference = "Stop"

function Lock-Folder($path) {
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
    icacls $path /inheritance:r /T | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "icacls /inheritance:r FAILED on $path (exit code $LASTEXITCODE) - this folder is NOT locked down. Check manually."
        return
    }
    icacls $path /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" /T | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "icacls /grant FAILED on $path (exit code $LASTEXITCODE) - this folder is NOT locked down. Check manually."
        return
    }
    Write-Host "Locked down: $path (Administrators + SYSTEM only, applied recursively)"
}

Lock-Folder $BackupDir
Lock-Folder $ToolsDir
Lock-Folder $PSScriptRoot

Write-Host "`nDone. Verify with: icacls `"$BackupDir`""
Write-Warning "This only stops a lower-privilege foothold from reading these files. Full admin/SYSTEM compromise bypasses ACLs entirely - this is a barrier, not a guarantee."
