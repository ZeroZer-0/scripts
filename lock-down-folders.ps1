# lock-down-folders.ps1
# Runs FIRST in run-setup.ps1 - before check-environment.ps1, before this
# run's own log file, before anything else exists in BackupDir/ToolsDir.
# Restricts BackupDir, ToolsDir, and the scripts folder itself (which
# holds config.ps1 - real sa/local-admin passwords in plaintext) to
# Administrators + SYSTEM only, removing default inherited access for
# everyone else.
#
# This has to run before anything is created in those folders, not after.
# A file created BEFORE this runs would need this script to retroactively
# re-apply folder-style inheritance flags to an already-existing file,
# which is a murkier case than a new file just cleanly inheriting
# permissions from an already-locked parent at creation time. run-setup.ps1
# enforces this ordering - this step runs outside its normal per-step
# logging wrapper specifically so its own log file doesn't become that
# problem case itself.
#
# Uses /T anyway as defense in depth, in case this script is ever run a
# second time after other files already exist (e.g. manual re-run outside
# the normal sequence) - not something the normal flow should rely on.
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

    # GRANT FIRST, restrict second - deliberately in this order. If something
    # in a recursive /T walk fails partway through (one uncooperative file,
    # a lock, whatever), icacls doesn't behave atomically - it keeps whatever
    # it already changed on the items it successfully reached. Restricting
    # first and granting second meant a partial failure on the restrict step
    # could leave files with inheritance stripped and the replacement grant
    # never applied - i.e. no usable access to anyone, not even Administrators.
    # Granting first means even a partial failure later leaves Administrators/
    # SYSTEM with explicit access already in place - worst case some old
    # broader permissions also linger, which is a smaller problem than a
    # lockout. /C tells icacls to continue past individual file errors in the
    # recursive walk instead of the whole operation being an all-or-nothing
    # black box.
    icacls $path /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "icacls /grant reported errors on some items under $path (exit code $LASTEXITCODE). Administrators/SYSTEM have explicit access on everything it COULD reach - check manually: icacls `"$path`" /T"
    }

    icacls $path /inheritance:r /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "icacls /inheritance:r reported errors on some items under $path (exit code $LASTEXITCODE). Some files may still carry old inherited permissions beyond Administrators/SYSTEM - not a lockout (grant already applied above), but not fully restricted either. Check manually: icacls `"$path`" /T"
    }

    Write-Host "Locked down: $path (Administrators + SYSTEM, applied recursively - see warnings above if anything couldn't be reached)"
}

Lock-Folder $BackupDir
Lock-Folder $ToolsDir
Lock-Folder $PSScriptRoot

Write-Host "`nDone. Verify with: icacls `"$BackupDir`""
Write-Warning "This only stops a lower-privilege foothold from reading these files. Full admin/SYSTEM compromise bypasses ACLs entirely - this is a barrier, not a guarantee."
