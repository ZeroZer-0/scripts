# run-setup.ps1
# Run this once, as Administrator, right after you get console access.
# Pauses before EACH step, shows what it's about to do, and waits for
# you to approve it - so a bad assumption in one step doesn't silently
# take out an account or a rule you didn't expect. Slower than running
# unattended, on purpose.
#
# At the prompt: y = run this step, n = skip it, a = approve this and
# everything remaining without asking again.
#
# NOT included here - run these separately, when needed, not at setup:
#   healthcheck.ps1        - needs the scoring account's password as input
#   find-hidden-challenges.ps1 - slow, run it on its own when you have time
#   autoruns-scan.ps1 second/third pass - re-run periodically, not just once
#
# Before running this: fill in config.ps1. Placeholders left as CHANGEME
# will cause the affected step to skip itself and warn, not silently
# apply garbage - but you should still fill it in first.

$ErrorActionPreference = "Continue"

. "$PSScriptRoot\config.ps1"

if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$RunLog = Join-Path $BackupDir "run_setup_$Timestamp.log"

$results = @()
$approveAll = $false

function Run-Step($name, $scriptFile, $description) {
    Write-Host "`n########################################" -ForegroundColor Magenta
    Write-Host "# $name" -ForegroundColor Magenta
    Write-Host "########################################" -ForegroundColor Magenta
    Write-Host $description -ForegroundColor Gray

    if (-not $script:approveAll) {
        $choice = Read-Host "Run this step? [y/n/a=approve all remaining]"
        if ($choice -eq "a") {
            $script:approveAll = $true
        } elseif ($choice -ne "y") {
            Write-Host "Skipped." -ForegroundColor Yellow
            $script:results += [PSCustomObject]@{ Step = $name; Status = "SKIPPED (user)" }
            Add-Content -Path $RunLog -Value "`n### $name - SKIPPED by user ($(Get-Date -Format o)) ###"
            return
        }
    }

    Add-Content -Path $RunLog -Value "`n### $name ($(Get-Date -Format o)) ###"

    $path = Join-Path $PSScriptRoot $scriptFile
    if (-not (Test-Path $path)) {
        Write-Warning "$scriptFile not found - skipping"
        $script:results += [PSCustomObject]@{ Step = $name; Status = "MISSING" }
        return
    }

    try {
        & $path *>&1 | Tee-Object -FilePath $RunLog -Append
        $script:results += [PSCustomObject]@{ Step = $name; Status = "OK" }
    } catch {
        Write-Warning "$name FAILED: $($_.Exception.Message)"
        $script:results += [PSCustomObject]@{ Step = $name; Status = "FAILED: $($_.Exception.Message)" }
    }
}

# --- Pre-flight: PowerShell version + config check ---
Write-Host "Pre-flight checks..." -ForegroundColor Cyan

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Warning "PowerShell $($PSVersionTable.PSVersion) detected. This was written for PowerShell 5.1 (Server 2019 default) - some cmdlets used here (NetSecurity, LocalAccounts modules) may not exist. Run this from a normal Windows PowerShell 5.1 prompt, not PowerShell 2.0/cmd.exe."
    $proceed = Read-Host "Continue anyway? [y/n]"
    if ($proceed -ne "y") { exit 1 }
}

$configText = Get-Content "$PSScriptRoot\config.ps1" -Raw
if ($configText -match "CHANGEME") {
    Write-Warning "config.ps1 still has CHANGEME placeholders. Affected steps will skip themselves and warn rather than apply garbage, but fill it in when you can."
}

Run-Step "Lock down backup/tools/script folders" "lock-down-folders.ps1" `
    "Restricts filesystem ACLs on BackupDir, ToolsDir, and the scripts folder (which holds config.ps1's real passwords) to Administrators+SYSTEM only. Run first, before anything writes sensitive files. Does NOT protect against full admin/SYSTEM-level compromise."

Run-Step "Create local break-glass admin" "create-local-admin.ps1" `
    "Creates a local admin account (config.ps1: LocalAdminUsername) as a fallback if AD goes down. Will PROMPT for the password (masked, typed twice) - have it ready. Adds account to local Administrators."

Run-Step "Enable firewall rule-change auditing" "enable-firewall-auditing.ps1" `
    "Turns on Windows audit logging for firewall rule add/modify/delete (auditpol, MPSSVC subcategory). Run before any firewall changes so those are captured too. No changes to actual firewall rules."

Run-Step "Install tools (Autoruns)" "install-tools.ps1" `
    "Downloads Sysinternals Autoruns from the internet, verifies it's Microsoft-signed before trusting it. No changes to the box itself."

Run-Step "Core hardening" "harden.ps1" `
    "Backs up current SQL config/logins/sysadmin list to disk, then: PROMPTS for a new sa password (masked, typed twice - have it ready), disables xp_cmdshell, adds firewall allow rules for AllowedSourceIPs on port $MSSQLPort. Review AllowedSourceIPs in config.ps1 before approving."

Run-Step "Additional hardening checks" "additional-hardening.ps1" `
    "Mostly read-only reporting (auth mode, password policy, linked servers, local admins). One real change: enables SQL login auditing via a registry write (requires a later SQL service restart to take effect, not done automatically here)."

Run-Step "Baseline snapshot" "baseline.ps1" `
    "Read-only. Captures services, scheduled tasks, startup programs, local admins, listening ports, established connections, SQL logins, SQL Agent jobs to CSV/text files."

Run-Step "Account audit" "audit-accounts.ps1" `
    "Read-only. Compares local users, local Administrators group, and SQL logins against the packet account list and your own break-glass admin. Flags anything unexpected, changes nothing."

Run-Step "Autoruns scan" "autoruns-scan.ps1" `
    "Read-only. Runs Autorunsc against all persistence categories, saves CSV output. Only works if the install-tools step succeeded earlier."

# --- Summary ---
Write-Host "`n########################################" -ForegroundColor Cyan
Write-Host "# SETUP SUMMARY" -ForegroundColor Cyan
Write-Host "########################################" -ForegroundColor Cyan
$results | Format-Table -AutoSize
$results | Out-File (Join-Path $BackupDir "run_setup_summary_$Timestamp.txt")

Write-Host "`nFull log: $RunLog"
Write-Host "Still to do manually: healthcheck.ps1 (needs scoring account password), find-hidden-challenges.ps1 (slow, run separately)"
