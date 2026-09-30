# check-environment.ps1
# Runs SECOND in run-setup.ps1, right after lock-down-folders.ps1 - not
# before it. Folders need to be locked down first so nothing this script
# creates (like a sqlcmd install) ends up needing a retroactive ACL fix.
#
# NOTE: this script unblocks every OTHER .ps1 file in the folder, but it
# cannot unblock itself before it starts (Windows checks the block before
# PowerShell begins running it at all). Launch this - and run-setup.ps1,
# which calls this - with:
#   powershell.exe -ExecutionPolicy Bypass -File .\run-setup.ps1
# rather than relying on this script's own unblock logic to cover itself.
#
# Detects environment prerequisites and auto-fixes the ones that are safe
# and unambiguous (installing sqlcmd, starting a stopped service,
# unblocking script files). Anything disruptive (SQL auth mode requires
# a service restart, dropping active connections) is reported with the
# exact fix and asks before applying it - same philosophy as the rest of
# this toolkit: safe stuff happens automatically, disruptive stuff gets
# a chance to say no.
#
# Deliberately does NOT depend on config.ps1 - this needs to run and be
# useful even before config.ps1 is fully filled in.

$ErrorActionPreference = "Continue"
$problems = @()
$fixedThings = @()

function Write-Section($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Write-Ok($msg) { Write-Host "OK: $msg" -ForegroundColor Green }
function Write-Fixed($msg) { Write-Host "FIXED: $msg" -ForegroundColor Yellow; $script:fixedThings += $msg }
function Write-Problem($msg) { Write-Warning $msg; $script:problems += $msg }

# --- 1. Elevation check ---
Write-Section "Checking elevation"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Problem "NOT running as Administrator. Everything past this point will fail. Close this window and re-open PowerShell with 'Run as Administrator'."
} else {
    Write-Ok "Running elevated"
}

# --- 2. Unblock all scripts in this folder ---
Write-Section "Unblocking scripts (clears Mark-of-the-Web from files transferred via download/RustDesk)"
try {
    Get-ChildItem $PSScriptRoot -Filter *.ps1 -ErrorAction Stop | Unblock-File -ErrorAction Stop
    Write-Ok "All .ps1 files in $PSScriptRoot unblocked"
} catch {
    Write-Problem "Failed to unblock files: $($_.Exception.Message)"
}

# --- 3. PowerShell version ---
Write-Section "Checking PowerShell version"
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Problem "PowerShell $($PSVersionTable.PSVersion) detected - this toolkit expects 5.1 (Server 2019 default). Some cmdlets used here may not exist."
} else {
    Write-Ok "PowerShell $($PSVersionTable.PSVersion)"
}

# --- 4. Required built-in Windows modules ---
Write-Section "Checking required PowerShell modules"
$requiredModules = "Microsoft.PowerShell.LocalAccounts", "NetSecurity", "NetTCPIP", "ScheduledTasks", "ServerManager"
foreach ($m in $requiredModules) {
    if (Get-Module -ListAvailable -Name $m) {
        Write-Ok "$m available"
    } else {
        Write-Problem "$m module NOT found. This should be built into Windows Server 2019 - if it's missing, something is wrong with this install, not something this script can fix."
    }
}

# --- 5. winget availability (informational - used by the sqlcmd install below if present) ---
Write-Section "Checking for winget"
$hasWinget = [bool](Get-Command winget -ErrorAction SilentlyContinue)
if ($hasWinget) {
    Write-Ok "winget available"
} else {
    Write-Host "winget not found - normal on Server editions, which don't always ship App Installer by default."
    Write-Host "Not attempting to bootstrap winget itself (sideloading it needs VCLibs/UI.Xaml dependencies and is fragile to automate reliably) - the sqlcmd install below falls back to a direct GitHub download instead, which doesn't need winget at all."
}

# --- 6. sqlcmd - attempt automatic install if missing ---
Write-Section "Checking for sqlcmd"
if (Get-Command sqlcmd -ErrorAction SilentlyContinue) {
    Write-Ok "sqlcmd found on PATH"
} else {
    Write-Host "sqlcmd not found - attempting automatic install..."
    $installed = $false

    if ($hasWinget) {
        try {
            winget install sqlcmd --accept-package-agreements --accept-source-agreements | Out-Null
            if (Get-Command sqlcmd -ErrorAction SilentlyContinue) { $installed = $true }
        } catch { }
    }

    if (-not $installed) {
        Write-Host "winget unavailable or failed - falling back to direct download from GitHub (go-sqlcmd)..."
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $releaseInfo = Invoke-RestMethod -Uri "https://api.github.com/repos/microsoft/go-sqlcmd/releases/latest"
            $asset = $releaseInfo.assets | Where-Object { $_.name -match "windows-amd64\.zip$" } | Select-Object -First 1
            if ($asset) {
                $zipPath = Join-Path $env:TEMP "sqlcmd.zip"
                Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing
                $destDir = "C:\CompTools\sqlcmd"
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                Expand-Archive -Path $zipPath -DestinationPath $destDir -Force
                Remove-Item $zipPath -Force
                $env:Path += ";$destDir"
                if (Get-Command sqlcmd -ErrorAction SilentlyContinue) { $installed = $true }
            } else {
                Write-Problem "Could not find a windows-amd64.zip asset in the latest go-sqlcmd release - GitHub's release structure may have changed."
            }
        } catch {
            Write-Problem "Automatic sqlcmd install failed: $($_.Exception.Message)"
        }
    }

    if ($installed) {
        Write-Fixed "sqlcmd installed automatically (added to this session's PATH - a NEW PowerShell window will also need this, or a permanent PATH entry)"
    } else {
        Write-Problem "Could not install sqlcmd automatically. Install manually: winget install sqlcmd (or see github.com/microsoft/go-sqlcmd)"
    }
}

# --- 7. SQL Server service running at all ---
Write-Section "Checking SQL Server service"
$sqlService = Get-Service -Name "MSSQLSERVER" -ErrorAction SilentlyContinue
if (-not $sqlService) {
    Write-Problem "MSSQLSERVER service not found - is SQL Server actually installed? (named instances use a different service name - if you installed a named instance, this check won't find it)"
} elseif ($sqlService.Status -ne "Running") {
    try {
        Start-Service -Name "MSSQLSERVER" -ErrorAction Stop
        Write-Fixed "MSSQLSERVER service was stopped - started it"
    } catch {
        Write-Problem "MSSQLSERVER service is stopped and could not be started: $($_.Exception.Message)"
    }
} else {
    Write-Ok "MSSQLSERVER service running"
}

# --- 8. SQL Server Agent - safe to auto-fix (no security implications) ---
Write-Section "Checking SQL Server Agent"
$agentService = Get-Service -Name "SQLSERVERAGENT" -ErrorAction SilentlyContinue
if (-not $agentService) {
    Write-Host "SQLSERVERAGENT service not found (expected if this is SQL Server Express - Agent isn't included in that edition)."
} else {
    $wmiAgent = Get-CimInstance -ClassName Win32_Service -Filter "Name='SQLSERVERAGENT'" -ErrorAction SilentlyContinue
    if ($wmiAgent -and $wmiAgent.StartMode -ne "Auto") {
        try {
            Set-Service -Name "SQLSERVERAGENT" -StartupType Automatic -ErrorAction Stop
            Write-Fixed "SQL Server Agent startup type set to Automatic"
        } catch {
            Write-Problem "Could not set SQL Server Agent to Automatic startup: $($_.Exception.Message)"
        }
    }
    if ($agentService.Status -ne "Running") {
        try {
            Start-Service -Name "SQLSERVERAGENT" -ErrorAction Stop
            Write-Fixed "SQL Server Agent was stopped - started it"
        } catch {
            Write-Problem "Could not start SQL Server Agent: $($_.Exception.Message)"
        }
    } else {
        Write-Ok "SQL Server Agent running"
    }
}

# --- 9. SQL auth mode - detect, report exact fix, ASK before restarting (disruptive) ---
Write-Section "Checking SQL authentication mode"
if (Get-Command sqlcmd -ErrorAction SilentlyContinue) {
    $authModeRaw = sqlcmd -S localhost -E -h -1 -Q "SET NOCOUNT ON; EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode';" 2>$null
    if ($authModeRaw -match "2\s*$") {
        Write-Ok "Mixed mode authentication already enabled"
    } elseif ($authModeRaw -match "1\s*$") {
        Write-Problem "SQL Server is in Windows-only auth mode. If a SQL login (e.g. the scoring account) needs to connect, this must be Mixed mode."
        $fixNow = Read-Host "Switch to Mixed mode now? This restarts the SQL Server service and drops current connections. [y/n]"
        if ($fixNow -eq "y") {
            sqlcmd -S localhost -E -Q "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 2;" | Out-Null
            Restart-Service -Name "MSSQLSERVER" -Force
            Start-Sleep -Seconds 5
            Write-Fixed "Switched to Mixed mode and restarted SQL Server"
        } else {
            Write-Host "Skipped. Fix later with the command above plus a service restart, or via SSMS: Server Properties > Security."
        }
    } else {
        Write-Problem "Could not determine auth mode - sqlcmd returned something unexpected: '$authModeRaw'"
    }
} else {
    Write-Host "Skipping auth mode check - sqlcmd still not available."
}

# --- Summary ---
Write-Section "Environment check summary"
if ($fixedThings.Count -gt 0) {
    Write-Host "Auto-fixed:" -ForegroundColor Yellow
    $fixedThings | ForEach-Object { Write-Host "  - $_" }
}
if ($problems.Count -gt 0) {
    Write-Host "`nUnresolved - review before continuing:" -ForegroundColor Red
    $problems | ForEach-Object { Write-Host "  - $_" }
} else {
    Write-Host "`nNo unresolved problems. Environment looks ready." -ForegroundColor Green
}
