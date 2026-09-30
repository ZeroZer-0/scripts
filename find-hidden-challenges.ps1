# find-hidden-challenges.ps1
# Sweeps for hidden challenge/flag content, tiered by how likely each
# spot is to actually be used. Run tier by tier with -Tier, or omit
# -Tier entirely to run all of them at once (default is 0 = all).
# Output goes to console and a log file so you can grep it later.
#
# Usage:
#   .\find-hidden-challenges.ps1               # no -Tier = runs all tiers (default Tier=0)
#   .\find-hidden-challenges.ps1 -Tier 1        # just tier 1
#   .\find-hidden-challenges.ps1 -Keywords "flag","token","ctf"

param(
    [int]$Tier = 0,   # 0 = all tiers
    [string[]]$Keywords = @("flag", "challenge", "hidden", "secret", "clue", "key", "token", "ctf")
)

. "$PSScriptRoot\config.ps1"

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = Join-Path $BackupDir "hidden_challenge_scan_$Timestamp.txt"
if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }

function Write-Hit($tier, $msg) {
    $line = "[Tier $tier] $msg"
    Write-Host $line -ForegroundColor Yellow
    Add-Content -Path $LogFile -Value $line
}

function Write-Section($msg) {
    Write-Host "`n=== $msg ===" -ForegroundColor Cyan
    Add-Content -Path $LogFile -Value "`n=== $msg ==="
}

$KeywordPattern = ($Keywords -join "|")

# --- Tier 1: most common CTF/challenge hiding spots ---
if ($Tier -eq 0 -or $Tier -eq 1) {
    Write-Section "Tier 1: Desktop, Documents, Public, root of C:\"

    $tier1Paths = @(
        "C:\Users\*\Desktop"
        "C:\Users\*\Documents"
        "C:\Users\Public"
        "C:\"
        "C:\inetpub"
    )

    foreach ($path in $tier1Paths) {
        Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue -Depth 2 |
            Where-Object { $_.Name -match $KeywordPattern } |
            ForEach-Object { Write-Hit 1 "Filename match: $($_.FullName)" }
    }
}

# --- Tier 2: recently created/modified files system-wide (last 30 days) ---
if ($Tier -eq 0 -or $Tier -eq 2) {
    Write-Section "Tier 2: Recently modified files (last 30 days, excluding noisy system paths)"

    $excludePaths = "Windows\\WinSxS|Windows\\servicing|\\AppData\\Local\\Temp|\\AppData\\Local\\Microsoft\\Windows\\INetCache"
    $cutoff = (Get-Date).AddDays(-30)

    Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue -File |
        Where-Object { $_.LastWriteTime -gt $cutoff -and $_.FullName -notmatch $excludePaths } |
        Select-Object -First 200 |
        ForEach-Object { Write-Hit 2 "Recently modified: $($_.FullName) ($($_.LastWriteTime))" }

    Write-Host "(capped at 200 results - narrow the date range or add exclusions if this is too noisy)"
}

# --- Tier 3: hidden/system attribute files ---
if ($Tier -eq 0 -or $Tier -eq 3) {
    Write-Section "Tier 3: Hidden or system-attribute files outside normal Windows locations"

    Get-ChildItem -Path C:\Users -Recurse -Force -ErrorAction SilentlyContinue -File |
        Where-Object { ($_.Attributes -match "Hidden") -and ($_.FullName -notmatch "\\AppData\\") } |
        ForEach-Object { Write-Hit 3 "Hidden file: $($_.FullName)" }
}

# --- Tier 4: alternate data streams (classic hiding technique) ---
if ($Tier -eq 0 -or $Tier -eq 4) {
    Write-Section "Tier 4: Alternate Data Streams on Desktop/Documents/root"

    $adsPaths = @("C:\Users\*\Desktop", "C:\Users\*\Documents", "C:\")
    foreach ($path in $adsPaths) {
        Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue -Depth 1 |
            ForEach-Object {
                $streams = Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue |
                    Where-Object { $_.Stream -ne ':$DATA' }
                foreach ($s in $streams) {
                    Write-Hit 4 "ADS found: $($_.FullName) -> stream '$($s.Stream)'"
                }
            }
    }
}

# --- Tier 5: registry autorun/persistence locations (also common flag spot) ---
if ($Tier -eq 0 -or $Tier -eq 5) {
    Write-Section "Tier 5: Registry Run keys and autorun locations"

    $runKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            Get-ItemProperty -Path $key | ForEach-Object {
                $_.PSObject.Properties | Where-Object { $_.Name -match $KeywordPattern } |
                    ForEach-Object { Write-Hit 5 "Registry match in ${key}: $($_.Name) = $($_.Value)" }
            }
        }
    }
}

# --- Tier 6: SQL Server specific hiding spots ---
if ($Tier -eq 0 -or $Tier -eq 6) {
    Write-Section "Tier 6: SQL Server extended properties, comments, and job steps"

    if (Get-Command sqlcmd -ErrorAction SilentlyContinue) {
        Write-Host "Checking extended properties across all user databases..."
        $epQuery = @"
SET NOCOUNT ON;
EXEC sp_MSforeachdb 'USE [?]; IF DB_ID(''?'') > 4
SELECT ''?'' AS db_name, class_desc, name, CAST(value AS NVARCHAR(4000)) AS value
FROM sys.extended_properties'
"@
        $epResult = sqlcmd -S localhost -E -h -1 -Q $epQuery
        if ($epResult -match "\S") {
            Write-Hit 6 "Extended properties found (check for flag content):"
            Write-Host $epResult
            Add-Content -Path $LogFile -Value $epResult
        }

        Write-Host "Checking SQL Agent job step commands..."
        $jobQuery = "SELECT j.name AS job_name, s.command FROM msdb.dbo.sysjobs j JOIN msdb.dbo.sysjobsteps s ON j.job_id = s.job_id;"
        $jobResult = sqlcmd -S localhost -E -h -1 -Q $jobQuery
        if ($jobResult -match $KeywordPattern) {
            Write-Hit 6 "SQL Agent job step matched keyword - review manually"
            Write-Host $jobResult
        }
    } else {
        Write-Warning "sqlcmd not found - skipping SQL-specific checks"
    }
}

Write-Section "Scan complete"
Write-Host "Full log: $LogFile"
