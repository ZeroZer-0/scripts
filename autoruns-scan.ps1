# autoruns-scan.ps1
# Enumerates persistence/autorun locations via Sysinternals Autorunsc.
# READ ONLY - reports what it finds, changes nothing, removes nothing.
# Review the output yourself. Do not wire this into anything that
# auto-deletes flagged entries - false positives here can take down
# your own service.
#
# Run once at setup (right after install-tools.ps1) to get a baseline,
# then again periodically. Compare snapshots to spot anything NEW that
# showed up mid-competition - that's the actually interesting signal,
# more than any single scan in isolation.

. "$PSScriptRoot\config.ps1"

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$autorunscExe = Join-Path $ToolsDir "autorunsc64.exe"

if (-not (Test-Path $autorunscExe)) {
    Write-Warning "$autorunscExe not found. Run install-tools.ps1 first (or transfer it in manually if internet's gone)."
    return
}

if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }

$outFile = Join-Path $BackupDir "autoruns_scan_$Timestamp.csv"

# -a *  : all categories (not just the default subset)
# -c    : CSV output
# -h    : include file hashes
# -s    : verify digital signatures, flag unsigned entries
# -t    : include timestamps
# -nobanner -accepteula : skip interactive prompts, required for unattended run
& $autorunscExe -accepteula -nobanner -a * -c -h -s -t | Out-File -FilePath $outFile -Encoding utf8

Write-Host "Scan saved to $outFile"
Write-Host "Open in Excel/import-csv and sort by 'Signer' - unsigned or unexpected-signer entries are the first thing to actually look at."
Write-Host "To diff against a previous scan: Compare-Object (Import-Csv old.csv) (Import-Csv new.csv) -Property 'Entry Location','Entry','Image Path'"
