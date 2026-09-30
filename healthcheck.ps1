# healthcheck.ps1
# Quick self-check mimicking what the scorebot likely does: connect,
# run a trivial query, confirm success. Run this any time to verify
# the service looks up before the next 60-second scoring check catches it.
#
# Usage: .\healthcheck.ps1                      # prompts for password (masked, not saved anywhere)
#        .\healthcheck.ps1 -Password "..."      # only if you specifically need scripted/unattended use -
#                                                   this leaves the password sitting in PSReadLine's
#                                                   saved command history on disk. Prefer the prompt.

param(
    [string]$Password
)

. "$PSScriptRoot\config.ps1"

if ($ScoringAccount -like "CHANGEME*") {
    Write-Warning "ScoringAccount not set in config.ps1 - set it first"
    exit 1
}

if ([string]::IsNullOrEmpty($Password)) {
    $securePw = Read-Host "Password for scoring account '$ScoringAccount' (input hidden)" -AsSecureString
    $Password = [System.Net.NetworkCredential]::new("", $securePw).Password
}

$result = sqlcmd -S "localhost,$MSSQLPort" -U $ScoringAccount -P $Password -h -1 -Q "SET NOCOUNT ON; SELECT 1;" 2>&1
$Password = $null

if ($LASTEXITCODE -eq 0 -and $result -match "1") {
    Write-Host "OK: MSSQL reachable and query succeeded as $ScoringAccount" -ForegroundColor Green
} else {
    Write-Host "FAIL: could not connect or query failed" -ForegroundColor Red
    Write-Host $result
    exit 1
}
