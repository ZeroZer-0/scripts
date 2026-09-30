# check-firewall-events.ps1
# Run this periodically (manually, or on a schedule - see note at bottom)
# to see firewall rule changes logged since the last time you checked.
# Requires enable-firewall-auditing.ps1 to have been run first, or the
# Security log won't have anything to show.

. "$PSScriptRoot\config.ps1"

$MarkerFile = Join-Path $BackupDir "firewall_audit_last_check.txt"
$RuleChangeEventIDs = 4946, 4947, 4948, 4950

if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }

$since = if (Test-Path $MarkerFile) {
    Get-Date (Get-Content $MarkerFile -Raw).Trim()
} else {
    (Get-Date).AddHours(-24)  # first run: look back 24h as a reasonable default
}

Write-Host "Checking for firewall rule changes since $since ..." -ForegroundColor Cyan

$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = $RuleChangeEventIDs
    StartTime = $since
} -ErrorAction SilentlyContinue

if (-not $events) {
    Write-Host "No firewall rule change events found since last check." -ForegroundColor Green
} else {
    Write-Warning "$($events.Count) firewall change event(s) found - review below:"
    foreach ($e in $events) {
        $label = switch ($e.Id) {
            4946 { "RULE ADDED" }
            4947 { "RULE MODIFIED" }
            4948 { "RULE DELETED" }
            4950 { "SETTING CHANGED" }
            default { "EVENT $($e.Id)" }
        }
        Write-Host "`n[$label] $($e.TimeCreated)" -ForegroundColor Yellow
        Write-Host $e.Message
    }

    $logFile = Join-Path $BackupDir "firewall_events_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $events | Format-List TimeCreated, Id, Message | Out-File $logFile
    Write-Host "`nFull details saved to $logFile"
}

# Update marker so next run only shows new events
(Get-Date -Format o) | Out-File $MarkerFile -Force

Write-Host "`nNote: event field completeness (rule name, who made the change) varies by"
Write-Host "how the rule was created. If a message here looks incomplete, cross-check"
Write-Host "current state with: Get-NetFirewallRule | Where DisplayName -notmatch 'CompBlue|BlueTeam'"
Write-Host "`nTo run this automatically every few minutes instead of by hand, wrap it in a"
Write-Host "scheduled task: schtasks /create /tn 'FirewallAuditCheck' /tr 'powershell.exe -File `"$PSCommandPath`"' /sc minute /mo 5"
