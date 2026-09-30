# baseline.ps1
# Run once at setup, right after harden.ps1. Captures a snapshot of
# system state so you can diff against it later if something looks
# off mid-competition. Re-run anytime to compare against the original.

. "$PSScriptRoot\config.ps1"

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$SnapshotDir = Join-Path $BackupDir "baseline_$Timestamp"
New-Item -ItemType Directory -Path $SnapshotDir -Force | Out-Null

function Write-Section($msg) {
    Write-Host "`n=== $msg ===" -ForegroundColor Cyan
}

Write-Section "Services"
Get-Service | Select-Object Name, Status, StartType | Sort-Object Name |
    Export-Csv (Join-Path $SnapshotDir "services.csv") -NoTypeInformation

Write-Section "Scheduled tasks"
Get-ScheduledTask | Select-Object TaskName, TaskPath, State |
    Export-Csv (Join-Path $SnapshotDir "scheduled_tasks.csv") -NoTypeInformation

Write-Section "Startup programs"
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User |
    Export-Csv (Join-Path $SnapshotDir "startup_programs.csv") -NoTypeInformation

Write-Section "Local administrators"
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource |
    Export-Csv (Join-Path $SnapshotDir "local_admins.csv") -NoTypeInformation

Write-Section "Installed features/roles"
Get-WindowsFeature | Where-Object { $_.InstallState -eq "Installed" } | Select-Object Name |
    Export-Csv (Join-Path $SnapshotDir "windows_features.csv") -NoTypeInformation

Write-Section "Listening ports"
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess |
    Export-Csv (Join-Path $SnapshotDir "listening_ports.csv") -NoTypeInformation

Write-Section "Established outbound connections (C2 beacon check)"
Get-NetTCPConnection -State Established |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
        @{N="ProcessName";E={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path }} |
    Export-Csv (Join-Path $SnapshotDir "established_connections.csv") -NoTypeInformation
Write-Host "Review RemoteAddress values outside your known subnets (10.110.10.0/24, 10.110.20.0/24, gray team infra)."
Write-Host "Any connection to something outside that with no obvious process reason is worth investigating."

Write-Section "SQL Server logins"
sqlcmd -S localhost -E -Q "SELECT name, type_desc, is_disabled, create_date, modify_date FROM sys.server_principals WHERE type IN ('S','U','G');" `
    -o (Join-Path $SnapshotDir "sql_logins.txt")

Write-Section "SQL Server Agent jobs"
sqlcmd -S localhost -E -Q "SELECT name, enabled, date_created, date_modified FROM msdb.dbo.sysjobs;" `
    -o (Join-Path $SnapshotDir "sql_agent_jobs.txt")

Write-Host "`nBaseline saved to $SnapshotDir"
Write-Host "To compare later: Compare-Object (Import-Csv old.csv) (Import-Csv new.csv)"
