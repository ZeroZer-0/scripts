# enable-firewall-auditing.ps1
# Run ONCE at setup. Turns on Windows' own audit logging for firewall
# rule changes (additions, modifications, deletions) - this logs the
# event the moment it happens, which a periodic snapshot-and-diff would
# miss if a rule gets added and removed between checks.
#
# This does NOT require re-running after a reboot - the audit policy
# setting persists. It DOES need to run again if gray team redeploys
# the box (full reset wipes audit policy along with everything else).

$ErrorActionPreference = "Stop"

Write-Host "Enabling firewall rule-level policy change auditing..."

# MPSSVC = Microsoft Protection Service (the Windows Firewall service).
# This subcategory covers rule add/modify/delete and firewall setting changes.
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable

$check = auditpol /get /subcategory:"MPSSVC Rule-Level Policy Change"
Write-Host $check

if ($check -match "Success and Failure" -or ($check -match "Success" -and $check -match "Failure")) {
    Write-Host "Confirmed: auditing enabled." -ForegroundColor Green
} else {
    Write-Warning "Auditing may not have applied correctly - check the output above manually."
}

Write-Host "`nFirewall rule changes will now appear in the Security event log as:"
Write-Host "  4946 - rule added"
Write-Host "  4947 - rule modified"
Write-Host "  4948 - rule deleted"
Write-Host "  4950 - a firewall setting changed"
Write-Host "Use check-firewall-events.ps1 to review these."
