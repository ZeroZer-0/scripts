# create-local-admin.ps1
# Run FIRST, before anything else touches the box - the whole point is
# having a fallback in place before you start changing sa passwords,
# firewall rules, xp_cmdshell, etc. in case something goes wrong.
#
# Idempotent: if the account already exists, this does NOT touch its
# password on a re-run and does NOT prompt for one. If you need to
# rotate it later, do that deliberately with Set-LocalUser, not by
# re-running this script.

. "$PSScriptRoot\config.ps1"

$ErrorActionPreference = "Stop"

if ($LocalAdminUsername -like "CHANGEME*") {
    Write-Warning "LocalAdminUsername still a placeholder in config.ps1 - SKIPPING."
    return
}

$existing = Get-LocalUser -Name $LocalAdminUsername -ErrorAction SilentlyContinue

if ($existing) {
    Write-Host "Account '$LocalAdminUsername' already exists - not touching its password."
} else {
    $pw1 = Read-Host "Password for local account '$LocalAdminUsername' (input hidden)" -AsSecureString
    $pw2 = Read-Host "Confirm password" -AsSecureString
    $check1 = [System.Net.NetworkCredential]::new("", $pw1).Password
    $check2 = [System.Net.NetworkCredential]::new("", $pw2).Password

    if ($check1 -ne $check2) {
        Write-Warning "Passwords did not match - account NOT created. Re-run this step."
        return
    }
    if ([string]::IsNullOrWhiteSpace($check1)) {
        Write-Warning "Empty password entered - account NOT created."
        return
    }
    $check1 = $null; $check2 = $null  # done with the comparison copies

    New-LocalUser -Name $LocalAdminUsername -Password $pw1 `
        -PasswordNeverExpires -AccountNeverExpires -FullName "Blue Team Break-Glass Admin" | Out-Null
    Write-Host "Created local account '$LocalAdminUsername'."
    $pw1 = $null; $pw2 = $null
}

$members = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
if ($members.Name -match [regex]::Escape($LocalAdminUsername)) {
    Write-Host "Already in local Administrators group."
} else {
    Add-LocalGroupMember -Group "Administrators" -Member $LocalAdminUsername
    Write-Host "Added '$LocalAdminUsername' to local Administrators."
}

Write-Host "`nDone. This account is local-only - it won't survive a full reimage if gray team"
Write-Host "has to intervene and redeploy the box after something breaks badly."
Write-Host "Red team can see the same required-account list you can, so they'll recognize"
Write-Host "this as an extra account on sight. They can delete it without breaking any rule"
Write-Host "(it's not a required account). Its value is a fallback login, not concealment."
