# config.ps1
# Fill this in on setup day. Nothing in harden.ps1 or healthcheck.ps1
# should need editing - only this file.
#
# This file does NOT store the sa or local-admin passwords - those are
# prompted for interactively (masked input) by harden.ps1 and
# create-local-admin.ps1 so they never sit in a file on disk. Still safe
# to commit a filled-in version of this file as-is, but double-check
# nothing else sensitive gets added here later before you do.

# --- Accounts ---
# The account the scorebot/gray team uses to check the service.
# NEVER disable, lock, or change the password on this one without
# confirming with gray team first - rule 13 says blue team cannot
# delete required users. You mentioned you likely won't get this account -
# if it stays unset, healthcheck.ps1 just won't be usable, rely on the
# competition scoreboard instead. Everything else here works without it.
$ScoringAccount = "CHANGEME_scoring_user"

# sa account - not deleting it, just locking down the password.
# The password is NOT stored here anymore - harden.ps1 prompts for it
# interactively (masked input) so it never sits in a file on disk.
# Have it written down/saved somewhere off this box before running harden.ps1.

# Any known-good admin/sysadmin logins that SHOULD have sysadmin role.
# Anything else showing up in the sysadmin role audit is suspicious.
# The four packet admin accounts are the expected sysadmins - the six
# CT accounts should NOT have sysadmin. If that assumption is wrong once
# you see the real box, fix this list on setup day.
$KnownSysadminLogins = @(
    "sa"
    "Commander Cody"
    "Commander Wolffe"
    "Captain Rex"
    "Captain Gregor"
)

# --- Accounts from the competition packet ---
# Names as printed in the packet. audit-accounts.ps1 ignores case, spaces,
# and domain prefixes when comparing, but the real logon names may differ
# (e.g. "ccody" instead of "Commander Cody"). Run the audit on setup day and
# fix any names that show up as UNKNOWN.
$PacketAdmins = @("Commander Cody", "Commander Wolffe", "Captain Rex", "Captain Gregor")
$PacketUsers  = @("CT Fives", "CT Echo", "CT Jesse", "CT 99", "CT Hevy", "CT Tup")

# OFF LIMITS (rule 3). Never modify or delete these.
$GreyTeamAccounts = @("realgreyteam", "dontdeletegreyteam", "grayteam")

# Accounts that are normal on a Windows/SQL box and not worth flagging.
$BuiltinNames = @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount", "sa", "Domain Admins", "Enterprise Admins")
$BuiltinRawPatterns = @('^NT SERVICE\\', '^NT AUTHORITY\\', '^BUILTIN\\', '^##MS_', '\\SQLServer2005SQLBrowserUser')

# --- Local break-glass admin ---
# A local account, separate from the domain, so you still have admin
# access if AD goes offline or gets attacked. NOT a required competition
# account - red team can see the same required-account list you can, so
# they know exactly which accounts are supposed to exist. Any extra local
# account is immediately identifiable as something blue team added,
# whatever it's named - the name buys you nothing. What actually matters:
# a strong password that isn't shared with sa or the domain accounts, so
# finding this account doesn't also hand over something else.
#
# Red team deleting this wouldn't break rule 13 (only the 10 required
# accounts are protected) - treat it as a fallback, not guaranteed access.
$LocalAdminUsername = "blueadmin"
# Password is NOT stored here - create-local-admin.ps1 prompts for it
# interactively (masked input) so it never sits in a file on disk.

# --- Network ---
# MSSQL default port. Only change if gray team's setup uses something else.
$MSSQLPort = 1433

# Specific source IPs allowed to hit MSSQL (scorebot, gray team, legit admin).
# Per competition rule 12: no firewall rules for entire subnets/ranges.
# Only add specific /32 hosts here, not ranges.
$AllowedSourceIPs = @(
    "CHANGEME_scorebot_ip"
    # "CHANGEME_gray_team_ip"
)

# --- Paths ---
# Where we back up original config before touching anything (rule 15).
$BackupDir = "C:\CompBackups"

# Where third-party tools (Autoruns, etc.) get staged. Downloaded once at
# setup while internet access is confirmed working - don't rely on this
# working again later if red team cuts egress.
$ToolsDir = "C:\CompTools"

# --- Behavior toggles ---
# Set to $true only once you've confirmed with gray team that disabling
# xp_cmdshell won't break a scored check. It's a common red-team pivot,
# but some competitions expect it to stay enabled for legit remote exec checks.
$DisableXpCmdshell = $true
