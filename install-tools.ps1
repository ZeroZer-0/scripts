# install-tools.ps1
# Run ONCE at setup, as early as possible, while internet access is
# confirmed working. Red team may cut egress later - this is not something
# to rely on mid-competition, so don't re-run this expecting it to work.
#
# This only STAGES tools. It doesn't run any scan itself - see
# autoruns-scan.ps1 for that.

. "$PSScriptRoot\config.ps1"

$ErrorActionPreference = "Stop"

# Force TLS 1.2 explicitly. Server 2019 defaults to it, but don't assume -
# if anything else in your hardening touches SChannel/cipher policy, a
# silent TLS negotiation failure here is a bad way to find out.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-Section($msg) {
    Write-Host "`n=== $msg ===" -ForegroundColor Cyan
}

if (-not (Test-Path $ToolsDir)) {
    New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
}

# --- Sysinternals Autoruns ---
Write-Section "Fetching Autoruns"

$autorunsZip = Join-Path $ToolsDir "Autoruns.zip"
$autorunscExe = Join-Path $ToolsDir "autorunsc64.exe"

if (Test-Path $autorunscExe) {
    Write-Host "Already staged at $autorunscExe - skipping download."
} else {
    try {
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Autoruns.zip" -OutFile $autorunsZip -UseBasicParsing
        Expand-Archive -Path $autorunsZip -DestinationPath $ToolsDir -Force
        Remove-Item $autorunsZip -Force
    } catch {
        Write-Warning "Download failed: $($_.Exception.Message)"
        Write-Warning "If internet access is already gone, this needs to come in via RustDesk file transfer instead."
        return
    }
}

# --- Verify it's actually Microsoft-signed before trusting it ---
# This matters specifically because we just pulled a binary over the network
# during a competition where a hostile team is on the same infrastructure.
# Don't skip this check.
Write-Section "Verifying signature"

if (-not (Test-Path $autorunscExe)) {
    Write-Warning "autorunsc64.exe not found after extraction - check $ToolsDir contents manually."
    return
}

$sig = Get-AuthenticodeSignature -FilePath $autorunscExe

if ($sig.Status -eq "Valid" -and $sig.SignerCertificate.Subject -match "Microsoft Corporation") {
    Write-Host "OK: signed by Microsoft, signature valid." -ForegroundColor Green
} else {
    Write-Warning "SIGNATURE CHECK FAILED - status: $($sig.Status), signer: $($sig.SignerCertificate.Subject)"
    Write-Warning "Do not use this binary. Delete $ToolsDir and get a clean copy, or verify manually before running anything."
    return
}

Write-Section "Done"
Write-Host "Staged at $ToolsDir - run autoruns-scan.ps1 to use it."
