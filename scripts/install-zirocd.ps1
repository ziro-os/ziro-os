# Installs zirocd on Windows (amd64, arm64) from the tools release stream and starts its service.
# Run in an elevated PowerShell:
#   irm https://raw.githubusercontent.com/ziro-os/ziro-os/main/scripts/install-zirocd.ps1 | iex
# The zip must match the release's SHA256SUMS (fetched over HTTPS from GitHub). Every later
# update is verified by zirocd itself against the ed25519 release signature.
$ErrorActionPreference = 'Stop'
$repo = 'ziro-os/ziro-os'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this in an elevated (Administrator) PowerShell.'
}
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$version = $env:ZIROCD_VERSION
if (-not $version) {
    $refs = Invoke-RestMethod "https://api.github.com/repos/$repo/git/matching-refs/tags/tools/v"
    $version = ($refs | ForEach-Object { if ($_.ref -match '^refs/tags/tools/v(\d+\.\d+\.\d+)$') { [version]$Matches[1] } } |
        Sort-Object | Select-Object -Last 1).ToString()
}
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw "no zirocd release found" }
$base = "https://github.com/$repo/releases/download/tools/v$version"
$zip = "zirocd-windows-$arch.zip"
$tmp = Join-Path $env:TEMP ("zirocd-" + [guid]::NewGuid())
New-Item -ItemType Directory $tmp | Out-Null
try {
    Write-Host "Downloading zirocd $version (windows/$arch)..."
    Invoke-WebRequest "$base/$zip" -OutFile "$tmp\$zip" -UseBasicParsing
    Invoke-WebRequest "$base/SHA256SUMS" -OutFile "$tmp\SHA256SUMS" -UseBasicParsing
    $want = (Get-Content "$tmp\SHA256SUMS" | Where-Object { $_ -match "^([0-9a-f]{64})\s+\*?$([regex]::Escape($zip))$" } | ForEach-Object { $Matches[1] })
    $got = (Get-FileHash "$tmp\$zip" -Algorithm SHA256).Hash.ToLower()
    if (-not $want -or $want -ne $got) { throw "$zip does not match SHA256SUMS" }
    Write-Host "checksum verified"
    $dest = Join-Path $env:ProgramFiles 'Ziro'
    New-Item -ItemType Directory -Force $dest | Out-Null
    if (Get-Service zirocd -ErrorAction SilentlyContinue) { Stop-Service zirocd -Force }
    Expand-Archive "$tmp\$zip" -DestinationPath $dest -Force
    & "$dest\zirocd.exe" service install
    if ($LASTEXITCODE -ne 0) { throw 'service install failed' }
    Write-Host "Join a network:  & '$dest\zirocd.exe' up --key zr1_..."
} finally {
    Remove-Item -Recurse -Force $tmp
}
