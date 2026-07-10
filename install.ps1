$ErrorActionPreference = 'Stop'

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($currentIdentity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    throw 'Run this script from an elevated PowerShell window.'
}

$source = Join-Path $PSScriptRoot 'OFT.Platform.Core.patched.dll'
$installDir = 'C:\Program Files\ATAS X'
$target = Join-Path $installDir 'OFT.Platform.Core.dll'

if (-not (Test-Path -LiteralPath $source)) {
    throw "Patched DLL not found at $source"
}

if (-not (Test-Path -LiteralPath $installDir)) {
    throw "Install directory not found at $installDir"
}

$running = Get-Process -Name 'OFT.PlatformX' -ErrorAction SilentlyContinue
if ($running) {
    throw 'Close ATAS X before installing the patch.'
}

if (Test-Path -LiteralPath $target) {
    $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash
    $targetHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash
    if ($sourceHash -eq $targetHash) {
        Write-Host "Already installed: $target"
        return
    }
}

Copy-Item -LiteralPath $source -Destination $target -Force

Write-Host "Installed patched DLL to $target"
