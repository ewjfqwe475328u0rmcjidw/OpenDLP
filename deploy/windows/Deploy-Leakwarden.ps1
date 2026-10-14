#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Silent, idempotent Leakwarden agent deployment for many Windows PCs
  (Group Policy startup script, Intune platform script / Win32 app, RMM, PDQ, SCCM).
.DESCRIPTION
  Downloads the release package (or uses a local / UNC copy), verifies its SHA-256, installs the
  agent as a service with self-enrollment and the watchdog, and writes a log to
  %ProgramData%\Leakwarden\deploy.log. Machines that already run the requested version are skipped.
  Exit code 0 = installed or already up to date, 1 = failed (see the log).
.EXAMPLE
  .\Deploy-Leakwarden.ps1 -ServerUrl https://dlp.example.com -EnrollmentCode "CODE"
.EXAMPLE
  # Offline / LAN: copy the zip to a share once, no internet needed on the PCs
  .\Deploy-Leakwarden.ps1 -ServerUrl https://dlp.example.com -EnrollmentCode "CODE" `
      -PackagePath \\fileserver\it\Leakwarden-windows-x64-v0.13.0.zip -ExpectedSha256 <hash from SHA256SUMS.txt>
#>
param(
    [Parameter(Mandatory)][string]$ServerUrl,
    [Parameter(Mandatory)][string]$EnrollmentCode,
    [string]$Version = "v0.13.0",
    [string]$Repo = "leakwarden/leakwarden",
    [string]$PackagePath = "",
    [string]$ExpectedSha256 = "",
    [string[]]$SensitivePaths = @(),
    [string]$InstallDir = "C:\Program Files\Leakwarden",
    [switch]$Force
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # Invoke-WebRequest is very slow with the progress bar on PS 5.1
$logDir = Join-Path $env:ProgramData "Leakwarden"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir "deploy.log"
function Log([string]$m) { $line = "$(Get-Date -Format o) [$env:COMPUTERNAME] $m"; Add-Content -Path $log -Value $line; Write-Host $line }

$tmp = Join-Path $env:TEMP ("leakwarden-deploy-" + [guid]::NewGuid().ToString("N"))
try {
    $marker = Join-Path $InstallDir "installed-version.txt"
    if (-not $Force -and (Get-Service LeakwardenAgent -ErrorAction SilentlyContinue) -and (Test-Path $marker) -and
        ((Get-Content $marker -Raw).Trim() -eq $Version)) {
        Log "Leakwarden $Version already installed - nothing to do"
        exit 0
    }

    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    if (-not $PackagePath) {
        $name = "Leakwarden-windows-x64-$Version.zip"
        $base = "https://github.com/$Repo/releases/download/$Version"
        $PackagePath = Join-Path $tmp $name
        Log "Downloading $base/$name"
        Invoke-WebRequest -Uri "$base/$name" -OutFile $PackagePath -UseBasicParsing
        if (-not $ExpectedSha256) {
            $sumsFile = Join-Path $tmp "SHA256SUMS.txt"
            Invoke-WebRequest -Uri "$base/SHA256SUMS.txt" -OutFile $sumsFile -UseBasicParsing
            $entry = Get-Content $sumsFile | Where-Object { $_ -match "\s\*?$([regex]::Escape($name))$" } | Select-Object -First 1
            if (-not $entry) { throw "No checksum for $name in SHA256SUMS.txt" }
            $ExpectedSha256 = ($entry -split '\s+')[0]
        }
    }
    if (-not (Test-Path $PackagePath)) { throw "Package not found: $PackagePath" }

    if ($ExpectedSha256) {
        $actual = (Get-FileHash -Path $PackagePath -Algorithm SHA256).Hash
        if ($actual -ne $ExpectedSha256) { throw "Checksum mismatch for $PackagePath (expected $ExpectedSha256, got $actual)" }
        Log "Checksum verified"
    } else {
        Log "WARNING: no -ExpectedSha256 given for a local package; integrity not verified"
    }

    $pkg = Join-Path $tmp "pkg"
    Expand-Archive -Path $PackagePath -DestinationPath $pkg -Force
    $installer = Get-ChildItem -Path $pkg -Recurse -Filter "install-service.ps1" | Select-Object -First 1
    if (-not $installer) { throw "install-service.ps1 not found in package" }

    Log "Installing to $InstallDir"
    $installArgs = @{
        InstallDir = $InstallDir; ServerUrl = $ServerUrl; EnrollmentCode = $EnrollmentCode
        AgentId = $env:COMPUTERNAME; WithWatchdog = $true
    }
    if ($SensitivePaths.Count -gt 0) { $installArgs.SensitivePaths = $SensitivePaths }
    & $installer.FullName @installArgs | ForEach-Object { Log "  $_" }

    if ((Get-Service LeakwardenAgent).Status -ne "Running") { throw "Service LeakwardenAgent is not running after install" }
    Set-Content -Path $marker -Value $Version
    Log "Leakwarden $Version installed and running"
    exit 0
}
catch {
    Log "FAILED: $($_.Exception.Message)"
    exit 1
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
