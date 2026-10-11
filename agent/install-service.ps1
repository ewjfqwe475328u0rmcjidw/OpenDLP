#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs the OpenDLP Agent as a Windows service. Run from the extracted release zip in an elevated PowerShell.
.EXAMPLE
  .\install-service.ps1 -ServerUrl https://dlp.example.com -EnrollmentCode "paste-code-from-admin" -WithWatchdog
.EXAMPLE
  .\install-service.ps1 -ServerUrl https://dlp.example.com -EnrollmentCode "..." -SensitivePaths "D:\Finance","{AllUsers}\Documents"
.NOTES
  Works on Windows PowerShell 5.1 and PowerShell 7, on any Windows display language.
  If an agent.config.json sits next to this script it is used as-is; otherwise one is generated from the parameters.
#>
param(
    [string]$InstallDir = "C:\Program Files\OpenDLP",
    [string]$ServiceName = "OpenDLPAgent",
    [string]$ServerUrl = "",
    [string]$EnrollmentCode = "",
    [string]$AgentId = $env:COMPUTERNAME,
    [string]$DisplayName = "",
    [string[]]$SensitivePaths = @(),
    [switch]$WithWatchdog
)
$ErrorActionPreference = "Stop"
$src = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Test-Path (Join-Path $src "OpenDLP.Agent.exe"))) {
    throw "OpenDLP.Agent.exe not found next to this script. Run it from the extracted release zip or a 'dotnet publish' output."
}

# ---- 1. build the configuration in memory (never leave a copy with secrets in the download folder) ----
$srcCfg = Join-Path $src "agent.config.json"
if (Test-Path $srcCfg) {
    $cfgJson = Get-Content $srcCfg -Raw
} else {
    if (-not $ServerUrl -or -not $EnrollmentCode) {
        throw "Pass -ServerUrl and -EnrollmentCode (recommended), or put an edited agent.config.json next to this script."
    }
    $cfg = Get-Content (Join-Path $src "agent.config.example.json") -Raw | ConvertFrom-Json
    $cfg.ServerUrl = $ServerUrl
    $cfg.EnrollmentCode = $EnrollmentCode
    $cfg.AgentId = $AgentId
    $cfg.DisplayName = $DisplayName
    $cfg.TelemetryEnabled = $true
    if ($SensitivePaths.Count -gt 0) { $cfg.SensitivePaths = $SensitivePaths }
    $cfgJson = $cfg | ConvertTo-Json -Depth 5
}

# ---- 2. stop a previous installation so its files are not locked ----
if (Get-ScheduledTask -TaskName "OpenDLP Watchdog" -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName "OpenDLP Watchdog" -ErrorAction SilentlyContinue
}
Get-Process OpenDLP.Watchdog -ErrorAction SilentlyContinue | Stop-Process -Force
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 3
}
Get-Process OpenDLP.Agent -ErrorAction SilentlyContinue | Stop-Process -Force

# ---- 3. copy files and write the config ----
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Get-ChildItem $src | Where-Object { $_.Name -ne "agent.config.json" } |
    Copy-Item -Destination $InstallDir -Recurse -Force
$cfgInstalled = Join-Path $InstallDir "agent.config.json"
[IO.File]::WriteAllText($cfgInstalled, $cfgJson, (New-Object System.Text.UTF8Encoding($false)))

# ---- 4. permissions (well-known SIDs: account names are localized on non-English Windows) ----
function New-Rule([string]$sid, [string]$rights, [string]$inherit) {
    $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
    New-Object System.Security.AccessControl.FileSystemAccessRule($id, $rights, $inherit, "None", "Allow")
}
$SYSTEM = "S-1-5-18"; $ADMINS = "S-1-5-32-544"; $USERS = "S-1-5-32-545"

# Install folder: SYSTEM/admins full control; ordinary users may only read and run the binaries
# (the per-user clipboard helper runs as the logged-on user).
$acl = Get-Acl $InstallDir
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Rule $SYSTEM "FullControl" "ContainerInherit,ObjectInherit"))
$acl.AddAccessRule((New-Rule $ADMINS "FullControl" "ContainerInherit,ObjectInherit"))
$acl.AddAccessRule((New-Rule $USERS "ReadAndExecute" "ContainerInherit,ObjectInherit"))
Set-Acl $InstallDir $acl

# Config (server URL, enrollment code / token): SYSTEM and admins only.
$cacl = Get-Acl $cfgInstalled
$cacl.SetAccessRuleProtection($true, $false)
$cacl.AddAccessRule((New-Rule $SYSTEM "FullControl" "None"))
$cacl.AddAccessRule((New-Rule $ADMINS "FullControl" "None"))
Set-Acl $cfgInstalled $cacl

# ---- 5. service ----
$exe = Join-Path $InstallDir "OpenDLP.Agent.exe"
# New-Service quotes the path correctly on both PowerShell 5.1 and 7 (paths with spaces).
New-Service -Name $ServiceName -BinaryPathName "`"$exe`" --mode service" -DisplayName "OpenDLP Endpoint Agent" `
    -Description "OpenDLP open-source endpoint audit/detection agent" -StartupType Automatic | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
Start-Service $ServiceName

# ---- 6. optional watchdog (restarts the service if it stops or hangs) ----
if ($WithWatchdog -and (Test-Path (Join-Path $InstallDir "OpenDLP.Watchdog.exe"))) {
    $wd = Join-Path $InstallDir "OpenDLP.Watchdog.exe"
    $action = New-ScheduledTaskAction -Execute $wd -Argument "--service $ServiceName"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName "OpenDLP Watchdog" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName "OpenDLP Watchdog"
}

# ---- 7. per-user clipboard helper at logon ----
$helperAction = New-ScheduledTaskAction -Execute $exe -Argument "--mode helper"
$helperTrigger = New-ScheduledTaskTrigger -AtLogOn
$helperPrincipal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited
Register-ScheduledTask -TaskName "OpenDLP Helper" -Action $helperAction -Trigger $helperTrigger -Principal $helperPrincipal -Force | Out-Null

Write-Host "Installed. Service '$ServiceName' status: $((Get-Service $ServiceName).Status)"
Write-Host "Logs: $env:ProgramData\OpenDLP\logs   Uninstall: & '$InstallDir\uninstall-service.ps1'"
