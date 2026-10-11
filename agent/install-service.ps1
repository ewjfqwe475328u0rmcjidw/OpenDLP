#Requires -RunAsAdministrator
<#
.SYNOPSIS  Installs the OpenDLP Agent as a Windows Service (prototype installer — test on a disposable machine first).
.EXAMPLE   .\install-service.ps1 -ServerUrl https://dlp.example.com -EnrollmentCode "paste-code-from-admin"
#>
param(
    [string]$InstallDir = "C:\Program Files\OpenDLP",
    [string]$ServiceName = "OpenDLPAgent",
    [string]$ServerUrl = "",
    [string]$EnrollmentCode = "",
    [string]$AgentId = $env:COMPUTERNAME,
    [string]$DisplayName = "",
    [switch]$WithWatchdog
)
$ErrorActionPreference = "Stop"
$src = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Test-Path (Join-Path $src "OpenDLP.Agent.exe"))) {
    throw "OpenDLP.Agent.exe not found next to this script. Run it from the extracted release zip (agent folder) or a 'dotnet publish' output."
}
$cfgPath = Join-Path $src "agent.config.json"
if (-not (Test-Path $cfgPath)) {
    if (-not $ServerUrl -or -not $EnrollmentCode) {
        throw "No agent.config.json found. Either pass -ServerUrl and -EnrollmentCode (recommended), or copy agent.config.example.json to agent.config.json and edit it."
    }
    $cfg = Get-Content (Join-Path $src "agent.config.example.json") -Raw | ConvertFrom-Json
    $cfg.ServerUrl = $ServerUrl
    $cfg.EnrollmentCode = $EnrollmentCode
    $cfg.AgentId = $AgentId
    $cfg.DisplayName = $DisplayName
    $cfg.TelemetryEnabled = $true
    $cfg | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $cfgPath
    Write-Host "Wrote agent.config.json (the enrollment code is exchanged for a per-machine token on first start and stored encrypted with DPAPI)."
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Path (Join-Path $src "*") -Destination $InstallDir -Recurse -Force

# Lock down the install dir (config contains the API token unless OPENDLP_TOKEN is used): SYSTEM + Administrators only.
$acl = Get-Acl $InstallDir
$acl.SetAccessRuleProtection($true, $false)
foreach ($id in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators")) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($rule)
}
Set-Acl $InstallDir $acl

$exe = Join-Path $InstallDir "OpenDLP.Agent.exe"
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}
sc.exe create $ServiceName binPath= "`"$exe`" --mode service" start= auto DisplayName= "OpenDLP Endpoint Agent" | Out-Null
sc.exe description $ServiceName "OpenDLP open-source endpoint audit/detection agent (experimental)" | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
Start-Service $ServiceName

if ($WithWatchdog -and (Test-Path (Join-Path $InstallDir "OpenDLP.Watchdog.exe"))) {
    $wd = Join-Path $InstallDir "OpenDLP.Watchdog.exe"
    $action = New-ScheduledTaskAction -Execute $wd -Argument "--agent `"$exe`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName "OpenDLP Watchdog" -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest -Force | Out-Null
}

# Per-user helper (clipboard monitor) starts at logon for every user.
$helperAction = New-ScheduledTaskAction -Execute $exe -Argument "--mode helper"
$helperTrigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "OpenDLP Helper" -Action $helperAction -Trigger $helperTrigger -GroupId "BUILTIN\Users" -Force | Out-Null

Write-Host "Installed. Service '$ServiceName' status: $((Get-Service $ServiceName).Status)"
Write-Host "Logs: $env:ProgramData\OpenDLP\logs   Uninstall: .\uninstall-service.ps1"
