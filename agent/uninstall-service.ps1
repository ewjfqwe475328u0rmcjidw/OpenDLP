#Requires -RunAsAdministrator
param([string]$ServiceName = "OpenDLPAgent", [string]$InstallDir = "C:\Program Files\OpenDLP", [switch]$RemoveLogs)
$ErrorActionPreference = "SilentlyContinue"
Stop-Service $ServiceName -Force
sc.exe delete $ServiceName | Out-Null
Unregister-ScheduledTask -TaskName "OpenDLP Watchdog" -Confirm:$false
Unregister-ScheduledTask -TaskName "OpenDLP Helper" -Confirm:$false
Get-Process OpenDLP.Agent, OpenDLP.Watchdog | Stop-Process -Force
Remove-Item -Recurse -Force $InstallDir
if ($RemoveLogs) { Remove-Item -Recurse -Force "$env:ProgramData\OpenDLP" }
Write-Host "OpenDLP removed."
