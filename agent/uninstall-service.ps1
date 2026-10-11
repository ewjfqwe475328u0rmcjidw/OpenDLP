#Requires -RunAsAdministrator
param([string]$ServiceName = "OpenDLPAgent", [string]$InstallDir = "C:\Program Files\OpenDLP", [switch]$RemoveLogs)
$ErrorActionPreference = "SilentlyContinue"
# Stop the watchdog first so it does not restart the service while we remove it.
Stop-ScheduledTask -TaskName "OpenDLP Watchdog"
Unregister-ScheduledTask -TaskName "OpenDLP Watchdog" -Confirm:$false
Get-Process OpenDLP.Watchdog | Stop-Process -Force
Unregister-ScheduledTask -TaskName "OpenDLP Helper" -Confirm:$false
Stop-Service $ServiceName -Force
sc.exe delete $ServiceName | Out-Null
Get-Process OpenDLP.Agent | Stop-Process -Force
Start-Sleep -Seconds 2
Remove-Item -Recurse -Force $InstallDir
if ($RemoveLogs) { Remove-Item -Recurse -Force "$env:ProgramData\OpenDLP" }
if (Get-Service $ServiceName) { Write-Warning "Service $ServiceName still present (a reboot may be required)."; exit 1 }
Write-Host "OpenDLP removed."
