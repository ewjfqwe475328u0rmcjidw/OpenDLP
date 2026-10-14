#Requires -RunAsAdministrator
param([string]$ServiceName = "LeakwardenAgent", [string]$InstallDir = "C:\Program Files\Leakwarden", [switch]$RemoveLogs)
$ErrorActionPreference = "SilentlyContinue"
# Stop the watchdog first so it does not restart the service while we remove it.
Stop-ScheduledTask -TaskName "Leakwarden Watchdog"
Unregister-ScheduledTask -TaskName "Leakwarden Watchdog" -Confirm:$false
Get-Process Leakwarden.Watchdog | Stop-Process -Force
Unregister-ScheduledTask -TaskName "Leakwarden Helper" -Confirm:$false
Stop-Service $ServiceName -Force
sc.exe delete $ServiceName | Out-Null
Get-Process Leakwarden.Agent | Stop-Process -Force
Start-Sleep -Seconds 2
Remove-Item -Recurse -Force $InstallDir
if ($RemoveLogs) { Remove-Item -Recurse -Force "$env:ProgramData\Leakwarden" }
if (Get-Service $ServiceName) { Write-Warning "Service $ServiceName still present (a reboot may be required)."; exit 1 }
Write-Host "Leakwarden removed."
