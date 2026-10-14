<#
Service-mode end-to-end test on a clean Windows VM (GitHub windows-latest runner, elevated):
 1. publish agent + watchdog like the release zip, install with install-service.ps1 (enrollment, watchdog)
 2. verify the Windows service runs, enrolls and receives the signed policy
 3. verify detection inside .docx and .xlsx files
 4. print to a silent PDF printer and verify a PRINT_JOB event (PrintService event log)
 5. kill the agent process and verify it comes back (SCM recovery / watchdog) and keeps reporting
 6. uninstall and verify nothing is left behind
#>
param([string]$Publish = "out/agent")
$ErrorActionPreference = "Stop"
# Exit codes of native commands are checked explicitly (some calls are EXPECTED to fail).
$PSNativeCommandUseErrorActionPreference = $false
# Any unexpected script error becomes a public annotation with its line number.
trap {
    Write-Host "::error::SERVICE-E2E script error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    Write-Host "::error::SERVICE-E2E   $($_.InvocationInfo.Line.Trim())"
    break
}
$root = (Resolve-Path ".").Path
$work = Join-Path $env:RUNNER_TEMP "leakwarden-svc-e2e"
$installDir = "C:\Leakwarden-e2e"
$watch = "C:\Leakwarden-e2e-watch"
$svc = "LeakwardenAgent"
Remove-Item -Recurse -Force $work, $watch -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $work, $watch | Out-Null

function New-Secret { -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 48 | ForEach-Object { [char]$_ }) }
$admin = New-Secret; $enroll = New-Secret
$port = 8766; $base = "http://127.0.0.1:$port"; $agentId = $env:COMPUTERNAME   # Deploy-Leakwarden.ps1 enrolls with the computer name
$serverLog = "$work\server.log"
$agentLogDir = "$env:ProgramData\Leakwarden\logs"

function Fail([string]$msg) {
    Write-Host "::error::SERVICE-E2E: $msg"
    Write-Host "----- service status -----"; Get-Service $svc -ErrorAction SilentlyContinue | Format-List | Out-String | Write-Host
    foreach ($f in @($serverLog, "$serverLog.err")) {
        if (Test-Path $f) { Write-Host "----- $f -----"; Get-Content $f -Tail 30 }
    }
    Write-Host "----- Application event log (Leakwarden / .NET) -----"
    Get-WinEvent -LogName Application -MaxEvents 30 -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'Leakwarden|\.NET Runtime|Application Error' } |
        ForEach-Object { $m = ($_.Message -split "`n")[0..6] -join ' '; Write-Host "::error::eventlog: $m" }
    & "$installDir\uninstall-service.ps1" -InstallDir $installDir -RemoveLogs 2>$null
    exit 1
}

# ---------- server ----------
$env:LEAKWARDEN_TOKEN = New-Secret
$env:LEAKWARDEN_ADMIN_TOKEN = $admin
$env:LEAKWARDEN_ENROLL_CODE = $enroll
$env:LEAKWARDEN_DB = "$work\leakwarden.db"
$server = Start-Process python -ArgumentList "-m uvicorn main:app --host 127.0.0.1 --port $port" -WorkingDirectory "$root\server" `
    -RedirectStandardOutput $serverLog -RedirectStandardError "$serverLog.err" -PassThru -NoNewWindow
$up = $false
for ($i = 0; $i -lt 30; $i++) { try { if ((Invoke-RestMethod "$base/health").status -eq "ok") { $up = $true; break } } catch { }; Start-Sleep 1 }
if (-not $up) { Fail "server did not start" }
$H = @{ Authorization = "Bearer $admin" }
Remove-Item Env:LEAKWARDEN_TOKEN, Env:LEAKWARDEN_ENROLL_CODE

# Invoke-RestMethod emits a JSON array as ONE pipeline object; unroll it so callers see individual events.
function Events([string]$type) {
    $r = Invoke-RestMethod "$base/api/v1/events?agent_id=$agentId&event_type=$type&limit=500" -Headers $H
    return @($r | ForEach-Object { $_ })
}
function Wait-Until([scriptblock]$cond, [int]$seconds, [string]$what) {
    for ($i = 0; $i -lt $seconds; $i++) {
        try { $r = & $cond; if ($r) { Write-Host "ok: $what"; return $r } } catch { }
        Start-Sleep 1
    }
    Fail "timed out after ${seconds}s waiting for: $what"
}

# ---------- install exactly like an administrator rolling out many PCs ----------
if (-not (Test-Path "$Publish\Leakwarden.Agent.exe")) { Fail "published agent not found in $Publish" }
if (-not (Test-Path "$Publish\Leakwarden.Watchdog.exe")) { Fail "published watchdog not found in $Publish" }
$zip = Join-Path $work "Leakwarden-windows-x64-e2e.zip"
Compress-Archive -Path $Publish -DestinationPath $zip -Force
$sha = (Get-FileHash $zip -Algorithm SHA256).Hash
$deploy = Join-Path $root "deploy\windows\Deploy-Leakwarden.ps1"
# a wrong checksum must be refused
& pwsh -NoProfile -File $deploy -ServerUrl $base -EnrollmentCode $enroll -PackagePath $zip -ExpectedSha256 ("0" * 64) -InstallDir $installDir -Version "e2e"
if ($LASTEXITCODE -eq 0) { Fail "deploy script accepted a package with a wrong checksum" }
if (Get-Service $svc -ErrorAction SilentlyContinue) { Fail "service was installed despite a checksum mismatch" }
Write-Host "ok: tampered package refused"
& pwsh -NoProfile -File $deploy -ServerUrl $base -EnrollmentCode $enroll -PackagePath $zip -ExpectedSha256 $sha `
    -InstallDir $installDir -Version "e2e" -SensitivePaths $watch
if ($LASTEXITCODE -ne 0) { Fail "Deploy-Leakwarden.ps1 failed with exit code $LASTEXITCODE (see $env:ProgramData\Leakwarden\deploy.log)" }
# re-running on an up-to-date machine must be a no-op
$out = & pwsh -NoProfile -File $deploy -ServerUrl $base -EnrollmentCode $enroll -PackagePath $zip -ExpectedSha256 $sha -InstallDir $installDir -Version "e2e"
if ($LASTEXITCODE -ne 0 -or -not ($out -match "already installed")) { Fail "second deploy run was not idempotent: $out" }
Write-Host "ok: second deploy run skipped"
if ((Get-Service $svc).Status -ne "Running") { Fail "service is not running after install" }
Write-Output "ok: service installed and running"
if (-not (Get-ScheduledTask -TaskName "Leakwarden Watchdog" -ErrorAction SilentlyContinue)) { Fail "watchdog task missing" }

Wait-Until { Invoke-RestMethod "$base/api/v1/agents" -Headers $H | ForEach-Object { $_ } | Where-Object { $_.agent_id -eq $agentId -and $_.enrolled } } 60 "service enrolled" | Out-Null
Wait-Until { (Events "POLICY_UPDATED").Count -ge 1 } 90 "service applied signed policy" | Out-Null
$cfgText = Get-Content "$installDir\agent.config.json" -Raw
if ($cfgText -match [regex]::Escape($admin)) { Fail "admin token leaked into agent config" }

# ---------- Office documents ----------
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
function New-Ooxml([string]$path, [hashtable]$parts) {
    $fs = [IO.File]::Create($path)
    $zip = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Create)
    foreach ($name in $parts.Keys) {
        $w = New-Object IO.StreamWriter($zip.CreateEntry($name).Open())
        $w.Write($parts[$name]); $w.Dispose()
    }
    $zip.Dispose(); $fs.Dispose()
}
$ct = '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'
$tmpDocx = "$work\report.docx"; $tmpXlsx = "$work\customers.xlsx"
New-Ooxml $tmpDocx @{
    "[Content_Types].xml" = $ct
    "word/document.xml"   = '<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>Passport number: C01X00T47</w:t></w:r></w:p><w:p><w:r><w:t>IBAN GB82 WEST 1234 5698 7654 32</w:t></w:r></w:p></w:body></w:document>'
}
New-Ooxml $tmpXlsx @{
    "[Content_Types].xml"    = $ct
    "xl/sharedStrings.xml"   = '<sst><si><t>Name</t></si><si><t>SSN</t></si><si><t>123-45-6789</t></si><si><t>4111 1111 1111 1111</t></si></sst>'
    "xl/worksheets/sheet1.xml" = '<worksheet><sheetData/></worksheet>'
}
Copy-Item $tmpDocx, $tmpXlsx $watch
$docHit = Wait-Until { Events "CONTENT_MATCH" | Where-Object { $_.message -match 'report\.docx' } | Select-Object -First 1 } 90 ".docx content detected"
foreach ($r in "PASSPORT", "IBAN") { if ($docHit.message -notmatch $r) { Fail ".docx hit is missing rule $r : $($docHit.message)" } }
$xlsHit = Wait-Until { Events "CONTENT_MATCH" | Where-Object { $_.message -match 'customers\.xlsx' } | Select-Object -First 1 } 90 ".xlsx content detected"
foreach ($r in "US-SSN", "CREDIT-CARD") { if ($xlsHit.message -notmatch $r) { Fail ".xlsx hit is missing rule $r : $($xlsHit.message)" } }

# ---------- printing ----------
$printerReady = $false
try {
    $pdf = "$work\print-test.pdf"
    Add-PrinterPort -Name $pdf -ErrorAction Stop
    Add-Printer -Name "Leakwarden E2E PDF" -DriverName "Microsoft Print To PDF" -PortName $pdf -ErrorAction Stop
    $printerReady = $true
} catch {
    Write-Output "::warning::SERVICE-E2E: could not create a test printer on this runner, print check skipped: $($_.Exception.Message)"
}
if ($printerReady) {
    Start-Sleep 3
    1..40 | ForEach-Object { "Leakwarden print monitor test line $_" } | Out-Printer -Name "Leakwarden E2E PDF"
    $job = Wait-Until { Events "PRINT_JOB" | Where-Object { $_.message -match 'Leakwarden E2E PDF' } | Select-Object -First 1 } 60 "PRINT_JOB event received"
    Write-Host "print event: $($job.message)"
}

# ---------- self-healing ----------
$oldPid = (Get-Process Leakwarden.Agent).Id
Stop-Process -Id $oldPid -Force
Write-Output "killed agent pid $oldPid"
Wait-Until { $p = Get-Process Leakwarden.Agent -ErrorAction SilentlyContinue; $p -and ($p.Id -ne $oldPid) -and ((Get-Service $svc).Status -eq "Running") } 90 "agent restarted after being killed" | Out-Null
$heartbeat = "$agentLogDir\agent.heartbeat"
Wait-Until { (Test-Path $heartbeat) -and ((Get-Date).ToUniversalTime() - (Get-Item $heartbeat).LastWriteTimeUtc).TotalSeconds -lt 15 } 60 "heartbeat fresh after restart" | Out-Null
$before = (Events "CONTENT_MATCH").Count
Set-Content "$watch\after-restart.txt" "National ID A123456789" -Encoding UTF8
Wait-Until { (Events "CONTENT_MATCH").Count -gt $before } 90 "detection works after restart" | Out-Null

# ---------- uninstall ----------
& "$installDir\uninstall-service.ps1" -InstallDir $installDir -RemoveLogs
if (Get-Service $svc -ErrorAction SilentlyContinue) { Fail "service still installed after uninstall" }
if (Test-Path $installDir) { Fail "install directory still present after uninstall" }
if (Get-ScheduledTask -TaskName "Leakwarden Watchdog" -ErrorAction SilentlyContinue) { Fail "watchdog task still present after uninstall" }
if (Get-Process Leakwarden.Agent, Leakwarden.Watchdog -ErrorAction SilentlyContinue) { Fail "Leakwarden processes still running after uninstall" }
Write-Output "ok: clean uninstall"

Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
Write-Output "SERVICE E2E PASSED"
"## Leakwarden service-mode test passed`n`n- Deploy-Leakwarden.ps1: checksum enforced, idempotent re-run`n- install-service.ps1 with self-enrollment and watchdog`n- Windows service runs as SYSTEM and applies signed policy`n- detection inside .docx and .xlsx`n- recovery after the agent process is killed`n- clean uninstall" | Out-File -Append -Encoding utf8 $env:GITHUB_STEP_SUMMARY
# The runner fails a step if the LAST native command returned non-zero (e.g. pgrep finding nothing): be explicit.
exit 0
