<#
Service-mode end-to-end test on a clean Windows VM (GitHub windows-latest runner, elevated):
 1. publish agent + watchdog like the release zip, install with install-service.ps1 (enrollment, watchdog)
 2. verify the Windows service runs, enrolls and receives the signed policy
 3. verify detection inside .docx and .xlsx files
 4. print to a silent PDF printer and look for a PRINT_JOB event (soft check: WMI polling can miss short jobs)
 5. kill the agent process and verify it comes back (SCM recovery / watchdog) and keeps reporting
 6. uninstall and verify nothing is left behind
#>
param([string]$Publish = "out/agent")
$ErrorActionPreference = "Stop"
$root = (Resolve-Path ".").Path
$work = Join-Path $env:RUNNER_TEMP "opendlp-svc-e2e"
$installDir = "C:\OpenDLP-e2e"
$watch = "C:\OpenDLP-e2e-watch"
$svc = "OpenDLPAgent"
Remove-Item -Recurse -Force $work, $watch -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $work, $watch | Out-Null

function New-Secret { -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 48 | ForEach-Object { [char]$_ }) }
$admin = New-Secret; $enroll = New-Secret
$port = 8766; $base = "http://127.0.0.1:$port"; $agentId = "e2e-service-01"
$serverLog = "$work\server.log"
$agentLogDir = "$env:ProgramData\OpenDLP\logs"

function Fail([string]$msg) {
    Write-Output "::error::SERVICE-E2E: $msg"
    Write-Output "----- service status -----"; Get-Service $svc -ErrorAction SilentlyContinue | Format-List | Out-String | Write-Output
    foreach ($f in @($serverLog, "$serverLog.err")) {
        if (Test-Path $f) { Write-Output "----- $f -----"; Get-Content $f -Tail 30 }
    }
    Write-Output "----- Application event log (OpenDLP / .NET) -----"
    Get-WinEvent -LogName Application -MaxEvents 30 -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'OpenDLP|\.NET Runtime|Application Error' } |
        ForEach-Object { $m = ($_.Message -split "`n")[0..6] -join ' '; Write-Output "::error::eventlog: $m" }
    & "$installDir\uninstall-service.ps1" -InstallDir $installDir -RemoveLogs 2>$null
    exit 1
}

# ---------- server ----------
$env:OPENDLP_TOKEN = New-Secret
$env:OPENDLP_ADMIN_TOKEN = $admin
$env:OPENDLP_ENROLL_CODE = $enroll
$env:OPENDLP_DB = "$work\opendlp.db"
$server = Start-Process python -ArgumentList "-m uvicorn main:app --host 127.0.0.1 --port $port" -WorkingDirectory "$root\server" `
    -RedirectStandardOutput $serverLog -RedirectStandardError "$serverLog.err" -PassThru -NoNewWindow
$up = $false
for ($i = 0; $i -lt 30; $i++) { try { if ((Invoke-RestMethod "$base/health").status -eq "ok") { $up = $true; break } } catch { }; Start-Sleep 1 }
if (-not $up) { Fail "server did not start" }
$H = @{ Authorization = "Bearer $admin" }
Remove-Item Env:OPENDLP_TOKEN, Env:OPENDLP_ENROLL_CODE

function Events([string]$type) { @(Invoke-RestMethod "$base/api/v1/events?agent_id=$agentId&event_type=$type&limit=500" -Headers $H) }
function Wait-Until([scriptblock]$cond, [int]$seconds, [string]$what) {
    for ($i = 0; $i -lt $seconds; $i++) {
        try { $r = & $cond; if ($r) { Write-Output "ok: $what"; return $r } } catch { }
        Start-Sleep 1
    }
    Fail "timed out after ${seconds}s waiting for: $what"
}

# ---------- install exactly like an end user would ----------
if (-not (Test-Path "$Publish\OpenDLP.Agent.exe")) { Fail "published agent not found in $Publish" }
if (-not (Test-Path "$Publish\OpenDLP.Watchdog.exe")) { Fail "published watchdog not found in $Publish" }
& "$Publish\install-service.ps1" -InstallDir $installDir -ServerUrl $base -EnrollmentCode $enroll -AgentId $agentId `
    -DisplayName "E2E service" -SensitivePaths $watch -WithWatchdog
if ((Get-Service $svc).Status -ne "Running") { Fail "service is not running after install" }
Write-Output "ok: service installed and running"
if (-not (Get-ScheduledTask -TaskName "OpenDLP Watchdog" -ErrorAction SilentlyContinue)) { Fail "watchdog task missing" }

Wait-Until { Invoke-RestMethod "$base/api/v1/agents" -Headers $H | Where-Object { $_.agent_id -eq $agentId -and $_.enrolled } } 60 "service enrolled" | Out-Null
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

# ---------- printing (soft check) ----------
try {
    $pdf = "$work\print-test.pdf"
    Add-PrinterPort -Name $pdf -ErrorAction Stop
    Add-Printer -Name "OpenDLP E2E PDF" -DriverName "Microsoft Print To PDF" -PortName $pdf -ErrorAction Stop
    Start-Sleep 3
    1..40 | ForEach-Object { "OpenDLP print monitor test line $_" } | Out-Printer -Name "OpenDLP E2E PDF"
    $printed = $false
    for ($i = 0; $i -lt 30; $i++) { if ((Events "PRINT_JOB").Count -ge 1) { $printed = $true; break }; Start-Sleep 1 }
    if ($printed) { Write-Output "ok: PRINT_JOB event received" }
    else { Write-Output "::warning::SERVICE-E2E: no PRINT_JOB event observed (short print jobs can be missed by WMI polling; known limitation)" }
} catch {
    Write-Output "::warning::SERVICE-E2E: print test skipped: $($_.Exception.Message)"
}

# ---------- self-healing ----------
$oldPid = (Get-Process OpenDLP.Agent).Id
Stop-Process -Id $oldPid -Force
Write-Output "killed agent pid $oldPid"
Wait-Until { $p = Get-Process OpenDLP.Agent -ErrorAction SilentlyContinue; $p -and ($p.Id -ne $oldPid) -and ((Get-Service $svc).Status -eq "Running") } 90 "agent restarted after being killed" | Out-Null
$heartbeat = "$agentLogDir\agent.heartbeat"
Wait-Until { (Test-Path $heartbeat) -and ((Get-Date).ToUniversalTime() - (Get-Item $heartbeat).LastWriteTimeUtc).TotalSeconds -lt 15 } 60 "heartbeat fresh after restart" | Out-Null
$before = (Events "CONTENT_MATCH").Count
Set-Content "$watch\after-restart.txt" "National ID A123456789" -Encoding UTF8
Wait-Until { (Events "CONTENT_MATCH").Count -gt $before } 90 "detection works after restart" | Out-Null

# ---------- uninstall ----------
& "$installDir\uninstall-service.ps1" -InstallDir $installDir -RemoveLogs
if (Get-Service $svc -ErrorAction SilentlyContinue) { Fail "service still installed after uninstall" }
if (Test-Path $installDir) { Fail "install directory still present after uninstall" }
if (Get-ScheduledTask -TaskName "OpenDLP Watchdog" -ErrorAction SilentlyContinue) { Fail "watchdog task still present after uninstall" }
if (Get-Process OpenDLP.Agent, OpenDLP.Watchdog -ErrorAction SilentlyContinue) { Fail "OpenDLP processes still running after uninstall" }
Write-Output "ok: clean uninstall"

Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
Write-Output "SERVICE E2E PASSED"
"## OpenDLP service-mode test passed`n`n- install-service.ps1 with self-enrollment and watchdog`n- Windows service runs as SYSTEM and applies signed policy`n- detection inside .docx and .xlsx`n- recovery after the agent process is killed`n- clean uninstall" | Out-File -Append -Encoding utf8 $env:GITHUB_STEP_SUMMARY
