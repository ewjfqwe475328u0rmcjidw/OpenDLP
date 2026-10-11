<#
macOS / Linux service-mode end-to-end test (GitHub macos-latest / ubuntu-latest runners, passwordless sudo):
 install.sh (launchd / systemd) with self-enrollment -> signed policy -> file content detection ->
 kill the agent and verify the OS service manager restarts it -> uninstall leaves nothing running.
#>
param([string]$Publish = "out/unix")
$ErrorActionPreference = "Stop"
$root = (Resolve-Path ".").Path
$work = Join-Path $env:RUNNER_TEMP "opendlp-unix-e2e"
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
$watch = Join-Path $work "watch"
New-Item -ItemType Directory -Force -Path $watch | Out-Null
$isMac = $IsMacOS
$dataDir = if ($isMac) { "/Library/Application Support/OpenDLP" } else { "/var/lib/opendlp" }

function New-Secret { -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 48 | ForEach-Object { [char]$_ }) }
$admin = New-Secret; $enroll = New-Secret
$port = 8767; $base = "http://127.0.0.1:$port"; $agentId = "e2e-unix-01"
$serverLog = Join-Path $work "server.log"

function Fail([string]$msg) {
    Write-Output "::error::UNIX-E2E: $msg"
    foreach ($f in @("$serverLog.err", (Join-Path $dataDir "logs/agent.out.log"), (Join-Path $dataDir "logs/agent.err.log"))) {
        Write-Output "----- $f -----"
        sudo tail -n 30 $f 2>$null | ForEach-Object { Write-Output $_; if ($_ -match 'error|exception|fail') { Write-Output "::error::$(Split-Path $f -Leaf): $($_.Trim())" } }
    }
    if (-not $isMac) { sudo journalctl -u opendlp-agent --no-pager -n 30 2>$null | ForEach-Object { Write-Output $_ } }
    sudo bash (Join-Path $Publish "uninstall.sh") --remove-data 2>$null | Out-Null
    exit 1
}

# ---------- server ----------
$env:OPENDLP_TOKEN = New-Secret
$env:OPENDLP_ADMIN_TOKEN = $admin
$env:OPENDLP_ENROLL_CODE = $enroll
$env:OPENDLP_DB = Join-Path $work "opendlp.db"
$server = Start-Process python -ArgumentList "-m uvicorn main:app --host 127.0.0.1 --port $port" -WorkingDirectory (Join-Path $root "server") `
    -RedirectStandardOutput $serverLog -RedirectStandardError "$serverLog.err" -PassThru -NoNewWindow
$up = $false
for ($i = 0; $i -lt 30; $i++) { try { if ((Invoke-RestMethod "$base/health").status -eq "ok") { $up = $true; break } } catch { }; Start-Sleep 1 }
if (-not $up) { Fail "server did not start" }
$H = @{ Authorization = "Bearer $admin" }

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
function Agent-Pid { (pgrep -f "opendlp-agent --config" 2>$null | Select-Object -First 1) }

# ---------- install like an end user ----------
sudo bash (Join-Path $Publish "install.sh") --server-url $base --enrollment-code $enroll --agent-id $agentId --display-name "E2E unix" --paths $watch
if ($LASTEXITCODE -ne 0) { Fail "install.sh exited with $LASTEXITCODE" }

Wait-Until { Invoke-RestMethod "$base/api/v1/agents" -Headers $H | ForEach-Object { $_ } | Where-Object { $_.agent_id -eq $agentId -and $_.enrolled } } 60 "agent enrolled" | Out-Null
$credMode = sudo stat $(if ($isMac) { "-f" } else { "-c" }) $(if ($isMac) { "%Sp" } else { "%A" }) (Join-Path $dataDir "credentials.bin")
if ($credMode -ne "-rw-------") { Fail "credentials.bin mode is '$credMode', expected -rw-------" }
$cfgMode = sudo stat $(if ($isMac) { "-f" } else { "-c" }) $(if ($isMac) { "%Sp" } else { "%A" }) (Join-Path $dataDir "agent.config.json")
if ($cfgMode -ne "-rw-------") { Fail "agent.config.json mode is '$cfgMode', expected -rw-------" }
Wait-Until { (Events "POLICY_UPDATED").Count -ge 1 } 90 "signed policy applied" | Out-Null

# ---------- detection ----------
Start-Sleep 3
Set-Content (Join-Path $watch "payroll.csv") "name,iban,ssn`nAlice,DE89 3704 0044 0532 0130 00,123-45-6789" -Encoding UTF8
$hit = Wait-Until { Events "CONTENT_MATCH" | Where-Object { $_.message -match 'payroll\.csv' } | Select-Object -First 1 } 90 "CONTENT_MATCH for payroll.csv"
foreach ($r in "IBAN", "US-SSN") { if ($hit.message -notmatch $r) { Fail "missing rule $r : $($hit.message)" } }
if ($hit.message -match "123-45-6789") { Fail "raw SSN leaked into the event" }

# ---------- self-healing (launchd KeepAlive / systemd Restart=always) ----------
$old = Agent-Pid
if (-not $old) { Fail "agent process not found" }
sudo kill -9 $old
Write-Host "killed agent pid $old"
Wait-Until { $p = Agent-Pid; $p -and ($p -ne $old) } 60 "agent restarted by the service manager" | Out-Null
$before = (Events "CONTENT_MATCH").Count
Start-Sleep 5
Set-Content (Join-Path $watch "after-restart.txt") "Card 4111 1111 1111 1111" -Encoding UTF8
Wait-Until { (Events "CONTENT_MATCH").Count -gt $before } 90 "detection works after restart" | Out-Null

# ---------- uninstall ----------
sudo bash (Join-Path $Publish "uninstall.sh") --remove-data
Start-Sleep 3
if (Agent-Pid) { Fail "agent still running after uninstall" }
if (Test-Path $dataDir) { Fail "$dataDir still present after uninstall --remove-data" }
Write-Host "ok: clean uninstall"

Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
Write-Output "UNIX SERVICE E2E PASSED"
"## OpenDLP $(if ($isMac) {'macOS'} else {'Linux'}) service test passed`n`n- install.sh with self-enrollment`n- root-only token and config (0600)`n- signed policy, content detection with masking`n- restart by $(if ($isMac) {'launchd'} else {'systemd'}) after crash`n- clean uninstall" | Out-File -Append -Encoding utf8 $env:GITHUB_STEP_SUMMARY
