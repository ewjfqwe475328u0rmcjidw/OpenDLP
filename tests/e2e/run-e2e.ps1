<#
End-to-end test on a clean Windows machine (used by CI on GitHub's windows-latest runners):
 1. start the OpenDLP server with fresh secrets
 2. start the agent in console mode with only an enrollment code (no token)
 3. verify: enrollment, signed-policy download, telemetry upload, and content detection of a file
    containing a Taiwan national ID + test credit card number dropped into a watched folder
 4. verify revocation blocks the agent
Every failure is printed as a GitHub annotation together with the tail of the agent and server logs.
#>
param([string]$AgentExe = "agent/bin/Release/net8.0-windows/OpenDLP.Agent.exe")
# Cross-platform: the same test drives the Windows agent and the macOS/Linux agent (agent-unix).
$ErrorActionPreference = "Stop"
# Exit codes of native commands are checked explicitly (some calls are EXPECTED to fail).
$PSNativeCommandUseErrorActionPreference = $false
# Any unexpected script error becomes a public annotation with its line number.
trap {
    Write-Host "::error::E2E script error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    Write-Host "::error::E2E   $($_.InvocationInfo.Line.Trim())"
    break
}
$root = (Resolve-Path ".").Path
$work = Join-Path $env:RUNNER_TEMP "opendlp-e2e"
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
foreach ($d in "watch", "logs", "policy") { New-Item -ItemType Directory -Force -Path (Join-Path $work $d) | Out-Null }

function New-Secret { -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 48 | ForEach-Object { [char]$_ }) }
$admin = New-Secret
$enroll = New-Secret
$port = 8765
$base = "http://127.0.0.1:$port"
$agentId = "e2e-agent-01"
$serverLog = (Join-Path $work "server.log")
$agentLog = (Join-Path $work "agent.log")

function Fail([string]$msg) {
    Write-Host "::error::E2E: $msg"
    foreach ($f in @($agentLog, "$agentLog.err", $serverLog, "$serverLog.err")) {
        if (Test-Path $f) {
            Write-Host "----- $f (tail) -----"
            Get-Content $f -Tail 40 | ForEach-Object {
                Write-Host $_
                if ($_ -match 'error|exception|fail') { Write-Host "::error::$(Split-Path $f -Leaf): $($_.Trim())" }
            }
        }
    }
    exit 1
}

# ---------- server ----------
$env:OPENDLP_TOKEN = New-Secret
$env:OPENDLP_ADMIN_TOKEN = $admin
$env:OPENDLP_ENROLL_CODE = $enroll
$env:OPENDLP_DB = (Join-Path $work "opendlp.db")
$env:OPENDLP_DASHBOARD_PASSWORD = "e2e-dashboard"
$server = Start-Process -FilePath python -ArgumentList "-m uvicorn main:app --host 127.0.0.1 --port $port" `
    -WorkingDirectory (Join-Path $root "server") -RedirectStandardOutput $serverLog -RedirectStandardError "$serverLog.err" -PassThru -NoNewWindow
$ok = $false
for ($i = 0; $i -lt 30; $i++) {
    try { if ((Invoke-RestMethod "$base/health").status -eq "ok") { $ok = $true; break } } catch { }
    Start-Sleep 1
}
if (-not $ok) { Fail "server did not start" }
Write-Output "server up"
$H = @{ Authorization = "Bearer $admin" }

# ---------- agent ----------
$exe = Join-Path $root $AgentExe
if (-not (Test-Path $exe)) { Fail "agent executable not found at $exe" }
$cfg = [ordered]@{
    AgentId = $agentId; DisplayName = "E2E runner"; ServerUrl = $base; EnrollmentCode = $enroll; ApiToken = ""
    SensitivePaths = @((Join-Path $work "watch")); LogDirectory = (Join-Path $work "logs"); PolicyCachePath = (Join-Path $work "policy/policy.json")
    CredentialPath = (Join-Path $work "credentials.bin"); TelemetryEnabled = $true; PolicyPollSeconds = 15
}
$cfg | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path (Split-Path $exe) "agent.config.json")
Remove-Item Env:OPENDLP_TOKEN   # the agent must not see the shared token; it has to enroll
$agent = Start-Process -FilePath $exe -ArgumentList "--mode console" -WorkingDirectory (Split-Path $exe) `
    -RedirectStandardOutput $agentLog -RedirectStandardError "$agentLog.err" -PassThru -NoNewWindow

function Wait-Until([scriptblock]$cond, [int]$seconds, [string]$what) {
    for ($i = 0; $i -lt $seconds; $i++) {
        if ($agent.HasExited) { Fail "agent exited early with code $($agent.ExitCode) while waiting for: $what" }
        try { $r = & $cond; if ($r) { Write-Host "ok: $what"; return $r } } catch { }
        Start-Sleep 1
    }
    Fail "timed out after ${seconds}s waiting for: $what"
}

# 1. enrollment
$a = Wait-Until { (Invoke-RestMethod "$base/api/v1/agents" -Headers $H) | ForEach-Object { $_ } | Where-Object { $_.agent_id -eq $agentId -and $_.enrolled } } 60 "agent enrolled"
$cred = Join-Path $work "credentials.bin"
# the server records the enrollment slightly before the agent has persisted its token
Wait-Until { Test-Path $cred } 20 "credential file written" | Out-Null
if ($IsWindows) {
    $raw = [IO.File]::ReadAllText($cred)
    if ($raw -match '[A-Za-z0-9_-]{40,}') { Fail "credential file looks like plaintext (DPAPI not applied)" }
} else {
    $mode = (Get-Item $cred).UnixMode
    if ($mode -ne "-rw-------") { Fail "credential file mode is $mode, expected -rw-------" }
}

# 2. policy applied (HMAC verified) and telemetry flowing
Wait-Until { (Invoke-RestMethod "$base/api/v1/events?agent_id=$agentId&event_type=POLICY_UPDATED" -Headers $H).Count -ge 1 } 90 "signed policy applied and reported" | Out-Null

# 3. content detection
Start-Sleep 3
$content = "Customer record`r`nNational ID: A123456789`r`nCard: 4111 1111 1111 1111`r`nCONFIDENTIAL"
Set-Content -Path (Join-Path $work "watch/customers.txt") -Value $content -Encoding UTF8
$hit = Wait-Until {
    (Invoke-RestMethod "$base/api/v1/events?agent_id=$agentId&event_type=CONTENT_MATCH" -Headers $H) | Select-Object -First 1
} 90 "CONTENT_MATCH event received by server"
foreach ($rule in @("TW-NID", "CREDIT-CARD", "KW-CONFIDENTIAL")) {
    if ($hit.message -notmatch $rule) { Fail "CONTENT_MATCH did not include rule $rule. message=$($hit.message)" }
}
if ($hit.message -match "A123456789|4111 1111 1111 1111") { Fail "raw sensitive value leaked into the event (masking broken)" }
if ($hit.level -ne "ALERT") { Fail "expected ALERT level, got $($hit.level)" }
Write-Output "detected: $($hit.message)"

# 4. revocation
Invoke-RestMethod -Method Post "$base/api/v1/admin/agents/$agentId/revoke" -Headers $H | Out-Null
$before = (Invoke-RestMethod "$base/api/v1/events?agent_id=$agentId&limit=500" -Headers $H).Count
Set-Content -Path (Join-Path $work "watch/after-revoke.txt") -Value "A123456789" -Encoding UTF8
Start-Sleep 20
$after = (Invoke-RestMethod "$base/api/v1/events?agent_id=$agentId&limit=500" -Headers $H).Count
if ($after -gt $before) { Fail "revoked agent could still upload events ($before -> $after)" }
Write-Output "ok: revoked agent is rejected"

Stop-Process -Id $agent.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
Write-Output "E2E PASSED"
"## OpenDLP end-to-end test passed ($([Runtime.InteropServices.RuntimeInformation]::OSDescription))`n`n- enrollment + DPAPI credential store`n- signed policy download`n- telemetry upload`n- content detection (TW national ID, payment card, keyword) with masking`n- revocation" | Out-File -Append -Encoding utf8 $env:GITHUB_STEP_SUMMARY
# The runner fails a step if the LAST native command returned non-zero (e.g. pgrep finding nothing): be explicit.
exit 0
