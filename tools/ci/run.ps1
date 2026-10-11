# Runs a command, streams its output, and on failure re-emits compiler/NuGet errors as GitHub annotations
# so they are visible on the public run page without signing in.
param([Parameter(Mandatory)][string]$Command)
$log = New-TemporaryFile
Invoke-Expression "$Command 2>&1" | Tee-Object -FilePath $log
$code = $LASTEXITCODE
if ($code -ne 0) {
    $errs = Get-Content $log | Select-String -Pattern '(: error |error NU\d+|error CS\d+|error MSB\d+|\[FAIL\]|Failed )' | Select-Object -First 25
    if (-not $errs) { $errs = Get-Content $log | Select-Object -Last 15 }
    foreach ($e in $errs) {
        $line = ($e.ToString().Trim() -replace '%', '%25' -replace "`r", '' -replace "`n", ' ')
        if ($line.Length -gt 900) { $line = $line.Substring(0, 900) }
        Write-Output "::error::$line"
    }
    exit $code
}
