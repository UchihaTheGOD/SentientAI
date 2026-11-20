param([string]$ProjectPath = $PSScriptRoot)
# Restart SentientAI server correctly using venv
$ErrorActionPreference = "SilentlyContinue"
Write-Host "=== Killing stale python processes on :8000 ==="
# Find PIDs listening on 8000
$netstat = netstat -ano | Select-String "8000"
Write-Host "$netstat"
$pids = @()
foreach ($line in $netstat) {
  if ($line -match "LISTENING\s+(\d+)") { $pids += $Matches[1] }
}
$pids = $pids | Sort-Object -Unique
foreach ($pid in $pids) {
  Write-Host "Killing LISTEN pid $pid"
  taskkill /F /PID $pid 2>&1 | Out-String | Write-Host
  Start-Sleep -Milliseconds 500
}
# Also kill any python run.py leftovers (but keep this shell's python)
Write-Host "=== Checking remaining python ==="
tasklist | findstr /i python | Write-Host
Start-Sleep 1
# Start server with venv
$venvPython = Join-Path $ProjectPath ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) { $venvPython = Join-Path $ProjectPath "venv\Scripts\python.exe" }
Write-Host "=== Starting server via venv ($venvPython) ==="
# Use Start-Process to detach
$proc = Start-Process -FilePath $venvPython -ArgumentList "run.py" -WorkingDirectory $ProjectPath -PassThru -WindowStyle Hidden
Write-Host "Started PID $($proc.Id)"
Start-Sleep 3
# Poll health
for ($i=0; $i -lt 20; $i++) {
  try {
    $r = Invoke-WebRequest -Uri http://127.0.0.1:8000/api/health -UseBasicParsing -TimeoutSec 3
    Write-Host "health $($r.StatusCode) $($r.Content)"
    break
  } catch { Write-Host "health poll $i failed: $($_.Exception.Message)"; Start-Sleep 1 }
}
for ($i=0; $i -lt 20; $i++) {
  try {
    $r = Invoke-WebRequest -Uri http://127.0.0.1:8000/api/sentinel/readiness -UseBasicParsing -TimeoutSec 5
    Write-Host "readiness poll $i : $($r.Content)"
    $j = $r.Content | ConvertFrom-Json
    if ($j.ready -eq $true) { Write-Host "READY TRUE at poll $i"; break }
  } catch { Write-Host "readiness poll $i failed: $($_.Exception.Message)" }
  Start-Sleep 2
}
Write-Host "=== netstat after ==="
netstat -ano | findstr 8000 | Write-Host
Write-Host "=== tasklist after ==="
tasklist | findstr /i python | Write-Host
