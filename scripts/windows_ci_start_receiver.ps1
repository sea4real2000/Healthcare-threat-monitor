# Starts the CI stand in for the platform (windows_ci_receiver.py) unless it is already listening, and waits
# until it accepts connections. Each CI step calls this, because a process started in one step may not
# survive into the next. Not part of any installation.
param([Parameter(Mandatory)][string]$Secret, [Parameter(Mandatory)][string]$Output)
function Test-Listening {
    $client = New-Object System.Net.Sockets.TcpClient
    try { $client.Connect('127.0.0.1', 8765); return $true } catch { return $false } finally { $client.Dispose() }
}
if (Test-Listening) { return }
$log = Join-Path $env:RUNNER_TEMP 'rx.log'
$err = Join-Path $env:RUNNER_TEMP 'rx.err.log'
$python = (Get-Command python).Source
Start-Process -FilePath $python -ArgumentList 'scripts/windows_ci_receiver.py', $Secret, $Output -RedirectStandardOutput $log -RedirectStandardError $err -WindowStyle Hidden
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    if (Test-Listening) { Write-Host 'test receiver listening on 127.0.0.1:8765'; return }
}
throw "The test receiver did not start. $((Get-Content $err -ErrorAction SilentlyContinue) -join ' ')"
