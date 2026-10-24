<#
  Healthcare Threat Monitor: removes the Windows collector from this computer.

  Run in Windows PowerShell as an administrator:
      powershell -ExecutionPolicy Bypass -File "C:\ProgramData\HealthcareThreatMonitor\uninstall.ps1"
  Removes the scheduled task and the collector's folder, including its secret. The Windows auditing the installer
  turned on is left as it is, because other tools may rely on it. Events already sent stay on the platform.
#>
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Please run this in PowerShell opened with "Run as administrator".' -ForegroundColor Red
    exit 1
}
$taskName = 'Healthcare Threat Monitor collector'
$target = Join-Path $env:ProgramData 'HealthcareThreatMonitor'
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host 'Scheduled task removed.'
}
if (Test-Path $target) {
    # This script may be running from that folder, so it is removed once this script has finished.
    Start-Process -WindowStyle Hidden -FilePath 'cmd.exe' -ArgumentList '/c', ('timeout /t 3 >nul & rmdir /s /q "{0}"' -f $target)
    Write-Host "The folder $target will be removed in a few seconds."
}
Write-Host 'The collector is uninstalled. Remove this computer''s group in the console when no computer uses it any more.' -ForegroundColor Green
