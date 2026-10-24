<#
  Healthcare Threat Monitor: installs the Windows collector on this computer.

  Run in Windows PowerShell as an administrator, from a folder holding HtmCollector.cs, htm-collector.ps1,
  uninstall.ps1 and the config.json downloaded from the console:
      powershell -ExecutionPolicy Bypass -File .\install.ps1
  The installer the console offers does all of this in one file.

  What it does, and nothing else:
    1. Copies the collector to C:\ProgramData\HealthcareThreatMonitor. Only SYSTEM and administrators can open
       that folder, because config.json holds this group's secret.
    2. Turns on the Windows auditing the platform reads: sign ins, account and group changes, special privileges,
       scheduled tasks and new processes with their command lines. Use -SkipAuditPolicy to leave auditing as it is,
       for example when Group Policy already sets it.
    3. Registers a scheduled task that runs the collector as SYSTEM every few minutes and when the computer starts.
    4. Runs it once and shows the result.
  Running it again updates the collector and keeps its place in the logs.
#>
param(
    [switch]$SkipAuditPolicy,
    [switch]$NoTest
)
$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Please run this in PowerShell opened with "Run as administrator".' -ForegroundColor Red
    exit 1
}
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host 'This needs Windows PowerShell 5.1 or later, which Windows 10 and 11 include.' -ForegroundColor Red
    exit 1
}

$source = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $env:ProgramData 'HealthcareThreatMonitor'
$taskName = 'Healthcare Threat Monitor collector'
$files = 'HtmCollector.cs', 'htm-collector.ps1', 'uninstall.ps1', 'config.json'
foreach ($f in $files) {
    if (-not (Test-Path (Join-Path $source $f))) {
        Write-Host "Missing $f next to this installer." -ForegroundColor Red
        exit 1
    }
}

# Check the settings before changing anything on this computer.
$config = Get-Content -Raw -Encoding UTF8 (Join-Path $source 'config.json') | ConvertFrom-Json
if (-not $config.api_url -or -not $config.collector_id -or -not $config.secret) {
    Write-Host 'config.json is incomplete. Download the installer again from the console.' -ForegroundColor Red
    exit 1
}
$interval = [Math]::Max(1, [int]$config.interval_minutes)

Write-Host "Installing the Healthcare Threat Monitor collector in $target"
New-Item -ItemType Directory -Force -Path $target | Out-Null
# SYSTEM (S-1-5-18) and the Administrators group (S-1-5-32-544) only, by their fixed identifiers so this works in any language.
& icacls.exe $target /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict access to the collector folder.' }
foreach ($f in $files) { Copy-Item -Force (Join-Path $source $f) (Join-Path $target $f) }

if (-not $SkipAuditPolicy) {
    Write-Host 'Turning on the Windows auditing the platform reads'
    # Subcategories by their fixed identifiers, so this works whatever the language of Windows.
    $subcategories = [ordered]@{
        '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'Logon'
        '{0CCE9217-69AE-11D9-BED3-505054503030}' = 'Account Lockout'
        '{0CCE921B-69AE-11D9-BED3-505054503030}' = 'Special Logon'
        '{0CCE922B-69AE-11D9-BED3-505054503030}' = 'Process Creation'
        '{0CCE9227-69AE-11D9-BED3-505054503030}' = 'Other Object Access Events'
        '{0CCE9235-69AE-11D9-BED3-505054503030}' = 'User Account Management'
        '{0CCE9237-69AE-11D9-BED3-505054503030}' = 'Security Group Management'
    }
    foreach ($guid in $subcategories.Keys) {
        & auditpol.exe /set "/subcategory:$guid" /success:enable /failure:enable | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Host "  Could not turn on auditing for $($subcategories[$guid])." -ForegroundColor Yellow }
    }
    # Record the command line of each new process, so commands that delete backups can be recognised.
    $key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -PropertyType DWord -Force | Out-Null
}

Write-Host "Scheduling the collector to run every $interval minute(s) as SYSTEM"
# The task is registered from task XML, the format Windows itself exports, so every Windows version reads it the same.
# S-1-5-18 is SYSTEM. A repetition with no end runs for as long as the task exists.
$collectorPath = [Security.SecurityElement]::Escape((Join-Path $target 'htm-collector.ps1'))
$start = (Get-Date).AddMinutes(1).ToString('yyyy-MM-ddTHH:mm:ss')
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Sends this computer's security events to the hospital's Healthcare Threat Monitor.</Description></RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition><Interval>PT${interval}M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
      <StartBoundary>$start</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "$collectorPath"</Arguments>
    </Exec>
  </Actions>
</Task>
"@
Register-ScheduledTask -TaskName $taskName -Xml $taskXml -Force | Out-Null

if (-not $NoTest) {
    Write-Host 'Running it once now'
    $logFile = Join-Path $target 'collector.log'
    $before = if (Test-Path $logFile) { (Get-Item $logFile).Length } else { 0 }
    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddMinutes(3)
    do {
        Start-Sleep -Seconds 3
        $state = (Get-ScheduledTask -TaskName $taskName).State
    } while (($state -eq 'Running' -or $state -eq 'Queued') -and (Get-Date) -lt $deadline)
    $info = Get-ScheduledTaskInfo -TaskName $taskName
    if (Test-Path $logFile) {
        $text = [IO.File]::ReadAllText($logFile)
        Write-Host $text.Substring([Math]::Min($before, $text.Length)).Trim()
    }
    if ($info.LastTaskResult -ne 0) {
        Write-Host "The first run did not finish cleanly (result $($info.LastTaskResult)). See $logFile." -ForegroundColor Yellow
        exit 2
    }
}
Write-Host 'Installed. This computer will appear in the console under Sources, Windows computers.' -ForegroundColor Green
exit 0
