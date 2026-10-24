<#
  Healthcare Threat Monitor: Windows collector.

  Runs every few minutes as a scheduled task under the SYSTEM account (see install.ps1). Each run reads the
  new events of the kinds the platform watches from the Security and System logs, and passes them to the
  collector's core (HtmCollector.cs), which keeps only the fields the platform reads, signs them and sends
  them over HTTPS. The position reached in each log is saved only after the platform has stored the events,
  so nothing is lost when the network is down: the next run sends them.

  Works in Windows PowerShell 5.1, which every supported Windows computer has. Writes its own short log to
  collector.log in this folder.
#>
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logFile = Join-Path $dir 'collector.log'

function Write-CollectorLog([string]$message) {
    try {
        if ((Test-Path $logFile) -and (Get-Item $logFile).Length -gt 1MB) {
            Move-Item -Force $logFile ($logFile + '.old')
        }
        Add-Content -Path $logFile -Value ('{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $message) -Encoding UTF8
    } catch { }
}

# The events the platform reads, by log. Process creation (4688) needs process auditing on, which install.ps1 sets.
$watched = [ordered]@{
    'Security' = @(4624, 4625, 4672, 4688, 4698, 4720, 4732, 4740, 1102)
    'System'   = @(7036, 7045)
}
$pageSize = 500      # must match the batch size in HtmCollector.cs
$maxPages = 20       # at most 10,000 events from each log in one run; the rest follow on the next run
$firstRunHours = 24  # on the very first run, only the last day is sent

try {
    if (-not ('HealthcareThreatMonitor.Collector' -as [type])) {
        $source = Get-Content -Raw -Encoding UTF8 -Path (Join-Path $dir 'HtmCollector.cs')
        Add-Type -TypeDefinition $source -Language CSharp -ReferencedAssemblies 'System.Xml', 'System.Core'
    }
    foreach ($log in $watched.Keys) {
        $ids = ($watched[$log] | ForEach-Object { "EventID=$_" }) -join ' or '
        for ($page = 0; $page -lt $maxPages; $page++) {
            $last = [HealthcareThreatMonitor.Collector]::LastRecordId($dir, $log)
            if ($last -lt 0) {
                $since = $firstRunHours * 3600 * 1000
                $xpath = "*[System[($ids) and TimeCreated[timediff(@SystemTime) <= $since]]]"
            } else {
                $xpath = "*[System[($ids) and EventRecordID > $last]]"
            }
            try {
                $events = @(Get-WinEvent -LogName $log -FilterXPath $xpath -MaxEvents $pageSize -Oldest -ErrorAction Stop)
            } catch {
                # Windows reports "no events found" as an error. Anything else is a real problem.
                if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events = @() } else { throw }
            }
            if ($events.Count -eq 0) {
                if ($last -lt 0) {
                    # Nothing in the last day. Start from the newest record, so the next run only sends what is new.
                    $newest = @(Get-WinEvent -LogName $log -MaxEvents 1 -ErrorAction SilentlyContinue)
                    if ($newest.Count -gt 0) {
                        [HealthcareThreatMonitor.Collector]::Start($dir, $log, [long]$newest[0].RecordId)
                    }
                }
                break
            }
            $xml = [string[]]@($events | ForEach-Object { $_.ToXml() })
            # Events come oldest first, so the last one ends the page.
            $pageEnd = [long]$events[$events.Count - 1].RecordId
            Write-CollectorLog ([HealthcareThreatMonitor.Collector]::Process($dir, $log, $xml, $pageEnd))
            if ($events.Count -lt $pageSize) { break }
        }
    }
} catch {
    Write-CollectorLog ('error: ' + $_.Exception.Message)
    exit 1
}
exit 0
