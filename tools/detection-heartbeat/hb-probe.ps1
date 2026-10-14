<#
.SYNOPSIS
    Detection Heartbeat probe: benign, marked test actions that should trip known detections.

.DESCRIPTION
    Runs as a standard (non-admin) user from a scheduled task. Every action carries the run
    marker HB-<HOST>-<yyyyMMddHHmm> (UTC) so the verifier can match this exact run.

      P1  discovery burst  -> Splunk D1 (Clustered Discovery Activity)
      P2  PowerShell starts rundll32 -> Wazuh 510143
      P3  HKCU Run value set, removed after 5 s -> Wazuh 510150 + Splunk D3

    No network activity, no credential access, nothing persistent: the Run value points to
    notepad.exe and is deleted seconds later (and any leftover HB- value is deleted at start).

    The task must NOT use "-ExecutionPolicy Bypass" (that is rule 510140, routed to SOAR).
    Use: powershell.exe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File hb-probe.ps1

.PARAMETER Probe
    Which probes to run. Default: P1, P2, P3.

.PARAMETER LogDir
    Where to append the JSON result line. Default: %LOCALAPPDATA%\DetectionHeartbeat.

.OUTPUTS
    One JSON line per run (also appended to <LogDir>\hb-probe.log). Exit code 0 = all probes
    ran, 1 = at least one probe failed to run.
#>
[CmdletBinding()]
param(
    [ValidateSet('P1', 'P2', 'P3')]
    [string[]] $Probe = @('P1', 'P2', 'P3'),
    [string] $LogDir
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$started = (Get-Date).ToUniversalTime()
$marker  = 'HB-{0}-{1}' -f $env:COMPUTERNAME.ToUpper(), $started.ToString('yyyyMMddHHmm')
$psExe   = Join-Path $PSHOME 'powershell.exe'
$runKey  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

if (-not $LogDir) {
    $base = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:TEMP }
    $LogDir = Join-Path $base 'DetectionHeartbeat'
}

function Invoke-MarkedPowerShell([string] $Body) {
    # The marker sits in the child's command line, so every process it starts carries the
    # marker in Sysmon's ParentCommandLine.
    $cmd = "`$hb='$marker'; $Body"
    $p = Start-Process -FilePath $psExe -WindowStyle Hidden -Wait -PassThru `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', "`"$cmd`"")
    if ($p.ExitCode -ne 0) { throw "child powershell exited $($p.ExitCode)" }
}

function Remove-StaleRunValues {
    $key = Get-Item -Path $runKey -ErrorAction SilentlyContinue
    if (-not $key) { return }
    foreach ($name in $key.GetValueNames()) {
        if ($name -like 'HB-*') { Remove-ItemProperty -Path $runKey -Name $name }
    }
}

$probes = [ordered]@{
    P1 = {
        Invoke-MarkedPowerShell ('whoami > $null; hostname > $null; ipconfig /all > $null; ' +
            'systeminfo > $null; net user > $null; tasklist > $null; netstat -ano > $null')
    }
    P2 = {
        Invoke-MarkedPowerShell 'Start-Process rundll32.exe -Wait'
    }
    P3 = {
        Remove-StaleRunValues
        if (-not (Test-Path $runKey)) { New-Item -Path $runKey -Force | Out-Null }
        $notepad = Join-Path $env:WINDIR 'System32\notepad.exe'
        New-ItemProperty -Path $runKey -Name $marker -Value $notepad -PropertyType String -Force | Out-Null
        Start-Sleep -Seconds 5
        Remove-ItemProperty -Path $runKey -Name $marker
    }
}

$results = [ordered]@{}
foreach ($name in $probes.Keys) {
    if ($Probe -notcontains $name) { continue }
    try {
        & $probes[$name]
        $results[$name] = 'ran'
    } catch {
        $results[$name] = 'error: ' + $_.Exception.Message
    }
}

$record = [ordered]@{
    marker   = $marker
    host     = $env:COMPUTERNAME.ToUpper()
    user     = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
    started  = $started.ToString('yyyy-MM-ddTHH:mm:ssZ')
    finished = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    probes   = $results
}
$line = $record | ConvertTo-Json -Compress
$line

try {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    Add-Content -Path (Join-Path $LogDir 'hb-probe.log') -Value $line -Encoding UTF8
} catch {
    Write-Warning "could not write log: $($_.Exception.Message)"
}

if (@($results.Values | Where-Object { $_ -ne 'ran' }).Count -gt 0) { exit 1 }
exit 0
