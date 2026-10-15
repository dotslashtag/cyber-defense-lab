# Detection Heartbeat

> **Status: paused.** The probe, manifest and searches are built and tested in CI, and the
> searches were dry-run in the lab. The probe has not yet been run on a host.

Answers one question on a schedule: **"Do our detections still work right now?"**

A scheduled task runs harmless, marked test actions on a workstation. Later, a verifier
checks that each expected alert arrived. It then tells two failures apart: a **dead
detection** (the telemetry arrived but no alert fired) and a **dead log source** (nothing
arrived at all).

Built after one week in which this lab found six Wazuh rules that could never fire and two
agents that had been silent for weeks, all found by hand.

## Files

| File | What it is |
|---|---|
| `hb-probe.ps1` | The probe. Windows PowerShell 5.1, runs as a standard user |
| `manifest.yml` | Which probe should trip which detection, and which search checks it |
| `verifier/*.spl` | The verifier searches (Splunk only; Wazuh alerts are forwarded to `index=wazuh`) |

## Probes

| Probe | Action | Expected detections |
|---|---|---|
| H0 | none; newest event per workstation | data newer than 30 min |
| P1 | `whoami`, `hostname`, `ipconfig /all`, `systeminfo`, `net user`, `tasklist`, `netstat -ano` | Splunk D1 *Clustered Discovery Activity* |
| P2 | PowerShell `Start-Process rundll32.exe` | Wazuh 510143 |
| P3 | HKCU `Run` value → `notepad.exe`, deleted after 5 s | Wazuh 510150, Splunk D3 *Run/RunOnce Key Modified* |

Every action carries the marker `HB-<HOST>-<yyyyMMddHHmm>` (UTC):

- **P1 and P2** start from a child `powershell -Command "$hb='<marker>'; ..."`, so the marker
  appears in Sysmon's `ParentCommandLine`.
- **P3** uses the marker as the name of the Run value (`TargetObject`).

## Verdicts

| Probe evidence | Alert | Verdict |
|---|---|---|
| yes | yes | **PASS** |
| yes | no | **DEAD DETECTION**: the rule or search is broken |
| no | — (H0 fresh) | **PROBE NOT RUN**: the task failed, or a Sysmon config gap |
| no | — (H0 stale) | **NO TELEMETRY**: the agent is silent |

`manifest.yml` also lists a **canary**: a rule id that does not exist. The verifier must
report DEAD DETECTION for it on every run. That proves the failure path works without
breaking a real rule.

## Run it

Run the task as a dedicated standard user with S4U ("do not store password"):

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File C:\ProgramData\SOC\Heartbeat\hb-probe.ps1
```

The script prints one JSON line and appends it to `%LOCALAPPDATA%\DetectionHeartbeat\hb-probe.log`:

```json
{"marker":"HB-WIN11-OPS01-202610141200","host":"WIN11-OPS01","user":"SOC\\hbprobe","started":"2026-10-14T12:00:03Z","finished":"2026-10-14T12:00:31Z","probes":{"P1":"ran","P2":"ran","P3":"ran"}}
```

Exit code `0` means every probe ran; `1` means at least one probe failed to run.

## Safety

- No network activity, credential access, downloads or lasting changes. The Run value
  points to `notepad.exe` and is removed after 5 s; leftover `HB-*` values are removed at
  start.
- Never start it with `-ExecutionPolicy Bypass`. That trips rule 510140, which is routed to
  the SOAR pilot.
- Triage views may hide `HB-` markers. **Detection logic must never exclude them**, because
  an attacker could copy the marker to bypass the detection.
- Each probe uses up that detection's per-host throttle for a while (D1: 30 min, D3: 15 min).
  Running every 6 h, staggered per host, keeps that blind window small.
