# Detection Heartbeat

**Status: Phase 1 (one workstation, manual runs).** This tool answers one question on a schedule:
"do our detections still work right now?"

[:material-github: Source and README](https://github.com/dotslashtag/cyber-defense-lab/tree/main/tools/detection-heartbeat){ .md-button .md-button--primary }

## Why

In one week of review this lab found six Wazuh rules that could never fire, and two agents
that had been silent for weeks. Nothing warned anyone; a person found each one by looking.
The Heartbeat makes that check continuous.

## How it works

1. A scheduled task runs `hb-probe.ps1` as a dedicated standard user, with S4U so no
   password is stored. It performs three harmless actions, each carrying a run marker
   `HB-<HOST>-<yyyyMMddHHmm>`:

| Probe | Action | Expected detections |
|---|---|---|
| P1 | discovery burst (`whoami`, `systeminfo`, `net user`, ...) | Splunk D1 *Clustered Discovery Activity* |
| P2 | PowerShell starts `rundll32.exe` | Wazuh 510143 |
| P3 | HKCU `Run` value → `notepad.exe`, removed after 5 s | Wazuh 510150, Splunk D3 |

2. About 35 minutes later, a verifier runs six Splunk searches. Wazuh alerts are already
   forwarded to Splunk, so one read-only account covers everything:
    - **V0:** telemetry freshness for each workstation
    - **V1:** probe evidence, found by the marker
    - **V2:** Wazuh alerts
    - **V3/V4:** re-runs of D1 and D3
    - **V5:** whether the scheduled alerts actually fired
3. Each expected detection gets a verdict:

| Probe evidence | Alert | Verdict |
|---|---|---|
| yes | yes | PASS |
| yes | no | DEAD DETECTION |
| no | — (agent fresh) | PROBE NOT RUN |
| no | — (agent stale) | NO TELEMETRY |

A **canary** entry expects a rule id that doesn't exist, so every run must show one DEAD
DETECTION. This proves the failure path works without breaking a real rule.

## What it already caught

The first dry run of the freshness search (V0) flagged two of the three lab workstations as
**STALE**: no Windows events in 30 minutes. That's the same class of silent-agent problem
that motivated the tool.

## Design choices

- **Probes that open SOAR cases are excluded.** These are `-ExecutionPolicy Bypass` (510140)
  and the brute-force chain. Running them every 6 h would open a SOAR run or an approval
  card each time. They'll be tested monthly, with an analyst present.
- **No suppression for heartbeat traffic.** Anything the probe can mark, an attacker can
  copy. Triage views may hide `HB-` markers, but detection logic never excludes them.
- **Throttle trade-off.** A probe uses up the detection's per-host throttle (D1: 30 min,
  D3: 15 min). With runs every 6 h, staggered per host, that blind window is about 8%.
