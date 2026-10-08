# Detections

Every detection here started as a finding from a purple-team operation, and every
one has tests: attack events it **must fire on** and normal events it **must
stay quiet on**. CI runs the tests on every change.

[:material-github: Browse the rules on GitHub](https://github.com/dotslashtag/cyber-defense-lab/tree/main/detections){ .md-button .md-button--primary }

## From a miss to a tested detection

In OP-002 and OP-003, three things got past the SOC. OP-004 turned each one into a
deployed detection:

| | What happened | Why nothing alerted | The fix |
|---|---|---|---|
| **D1** | Attacker ran native discovery (`whoami`, `net`, `nltest`, `systeminfo`...) | Each command is normal on its own; existing rules looked for attacker tools, not behaviour | Alert when **4+ different discovery tools** run on one host within 10 minutes |
| **D2** | Attacker hopped from one workstation to another with valid credentials | The lateral-movement rule only watched traffic from the attack network | Alert on any **network or RDP logon between two workstations** |
| **D3** | A Run-key persistence alert fired on `reg.exe` | The alert title said "script host", which pointed the analyst the wrong way | Renamed the alert to "Run/RunOnce Key Modified", showing the actual writer |

Each was validated **both ways** in the lab before being enabled:

- **D1** fired at 8 distinct tools on a replayed discovery burst; the busiest normal
  10-minute window on any host had 1.
- **D2** caught the OP-003 hop; across 7 days of normal logons it matched nothing else.

## Inventory

| Detection | ATT&CK | Formats | Origin |
|---|---|---|---|
| Clustered native discovery (D1) | T1033 · T1082 · T1016 · T1057 · T1087 · T1018 | Splunk · Sigma correlation | OP-002 → OP-004 |
| Workstation-to-workstation logon (D2) | T1021.002 · T1550.002 · T1078 | Splunk · Sigma | OP-003 → OP-004 |
| Run/RunOnce key written by script host or LOLBin (D3) | T1547.001 | Sigma (Splunk export pending) | OP-002 → OP-004 |
| Run/RunOnce key written by a script host | T1547.001 | Wazuh `510150` | PB-012 · OP-001 |
| PowerShell with ExecutionPolicy Bypass | T1059.001 | Wazuh `510140` · Sigma | PB-003 |
| Defender Tamper Protection blocked a change | T1562.001 | Wazuh `510142` · Sigma | PB-005 · OP-001 |
| Rundll32 spawned by PowerShell | T1218.011 | Wazuh `510143` · Sigma | PB-009 |
| Connection to a controlled IOC IP | (none on purpose) | Wazuh `510144` | PB-010 · PB-017 · PB-019 |

## Example: D2 in Sigma

```yaml
detection:
  selection_logon:
    EventID: 4624
    LogonType: [3, 10]
  selection_target_workstation:
    Computer: ['Win10.soc.lab', 'WIN11-OPS01.soc.lab']
  selection_source_workstation:
    IpAddress: ['10.10.2.4', '10.10.2.9']
  filter_loopback:
    IpAddress: ['127.0.0.1', '::1', '-']
  condition: all of selection_* and not filter_loopback
```

And its tests: the OP-003 hop must fire; a workstation logging on to the domain
controller, a loopback logon, a console logon and a failed logon must not.

## How the testing works

- **Sigma** rules are parsed by [pySigma](https://github.com/SigmaHQ/pySigma),
  converted to Splunk, and checked against their sample events by a small evaluator
  built on pySigma's own parser. The correlation rule is tested with a sliding
  10-minute window, including a burst that crosses a clock boundary.
- **Wazuh** rules are checked for unique IDs in the lab's range, a parent rule and
  an ATT&CK tag, and their field patterns are run against sample alerts.
- To show the tests catch mistakes, I broke rules on purpose (dropped an
  exclusion, raised a threshold, changed a process name). Each change made a test fail.

!!! note "Limits"
    The Wazuh parent rule and decoder only run on a real Wazuh manager, and the
    Splunk searches were validated against live lab data rather than in CI. Sample
    events are representative events based on lab validation runs, not raw log exports.
