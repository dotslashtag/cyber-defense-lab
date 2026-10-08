# Purple-Team Operations

Assumed-breach, post-compromise emulations run with MITRE Caldera and Kali. Each
starts **after** initial access and exercises the later stages: execution, defense
evasion, discovery, persistence, C2, lateral movement, collection and exfiltration.

Outcomes are scored honestly:
🟦 Prevented · 🟩 Alerted · 🟨 Logged-only · 🟥 Missed

## The four operations

| Operation | What it tested | Headline finding |
|---|---|---|
| **OP-001** Commodity Intrusion Chain | A 7-phase chain from execution to exfiltration | Defender **prevented** the stock agent by cloud reputation; a Run-key persistence gap surfaced (Wazuh silent, Splunk compensating) and was later fixed |
| **OP-002** Stealth Tradecraft Variant | The same chain, run quietly with built-in Windows tools | Detection was **tied to known tools and IOCs, not to attacker intent**: native discovery, sustained C2 and non-IOC exfiltration went unalerted |
| **OP-003** Lateral Movement / Multi-Host | Foothold → peer workstation with valid credentials | A **detection blind spot but a prevention success**: no alert on the hop, but the host firewall and token filtering blocked execution |
| **OP-004** Detection-Engineering Loop | Turn the OP-002/003 misses into detections | Three new detections deployed and validated both ways. The loop, closed |

## ATT&CK coverage

| Tactic | Technique | Outcome | Coverage now |
|---|---|---|---|
| Execution | T1059.001 PowerShell | 🟩 Alerted | Stable |
| Defense Evasion | T1562.001 Disable Security Tools | 🟦 Prevented | Stable |
| Credential Access | T1003.001 LSASS access | 🟩 Alerted | Telemetry validated |
| Discovery | T1087.002 · T1082 · T1016 · T1057 · T1033 · T1018 | 🟥 Missed (native tools) | ✅ Closed by D1, clustered discovery |
| Persistence | T1547.001 Run keys | 🟩 Alerted | ✅ Closed by D3, works for any writer |
| Lateral Movement | T1021.002 · T1550.002 · T1078 | 🟥 Missed within a zone | ✅ Closed by D2, workstation-to-workstation auth |
| Command & Control | T1071.001 Web C2 | 🟩 on connect · 🟨 sustained beacon | ⛏ Backlog: beaconing (→ Beacon Hunter) |
| Collection | T1005 · T1565.001 | 🟩 canary · 🟨 off-canary | ⛏ Backlog: wider file monitoring |
| Exfiltration | T1041 | 🟩 to known IOC · 🟥 unknown destination | ⛏ Backlog: IOC-independent egress |

The 🟥 rows are the point: each was found by a scored operation, and three have
been turned into deployed detections. The ⛏ items are a known, prioritized backlog.

!!! info "Full write-ups"
    Incident reports for OP-001, OP-002 and OP-003 are in the
    [Casebook](../casebook/index.md).
