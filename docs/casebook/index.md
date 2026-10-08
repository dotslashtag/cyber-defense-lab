# Casebook

Incident reports for the lab's purple-team operations, written the way a SOC
analyst hands off a case: bottom line first, then the verdict, timeline, scope,
indicators, response, and what the detection gaps led to.

| Case | Scenario | Headline | Gaps → fixes |
|---|---|---|---|
| [CASE-OP001](op-001-commodity-intrusion.md) | Commodity intrusion, 7 stages on one workstation | Defender blocked delivery; 5 of 7 stages alerted, but the malware launch was hidden in a noisy rule | Run-key rule `510150`; file monitoring added to the endpoint baseline |
| [CASE-OP002](op-002-stealth-tradecraft.md) | The same attack, run quietly with built-in tools | A file left the network with no alert, one IP away from a listed address | D1 clustered discovery, D3 Run-key rename; beaconing backlog |
| [CASE-OP003](op-003-lateral-movement.md) | Valid-credential hop between two workstations | No alert on the hop, but execution on the target was blocked | D2 workstation-to-workstation logon |

!!! info "How these were run"
    Each operation was an **authorized, assumed-breach emulation** in an isolated
    lab using MITRE Caldera and Kali. Everything was non-destructive: no credential
    dumping, no real data, and every temporary exception was logged and reversed.
    Outcomes are scored 🟦 Prevented · 🟩 Alerted · 🟨 Logged-only · 🟥 Missed.
