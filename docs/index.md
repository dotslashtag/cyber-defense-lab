---
hide:
  - navigation
  - toc
---

# Cyber Defense Lab

**A home SOC, built and run end to end:** telemetry → detection engineering →
purple-team operations → SOAR with human-approved response.

I built this lab to practise the work a SOC analyst and security engineer actually
does: collect the right telemetry, write detections, emulate real attacker behaviour,
score what was caught and what wasn't, then fix the gaps and prove the fix.

<div class="grid cards" markdown>

-   :material-sword-cross: **Purple-team operations**

    ---

    Four scored, assumed-breach operations across 9 ATT&CK tactics. Every outcome is
    graded Prevented, Alerted, Logged-only or Missed, including the misses.

    [:octicons-arrow-right-24: Operations](operations/index.md)

-   :material-radar: **Detection engineering**

    ---

    Wazuh rules and Splunk correlations built from real misses, each validated
    both ways: it fires on the technique and stays quiet on a normal baseline.

    [:octicons-arrow-right-24: Detections](detections/index.md)

-   :material-tools: **SOC tools**

    ---

    Analyzers for phishing email, Sysmon/EVTX and PCAP beaconing, each tested
    on data from this lab and wired into the SOAR pipeline.

    [:octicons-arrow-right-24: Tools](tools/index.md)

-   :material-file-document-outline: **Casebook**

    ---

    Incident reports for each operation, written as a SOC analyst would hand
    off a case.

    [:octicons-arrow-right-24: Casebook](casebook/index.md)

</div>

## By the numbers

| Metric | Value |
|---|---|
| Purple-team operations (scored, evidenced) | **4** (OP-001 to OP-004) |
| Single-technique playbooks validated | **25+** |
| ATT&CK techniques exercised | **17** across **9** tactics |
| Detection gaps found and then **closed** | **3** (native discovery, workstation-to-workstation lateral auth, Run-key mislabel) |
| Automatic containment actions | **0**: every response waits for a human approval |

## The stack

Wazuh 4.14 · Splunk 10.4 · Sysmon · OPNsense + Suricata · n8n · TheHive 5 ·
MISP 2.5 · MITRE Caldera 5.3 · Kali · Active Directory · Windows 10/11 · Ubuntu

[Explore the lab architecture](lab/architecture.md){ .md-button .md-button--primary }
[See the roadmap](roadmap.md){ .md-button }
