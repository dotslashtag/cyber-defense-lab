---
title: Home
hide:
  - navigation
  - toc
---

<div class="cdl-hero" markdown>

<!-- KICKER: small teal line above the headline (name + target roles) -->
<p class="cdl-kicker">Joseph Henry Cariazo · security engineering · detection engineering · infrastructure security</p>

<!-- HEADLINE: the one big claim (the # makes it the largest heading) -->
# 10+ years running enterprise infrastructure. Now I attack it and build the detections that catch it.

<!-- SUMMARY: 2–3 sentences under the headline that back up the claim -->
A home SOC built like a small enterprise: an Active Directory domain behind OPNsense and Suricata, with management, target and attack zones separated under default-deny. It’s monitored by Wazuh, Splunk and Sysmon, with n8n, TheHive and MISP for human-approved response. I attack it with MITRE Caldera and Kali, score each step Prevented, Alerted, Logged-only or Missed, turn every miss into a tested detection, and re-run it blind.

<!-- BUTTONS -->
[See the results](operations/results.md){ .md-button .md-button--primary }
[Read a case](casebook/op-002-stealth-tradecraft.md){ .md-button }
[Browse the code](https://github.com/dotslashtag/cyber-defense-lab){ .md-button }
[:fontawesome-brands-linkedin: LinkedIn](https://www.linkedin.com/in/jhrcariazo){ .md-button }

</div>

<!-- STAT TILES -->
<div class="cdl-stats" markdown>
<div class="cdl-stat"><div class="n">4</div><div class="l">scored purple-team operations across 9 ATT&CK tactics</div></div>
<div class="cdl-stat"><div class="n">17</div><div class="l">ATT&CK techniques exercised end to end</div></div>
<div class="cdl-stat"><div class="n">4 / 5</div><div class="l">techniques found cold in the blind re-run, decoy ignored</div></div>
<div class="cdl-stat"><div class="n">123</div><div class="l">automated tests on the detections and tools, run in CI</div></div>
<div class="cdl-stat"><div class="n">0</div><div class="l">automatic containment actions: every response waits for a human</div></div>
</div>

## The loop, in one picture

<!-- LOOP DIAGRAM: the project cycle in one picture (Mermaid draws it automatically) -->
```mermaid
flowchart LR
    B[Build<br/>AD lab + SIEM + SOAR] --> A[Attack<br/>Caldera / Kali]
    A --> S[Score every step<br/>Prevented · Alerted ·<br/>Logged-only · Missed]
    S --> D[Detect<br/>turn misses into<br/>tested detections]
    D --> R[Re-run blind<br/>prove the fix]
    R -->|next operation| A
    D --> H[Heartbeat<br/>keep proving it works]
```

<div class="cdl-ba" markdown>
<div markdown>
**Native discovery** · OP-002

<span class="cdl-pill missed">Missed</span> → <span class="cdl-pill alerted">Alerted</span>

Built D1: 4+ discovery tools on one host in 10 min. Caught cold in ~5 min.
</div>
<div markdown>
**Workstation → workstation logon** · OP-003

<span class="cdl-pill missed">Missed</span> → <span class="cdl-pill alerted">Alerted</span>

Built D2: logons between peer workstations. Caught cold in ~6 min.
</div>
<div markdown>
**Run-key persistence** · OP-001

<span class="cdl-pill logged">Logged-only</span> → <span class="cdl-pill alerted">Alerted</span>

Found why Wazuh was silent; wrote rule `510150`. Caught in seconds.
</div>
</div>

<figure class="cdl-wide" markdown>
![ATT&CK coverage heatmap: outcome per technique across OP-001 to OP-004](assets/img/attack-coverage.svg)
<figcaption>ATT&CK coverage after OP-001 to OP-004. Purple = a miss that OP-004 turned
into a working detection; amber = still logged-only, on the backlog.</figcaption>
</figure>

## Explore

<div class="grid cards cdl-two" markdown>

-   :material-sword-cross: **Operations & results**

    ---

    Four assumed-breach operations scored Prevented / Alerted / Logged-only /
    Missed, then a blind re-run to prove the fixes.

    [:octicons-arrow-right-24: Results](operations/results.md)

-   :material-file-document-outline: **Casebook**

    ---

    Incident reports written as a SOC analyst hands off a case: bottom line,
    timeline, scope, indicators, response, and what changed.

    [:octicons-arrow-right-24: Read the cases](casebook/index.md)

-   :material-radar: **Detections as code**

    ---

    Sigma, Wazuh and Splunk rules with must-fire and must-stay-quiet tests
    that run on every change.

    [:octicons-arrow-right-24: Detections](detections/index.md)

-   :material-tools: **SOC tools**

    ---

    EVTX Hunter: triage Windows logs with the same rules, rebuild process trees,
    and send findings to TheHive.

    [:octicons-arrow-right-24: Tools](tools/index.md)

</div>

## How the lab is built

Three internal zones (management, monitored endpoints, attacker) plus the WAN uplink, under default-deny,
with alerts flowing Wazuh → Splunk and high-severity alerts into n8n for
enrichment, a TheHive case and a signed Slack approval before any response.

[Architecture and data flow](lab/architecture.md){ .md-button }

**Stack:** Wazuh 4.14 · Splunk 10.4 · Sysmon · OPNsense + Suricata · n8n · TheHive 5 ·
MISP 2.5 · MITRE Caldera 5.3 · Kali · Active Directory · Windows 10/11 · Ubuntu
