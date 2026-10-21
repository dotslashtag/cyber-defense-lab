# About

<!-- PAGE: About
     On the site: https://dotslashtag.github.io/cyber-defense-lab/about/
     Menu: About -->

I'm **Joseph Henry Cariazo** (`dotslashtag` on GitHub). For more than ten years I ran
enterprise infrastructure: Active Directory, networks, virtualization and the change
control that kept them up. I'm now moving into security, and this lab is how I prove I
can do the work, not just describe it.

**I'm looking for:** security engineering, SOC engineering and detection engineering
roles, and infrastructure security work (Active Directory, segmentation, hardening).

<!-- BUTTONS: edit the text in [ ] and the link in ( ); keep { .md-button } -->
[:fontawesome-brands-linkedin: Message me on LinkedIn](https://www.linkedin.com/in/jhrcariazo){ .md-button .md-button--primary }
[:fontawesome-brands-github: GitHub](https://github.com/dotslashtag){ .md-button }

## What I bring from infrastructure

<!-- TIP: add one real number per line if you can (users, sites, servers, team size) -->

- **I know how the systems work.** I built and ran the AD, network and server estates
  that attackers target, so I read their logs as an operator, not only as an analyst.
- **Change control and uptime.** Every detection and exception in this lab is planned,
  tested, time-boxed and reversed, the same way I handled production changes.
- **Working across teams.** Security engineers spend much of their time asking IT teams
  to change things. I've been on the other side of that request for a decade.
- **Explaining risk to managers.** As an IT Infrastructure Manager I had to justify changes
  in business terms, so I write for the person who has to make the decision.

## What I can show you

| Skill | Where to see it |
|---|---|
| **Detection engineering** | [Detections](detections/index.md): Sigma, Wazuh and Splunk rules built from real misses, tested both ways in CI |
| **Purple teaming** | [Operations](operations/index.md) and [Results](operations/results.md): four scored operations and a blind re-run that caught 4 of 5 techniques cold |
| **Infrastructure security** | [The Lab](lab/index.md): an AD domain behind default-deny segmentation, with every test exception logged and reversed |
| **Security automation** | [Approval-gated SOAR](lab/soar.md): n8n enrichment and response where a human approves every action; [EVTX Hunter](tools/evtx-hunter.md) with a TheHive webhook |
| **Investigation** | [Casebook](casebook/index.md): three incident reports with timeline, scope, indicators and response |
| **Threat hunting** | Severity-first hunts, and the query mistakes I caught before they mis-scored a result ([CASE-OP002 §10](casebook/op-002-stealth-tradecraft.md#10-analyst-notes-three-near-misses-in-my-own-queries)) |
| **Keeping detections working** | [Detection Heartbeat](tools/detection-heartbeat.md): scheduled end-to-end tests that tell a broken rule apart from a silent agent |

**Also hands-on with:**

- [MyDFIR SOC course](https://academy.mydfir.com/p/soc): investigations across email, identity,
  Active Directory, network, malware and endpoint; threat hunting with Sigma; Splunk.
  Coursework complete, capstone in progress
- [TCM Security: Security Operations (SOC) 201](https://tcm-sec.com/academy/security-operations-soc-201/): completed
- Microsoft Sentinel and KQL (30-Day MYDFIR Microsoft SOC Challenge)
- TryHackMe: more than 60 rooms completed

## How I work with AI

**What I do myself:** I built and run the lab (AD, segmentation, Wazuh, Splunk, n8n,
TheHive), plan and run every operation, score the results, and make and verify every
change on the live systems.

**What AI does:** an AI coding assistant (Claude) writes most of the code, tests and
documentation in this repository, and drafts detection logic from the misses I find.

**How I check it:** nothing goes live or into a case until it has fired on the attack in
my lab and stayed quiet on normal activity. That test is what catches AI mistakes. For
example, the first AI draft of the Run-key search (D3) matched none of the 12 real events
in my logs, and the live test is what showed it.

I review each change before it is merged, and I'm working through every detection until I
can write and defend it on my own. What's next is on the [Roadmap](roadmap.md).

## Certifications

- ISC2 Certified in Cybersecurity (CC), 2024

From my infrastructure career:

- AWS Certified Solutions Architect – Associate, 2020
- CompTIA Security+, 2018
- VMware Certified Associate – Data Center Virtualization, 2015
- ITIL Foundation, 2015
- Cisco CCNA Security, 2014
- Cisco CCNA, 2013

## Safety

Everything here was run in an isolated, authorized lab, and every attack action was
non-destructive: no credential dumping, no real data, no ransomware. IP ranges and
account names are lab values. Secrets are never committed; every push is checked by
a gitleaks secret scan.
