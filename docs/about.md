# About

<!-- PAGE: About
     On the site: https://dotslashtag.github.io/cyber-defense-lab/about/
     Menu: About -->

I'm **Joseph Henry Cariazo** (`dotslashtag` on GitHub). I've spent more than ten years
running enterprise infrastructure. Now I attack it and build the detections that catch it.

I'm looking for **security engineering, SOC engineering and detection engineering** roles,
and for infrastructure security work: Active Directory, segmentation and hardening.

This lab is where I practise the whole loop:

1. Collect the right telemetry.
2. Emulate a real intruder.
3. Score honestly what was caught and what wasn't.
4. Fix the gaps.
5. Prove the fix with a cold re-run.

<!-- BUTTONS: edit the text in [ ] and the link in ( ); keep { .md-button } -->
[:fontawesome-brands-linkedin: LinkedIn](https://www.linkedin.com/in/jhrcariazo){ .md-button .md-button--primary }
[:fontawesome-brands-github: GitHub](https://github.com/dotslashtag){ .md-button }

## What I can show you

| Skill | Where to see it |
|---|---|
| **Alert triage and investigation** | [Casebook](casebook/index.md): three incident reports with timeline, scope, indicators and response |
| **Threat hunting** | Severity-first hunts, and the query mistakes I caught before they mis-scored a result ([CASE-OP002 §10](casebook/op-002-stealth-tradecraft.md#10-analyst-notes-three-near-misses-in-my-own-queries)) |
| **Detection engineering** | [Detections](detections/index.md): Sigma, Wazuh and Splunk rules built from real misses, tested both ways in CI |
| **Purple teaming** | [Operations](operations/index.md) and [Results](operations/results.md): four scored operations and a blind re-run |
| **Security automation** | n8n enrichment and approval-gated response; [EVTX Hunter](tools/evtx-hunter.md) with a TheHive webhook |
| **Engineering judgement** | Default-deny segmentation, time-boxed and reversed exceptions, no automatic containment |

## Certifications

- ISC2 Certified in Cybersecurity (CC), 2024

Earlier:

- AWS Certified Solutions Architect – Associate, 2020
- CompTIA Security+, 2018
- VMware Certified Associate – Data Center Virtualization, 2015
- ITIL Foundation, 2015
- Cisco CCNA Security, 2014
- Cisco CCNA, 2013

## How I work

**What I do myself:**

- I built and run the lab: AD, segmentation, Wazuh, Splunk, n8n, TheHive.
- I plan and run every operation.
- I score the results.
- I make every change on the live systems and check that it works there.

**What AI does:** an AI coding assistant (Claude) writes most of the code, tests and documentation in this
repository, and drafts detection logic from the misses I find.

**How I check it:** nothing goes live or into a case until it has fired on the attack in my lab
and stayed quiet on normal activity. That check is what catches AI mistakes. For example, the
first AI draft of the Run-key search (D3) matched none of the 12 real events in my logs, and the
live test is what showed it.

I review each change before it is merged, and I'm working through every detection until I can
write and defend it on my own.

## Safety

Everything here was run in an isolated, authorized lab, and every attack action was
non-destructive: no credential dumping, no real data, no ransomware. IP ranges and
account names are lab values. Secrets are never committed; every push is checked by
a gitleaks secret scan.
