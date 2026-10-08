# About

I'm **dotslashtag**, working toward SOC analyst, detection engineering and
security automation roles. This lab is where I practise the whole loop: collect
the right telemetry, emulate a real intruder, score honestly what was caught and
what wasn't, fix the gaps, and prove the fix with a cold re-run.

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

## How this was built

I designed and ran the lab, the operations, the detections and the validation. AI
assistants helped write tool code and documentation; every tool is tested against
data from my own lab, and I can walk through how each one works.

## Safety

Everything here was run in an isolated, authorized lab, and every attack action was
non-destructive: no credential dumping, no real data, no ransomware. IP ranges and
account names are lab values. Secrets are never committed; every push is checked by
a gitleaks secret scan.
