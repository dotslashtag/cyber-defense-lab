# Cyber Defense Lab

The public part of my home SOC lab, cleaned up for sharing. It holds the
detections, SOC analyzer tools, incident reports and portfolio site that came out
of running a full detect → investigate → respond loop against emulated attacks.

**Portfolio site:** https://dotslashtag.github.io/cyber-defense-lab/

## What's here

| Folder | What it is | Status |
|---|---|---|
| `docs/` | Portfolio hub site source (MkDocs Material → GitHub Pages) | ✅ Week 1 |
| `detections/` | Detection-as-code: Sigma, Wazuh XML and Splunk SPL, tested in CI against sample logs | ✅ Week 2 |
| `casebook/` | Incident reports for purple-team operations OP-001 to OP-003 | ✅ Week 3 |
| `tools/evtx-hunter/` | Sysmon/EVTX triage: process trees, Sigma matching, timelines | ⏳ Week 4 |
| `tools/phish-analyzer/` | Phishing `.eml` analyzer (CLI plus a browser demo; files never leave your browser) | ⏳ Week 5 |
| `tools/beacon-hunter/` | PCAP/Zeek beaconing and IOC-independent egress detection | ⏳ Week 6 |
| `n8n-workflows/` | Cleaned-up SOAR workflow exports (enrichment, human-approved response) | ⏳ |

## The lab behind it

- **SIEM/XDR:** Wazuh 4.14, Splunk 10.4, Sysmon (Olaf Hartong's sysmon-modular), OPNsense + Suricata
- **SOAR & case management:** n8n with signed Slack approvals, TheHive 5, MISP 2.5
- **Adversary emulation:** MITRE Caldera 5.3 + Kali, assumed-breach purple-team operations
- **Environment:** Active Directory (`soc.lab`), Windows 10/11, Ubuntu, four segmented zones under default-deny

Each operation is scored honestly (Prevented / Alerted / Logged-only / Missed) and
mapped to MITRE ATT&CK. Missed detections are rebuilt as new detections, which are
then checked both ways: they fire on the attack and stay quiet on normal activity.

## Safety & sanitization

- All activity was run in an isolated lab, and every attack action was non-destructive.
- Lab IPs (`10.10.x.x`) and fictional accounts are intentional.
- Secrets, tokens and webhook URLs are removed, and every push is checked by a gitleaks secret scan in CI.

## Build the site locally

```bash
pip install -r requirements-docs.txt
mkdocs serve   # http://127.0.0.1:8000
```

## License

Code is under the [MIT License](LICENSE).
