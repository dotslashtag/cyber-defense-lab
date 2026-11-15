# The Lab

<!-- PAGE: The Lab (section front page)
     On the site: https://dotslashtag.github.io/cyber-defense-lab/lab/
     Menu: The Lab -->

A segmented home SOC running in VMware Workstation, built to emulate a small
enterprise and the security team that defends it.

## Principles

- **Build → Test → Capture → Document.** Every use case goes from telemetry, to a
  controlled emulation, to detection in both Wazuh and Splunk, to evidence and an
  ATT&CK mapping.
- **Default deny.** Three internal zones and the WAN uplink, separated by OPNsense. Any test exception is logged,
  time-limited and closed afterward (disabled or removed), then checked closed.
- **Humans approve response.** Automation enriches and recommends; a signed Slack
  approval is required before any containment action.
- **Non-destructive emulation.** No credential dumping, no ransomware, and
  exfiltration only to lab hosts.

## Components

| Function | Tooling |
|---|---|
| Firewall, routing, network IDS | OPNsense 26.7.9_1, Suricata (ET Open) |
| Endpoint telemetry / XDR | Wazuh 4.14.10, Sysmon (Olaf Hartong's sysmon-modular), PowerShell 4103/4104 logging |
| SIEM analytics and hunting | Splunk 10.4.3 |
| Web application firewall | ModSecurity + OWASP Core Rule Set 4.25 (detection mode) in front of OWASP Juice Shop |
| SOAR | n8n with Redis duplicate protection and signed Slack approvals |
| Case management | TheHive 5.6 |
| Threat intelligence | MISP 2.5 (cached OSINT feeds), VirusTotal, AbuseIPDB |
| Adversary emulation | MITRE Caldera 5.3, Kali Linux |
| Identity | Windows Server 2022 Active Directory (`soc.lab`) |
| Endpoints | Windows 10, Windows 11, Ubuntu 24.04, WEB01 (Ubuntu + Docker web app) |

See [Architecture](architecture.md) for zones and data flow.

## Production at home, and this lab

My home network runs like production: segmented VLANs and a DMZ behind OPNsense, no open
inbound ports (public traffic arrives through an outbound Cloudflare Tunnel), and monitoring
that alerts on failures. My household depends on it, so I never attack it.

This lab is the opposite: an isolated range where I attack my own Active Directory domain,
break things on purpose, and turn what I miss into tested detections.

[:material-home-variant: Home production network](https://dotslashtag.online/){ .md-button }
