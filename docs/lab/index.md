# The Lab

A segmented home SOC running in VMware Workstation, built to emulate a small
enterprise and the security team that defends it.

## Principles

- **Build → Test → Capture → Document.** Every use case goes from telemetry, to a
  controlled emulation, to detection in both Wazuh and Splunk, to evidence and an
  ATT&CK mapping.
- **Default deny.** Four zones separated by OPNsense. Any test exception is logged,
  time-limited and removed afterwards.
- **Humans approve response.** Automation enriches and recommends; a signed Slack
  approval is required before any containment action.
- **Non-destructive emulation.** No credential dumping, no ransomware, and
  exfiltration only to lab hosts.

## Components

| Function | Tooling |
|---|---|
| Firewall, routing, network IDS | OPNsense 26.7, Suricata (ET Open) |
| Endpoint telemetry / XDR | Wazuh 4.14.7, Sysmon (Olaf Hartong's sysmon-modular), PowerShell 4103/4104 logging |
| SIEM analytics and hunting | Splunk 10.4.3 |
| SOAR | n8n with Redis duplicate protection and signed Slack approvals |
| Case management | TheHive 5.6 |
| Threat intelligence | MISP 2.5 (cached OSINT feeds), VirusTotal, AbuseIPDB |
| Adversary emulation | MITRE Caldera 5.3, Kali Linux |
| Identity | Windows Server 2022 Active Directory (`soc.lab`) |
| Endpoints | Windows 10, Windows 11, Ubuntu 24.04 |

See [Architecture](architecture.md) for zones and data flow.
