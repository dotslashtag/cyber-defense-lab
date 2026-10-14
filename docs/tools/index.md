# SOC Tools

Small, focused analyzers built around problems this lab actually ran into. Each one
is tested on lab data and can send its findings into the n8n → TheHive pipeline.

| Tool | Problem it solves | Status |
|---|---|---|
| [Phishing Analyzer](phish-analyzer.md) | Triage a suspicious `.eml`: headers, authentication results, URLs, attachments | ⏳ Week 5 |
| [EVTX Hunter](evtx-hunter.md) | Fast triage of Sysmon/Windows event logs into process trees and a timeline | ✅ |
| [Beacon Hunter](beacon-hunter.md) | Find C2 beaconing and unusual egress without relying on known IOCs | ⏳ Week 6 |
| [Detection Heartbeat](detection-heartbeat.md) | Prove on a schedule that detections still fire; tell a dead rule from a silent agent | 🧪 Phase 1 |
