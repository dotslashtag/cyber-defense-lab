# SOC Tools

<!-- PAGE: SOC Tools (section front page)
     On the site: https://dotslashtag.github.io/cyber-defense-lab/tools/
     Menu: Tools -->

Small, focused tools built around problems this lab actually ran into. Each one is
tested on lab data and can send its findings into the n8n → TheHive pipeline.

| Tool | Problem it solves | Status |
|---|---|---|
| [EVTX Hunter](evtx-hunter.md) | Fast triage of Sysmon/Windows event logs into process trees and a timeline | ✅ |
| [Detection Heartbeat](detection-heartbeat.md) | Prove on a schedule that detections still fire; tell a broken rule from a silent agent | ✅ Phase 1 |
