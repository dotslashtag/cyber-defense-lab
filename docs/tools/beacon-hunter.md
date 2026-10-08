# Beacon Hunter

!!! note "Coming in Week 6"

**Why:** in OP-001/002, C2 was caught when it first connected to a known IOC, but
the **sustained beacon** and **exfiltration to an unknown destination** were not.
This tool goes after that backlog item.

**Planned features**

- Read PCAP or Zeek `conn.log`
- Score connection regularity (interval and jitter) to flag beaconing
- Flag unusual egress by volume and destination, without needing an IOC list
- Validated against a controlled lab beacon capture
