# EVTX Hunter

!!! note "Coming in Week 4"

**Why:** OP-002 showed that native-tool activity was *logged but not alerted*.
Finding it meant hand-written queries over archived events. This tool makes that
triage fast and repeatable.

**Planned features**

- Parse `.evtx` exports and Wazuh archive JSON
- Rebuild process trees from Sysmon Event 1 (process creation)
- Match events against Sigma rules from this repo's `detections/` folder
- Produce a timeline of findings to attach to a TheHive case
