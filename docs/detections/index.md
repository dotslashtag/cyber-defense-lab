# Detections

!!! note "Coming in Week 2"
    This section will publish the lab's detections as code.

**What will be here**

- The deployed **Wazuh rules** (XML) and **Splunk correlation searches** (SPL),
  including the three detections built in OP-004:
    - **D1**: clustered native discovery
    - **D2**: workstation-to-workstation lateral authentication
    - **D3**: Run-key persistence written by any process
- **Sigma** versions of each rule, so they can be ported to other SIEMs.
- **Test samples** for each detection: one that must fire and one that must stay
  quiet, run automatically in CI.
- An ATT&CK Navigator layer showing coverage.
