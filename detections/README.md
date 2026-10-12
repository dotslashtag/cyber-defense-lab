# Detections

Detection-as-code for the lab. Every rule here was built from a real finding in a
purple-team operation, and every rule has tests: attack samples it **must fire on**
and benign samples it **must stay quiet on**. CI runs them on every push.

## Layout

```text
detections/
├── sigma/windows/          Portable Sigma rules (convert to any SIEM)
├── wazuh/local_rules.xml   The custom Wazuh rules deployed in the lab (510100-510199)
├── splunk/                 Deployed Splunk correlation searches + savedsearches.conf
└── tests/
    ├── cases/sigma/        Must-fire / must-stay-quiet events per Sigma rule
    ├── cases/wazuh/        Same, per Wazuh rule ID
    ├── test_sigma.py       Metadata, Splunk conversion, positive/negative tests
    └── test_wazuh.py       Structure checks + field-pattern tests
```

## Detection inventory

| Detection | ATT&CK | Wazuh | Splunk | Sigma | Origin |
|---|---|---|---|---|---|
| PowerShell with ExecutionPolicy Bypass | T1059.001 | `510140` | | ✅ | PB-003 |
| Defender Tamper Protection blocked a change | T1562.001 | `510142` | | ✅ | PB-005, OP-001 |
| Rundll32 spawned by PowerShell | T1218.011 | `510143` | | ✅ | PB-009 |
| Connection to a controlled IOC IP | (none on purpose) | `510144` | | | PB-010/017/019 |
| Run/RunOnce key written by a script host | T1547.001 | `510150` | | | PB-012, OP-001/002 |
| Run/RunOnce key written by a script host or LOLBin (**D3**) | T1547.001 | | ✅ | ✅ | OP-004 |
| Clustered native discovery (**D1**) | T1033, T1082, T1016, T1057, T1087, T1018 | | ✅ | ✅ (correlation) | OP-002 → OP-004 |
| Workstation-to-workstation logon (**D2**) | T1021.002, T1550.002, T1078 | | ✅ | ✅ | OP-003 → OP-004 |

## Run the tests

```bash
pip install -r requirements-detections.txt -e tools/evtx-hunter
pytest detections/tests -v
```

Convert a Sigma rule to Splunk SPL:

```bash
sigma convert -t splunk detections/sigma/windows/proc_creation_rundll32_spawned_by_powershell.yml
```
*(needs `sigma-cli`)*

## What the tests do and don't cover

- **Sigma:** each rule is parsed by pySigma, converted to Splunk, and evaluated
  against its sample events by the evaluator in
  [`tools/evtx-hunter`](../tools/evtx-hunter) (the same engine that hunts with these rules), including the correlation rule's 10-minute
  sliding window.
- **Wazuh:** rule IDs, structure and ATT&CK tags are checked, and each rule's own
  field patterns are run against sample alerts. The parent rule (`if_sid`) and the
  decoder are not run here; that needs a Wazuh manager (`wazuh-logtest`). The
  IOC-list rule `510144` can only be tested on the manager.
- **Splunk:** the `.spl` files are the searches deployed in the lab, validated
  there against live data (see OP-004). They are not executed in CI.
- Sample events are representative events based on the lab's validation runs, not raw
  log exports.

## Tuning notes on the deployed D3 search

Comparing the exported D3 SPL with its Sigma version found three things to fix in
the lab (tracked in the lab's owner checklist):

1. **Key match is too loose.** `like(target, "%currentversion%run%")` also matches
   `Explorer\RunMRU` (Win+R history) and `Uninstall` entries with "Run" in the name.
   The Sigma version lists the Run-style keys explicitly, ending in a backslash.
2. **`dedup event_record_id` can drop real events.** Record IDs are only unique per
   host and channel, so two hosts can share one. Dedup on host plus record ID.
3. **No host in the output.** Add the agent name so triage starts with *which machine*.

The deployed search is published unchanged in `splunk/`; the Sigma rule already
has the fixes and tests for 1. Proposed v2 for the lab (not yet deployed):

```spl
index=wazuh_archives sourcetype=wazuh_archives "EventChannel"
| rex field=_raw "\((?<agent_name>[^)]+)\)\s+any->EventChannel"
| rex field=_raw "(?<event_json>\{\"win\":.*)$"
| spath input=event_json path=win.system.eventID output=event_id
| spath input=event_json path=win.system.eventRecordID output=event_record_id
| spath input=event_json path=win.eventdata.targetObject output=target_object
| spath input=event_json path=win.eventdata.image output=source_image
| spath input=event_json path=win.eventdata.details output=details
| eval target_lower=lower(target_object), source_lower=lower(source_image)
| where event_id="13"
    AND match(target_lower, "\\\\currentversion\\\\(run|runonce|runonceex|runservices|runservicesonce|policies\\\\explorer\\\\run)\\\\")
| where match(source_lower, "\\\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|reg)\.exe$")
| dedup agent_name event_record_id
| table _time agent_name source_image target_object details
| sort 0 - _time
```

Validate it the same way as D1/D2 before switching: it must still fire on the
OP-001/OP-002 Run-key writes, and return nothing over a normal week.

## Adding a detection

1. Add the rule (`sigma/`, `wazuh/local_rules.xml`, or both).
2. Add `tests/cases/sigma/<rule-file-name>.yml` or `tests/cases/wazuh/<rule-id>.yml`
   with at least one `positive` and one `negative` case.
3. `pytest detections/tests`: CI blocks the merge if a rule has no tests.
