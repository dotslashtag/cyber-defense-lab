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
| Brute force / password spray from a known-bad IP (CDB-enriched) | T1110.001, T1110.003 | `510120`, `510121` | | | PB-001/002 |
| Brute force, no IOC needed | T1110.001 | `510123`, `510130` | | | PB-001/002 |
| Password spray by volume | T1110.003 | `510131` | | | PB-002 |
| Successful logon after brute force | T1110.001, T1078 | `510132` | | | PB-001 |
| Repeated failures labelled lateral movement | T1021 | `510133` | | | PB-002 |
| AD account lockout (4740, user accounts only) | T1110 | `510122` | | | PB-001/002 |

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
  IOC-list rule `510144` and the frequency/correlation rules (`510120`–`510121`,
  `510123`, `510130`–`510133`) can only be tested on the manager. `910001` is an n8n
  pipeline test marker, not a detection.
- **Splunk:** the `.spl` files are the searches deployed in the lab, validated
  there against live data (see OP-004). They are not executed in CI.
- Sample events are representative events based on the lab's validation runs, not raw
  log exports.

## Wazuh rule review

`wazuh/local_rules.xml` is the lab's live file. Reading it closely found these
issues; they are documented here rather than changed, because each fix needs
validating on the manager with `wazuh-logtest` first.

| Rule | Issue | Suggested fix |
|---|---|---|
| `510132` "Successful login after brute force" (L14) | Nothing in the rule checks that the current event **is a successful logon**. It only requires a prior `510130` and the same source IP within 10 minutes, so further failures from that IP could raise a "credential compromise" alert | Make it a child of the successful-logon (4624) rule with `if_sid`, keep `if_matched_sid 510130` + `same_srcip` |
| `510133` "Lateral movement attempt" (T1021) | Same trigger as `510130`/`510131` (failed logons from one IP) with a lower bar of 3 in 5 minutes; nothing checks workstation → server. It is a "3 failures" rule with a lateral-movement label, the same mislabel problem fixed in D3 | Rename and re-tag as low-severity brute-force precursor, or add a real workstation-source condition |
| `510131` "Password spray" | Counts failures from one IP but does not require **different users** (unlike `510121`, which uses `different_user`); its group also includes `lateral_movement` | Add `<different_user />`; drop the `lateral_movement` group |
| `510120`/`510123` vs `510130`/`510131` | Two families detect the same burst from different parents, so one attack may raise several alerts | Check in the lab which fire together; keep one family or chain them |
| `510143` | Parent must be `powershell.exe`; `pwsh.exe` (PowerShell 7) is missed | `(?i)\\(powershell\|pwsh)\.exe$` |
| `510140` | Only matches the full `-ExecutionPolicy`; `-ep bypass` / `-exec bypass` slip past | Use the Sigma version's pattern `(?i)\s[-/](ep\|ex[a-z]*)\s+bypass` |

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
