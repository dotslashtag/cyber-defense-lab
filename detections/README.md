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
issues. Each fix is made on the manager first, validated with a live test on an
endpoint, then mirrored here; open rows are still waiting for that.

| Rule | Issue | Suggested fix |
|---|---|---|
| `510132` "Successful login after brute force" (L14) | ✅ **Fixed 2026-10-12.** It never checked that the current event **is a successful logon**, and its `same_srcip` could not match on Windows events. Remote logons are claimed by the level-0 stock rule `92651` (a child of `60106`), so a plain `if_sid 60106` child would lose too. Now `if_group authentication_success` + `if_matched_sid 510130` + `same_field win.eventdata.ipAddress`, 4624 type 3/10 only, computer accounts skipped. Validated live: 9 failures then a success from the same IP → `510130` then `510132`; the same success 12 minutes later → `60106` only | Done |
| `510122` account lockout | ✅ **Fixed 2026-10-12.** Its parent `60106` only matches logon-success IDs (4624 etc.), so a 4740 lockout never reached it. Now `if_sid 60115` (stock lockout rule). Validated live: a local test account locked out on WIN11-OPS01 → `510122` | Done |
| `510133` "Lateral movement attempt" (T1021) | Same trigger as `510130`/`510131` (failed logons from one IP) with a lower bar of 3 in 5 minutes; nothing checks workstation → server. It is a "3 failures" rule with a lateral-movement label, the same mislabel problem fixed in D3 | Rename and re-tag as low-severity brute-force precursor, or add a real workstation-source condition |
| `510130` / `510131` | ✅ **Fixed 2026-10-12.** Both compared the source IP with `same_srcip`, but Wazuh never sets `srcip` on Windows eventchannel events (the IP is in `win.eventdata.ipAddress`), so **neither could fire**: a live burst of 12 failed logons from one IP raised nothing. `510131` also didn't require different users and carried a `lateral_movement` tag. Now `same_field win.eventdata.ipAddress`, plus `different_field win.eventdata.targetUserName` on `510131`. Validated live: 12 users from one IP → `510130` then `510131`; 12 failures for one user → `510130` only | Done |
| `510120`, `510123`, `510133` | Same IP comparison (`same_source_ip` / `same_srcip`) as the old `510130`/`510131`, so most likely also unable to fire on Windows events | Switch to `same_field win.eventdata.ipAddress` as each rule is fixed, and re-test live |
| `510120`/`510123` vs `510130`/`510131` | Two families detect the same burst from different parents, so one attack may raise several alerts. Checked live 2026-10-12: a spray raises `510130` (8th failure) and then `510131` (11th), which is an intended escalation, not a duplicate. `510123` did not fire, consistent with the IP-field issue above | Revisit once `510120`/`510123` can fire |
| `510143` | ✅ **Fixed 2026-10-12.** Parent had to be `powershell.exe`, so `pwsh.exe` (PowerShell 7) was missed. Now `(?i)\\(powershell\|pwsh)\.exe$`; validated live (powershell and pwsh alert, cmd stays quiet) | Done |
| `510140` | ✅ **Fixed 2026-10-12.** It was never reached on WIN11-OPS01: its parent `92027` no longer fires because the SOCFortress rule `100162` now classifies Sysmon PowerShell process events. It also missed `-ep` / `-exec`. Now `if_sid 92027, 100162` with the wider pattern; validated live (3/3 bypass forms alert, `RemoteSigned` stays quiet) | Done |

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
