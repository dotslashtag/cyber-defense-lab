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
| Brute force, no IOC needed | T1110.001 | `510130` | | | PB-001/002 |
| Password spray by volume | T1110.003 | `510131` | | | PB-002 |
| Successful logon after brute force | T1110.001, T1078 | `510132` | | | PB-001 |
| Repeated failed logons, early warning | T1110 | `510133` | | | PB-002 |
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
  decoder are not run here; that needs a live test on a Wazuh manager. The
  IOC-list rule `510144` and the frequency/correlation rules (`510120`–`510121`,
  `510130`–`510133`) can only be tested on the manager. `910001` is an n8n
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
| `510133` (was "Lateral movement attempt", T1021, L12) | ✅ **Fixed 2026-10-12.** It fired on 3 failed logons from one IP with nothing checking for lateral movement, and its `same_srcip` meant it could not fire at all. Re-tagged as a low-severity brute-force precursor (L6, T1110), `same_field win.eventdata.ipAddress`, `ignore="300"` so a burst alerts once. Validated live: 2 failures → nothing; 6 failures → one `510133` on the 3rd | Done |
| `510130` / `510131` | ✅ **Fixed 2026-10-12.** Both compared the source IP with `same_srcip`, but Wazuh never sets `srcip` on Windows eventchannel events (the IP is in `win.eventdata.ipAddress`), so **neither could fire**: a live burst of 12 failed logons from one IP raised nothing. `510131` also didn't require different users and carried a `lateral_movement` tag. Now `same_field win.eventdata.ipAddress`, plus `different_field win.eventdata.targetUserName` on `510131`. Validated live: 12 users from one IP → `510130` then `510131`; 12 failures for one user → `510130` only | Done |
| `510123` brute-force fallback | 🗑️ **Retired 2026-10-12.** 0 hits in 90 days: it counted events ending at the generic audit-failure rule `60105`, but logon failures end at `60122`; its `same_source_ip` could not match on Windows events; and `510130` now covers the same burst. Removed from the rules file and the n8n integration list; live check after removal: 3 failures → `510133`, no `510123` | Done |
| `510120` brute force from malicious IP | Same `same_source_ip` problem as the old `510130`/`510131`, so most likely unable to fire on Windows events | Switch to `same_field win.eventdata.ipAddress`; needs a live test from an IP on the malicious-IP list (Kali), planned for the next Kali session |
| `510120` vs `510130`/`510131` | Two families detect the same burst from different parents, so one attack may raise several alerts. Checked live 2026-10-12: a spray raises `510130` (8th failure) and then `510131` (11th), which is an intended escalation, not a duplicate. `510123` never fired and was retired | Revisit once `510120` can fire |
| `510143` | ✅ **Fixed 2026-10-12.** Parent had to be `powershell.exe`, so `pwsh.exe` (PowerShell 7) was missed. Now `(?i)\\(powershell\|pwsh)\.exe$`; validated live (powershell and pwsh alert, cmd stays quiet) | Done |
| `510140` | ✅ **Fixed 2026-10-12.** It was never reached on WIN11-OPS01: its parent `92027` no longer fires because the SOCFortress rule `100162` now classifies Sysmon PowerShell process events. It also missed `-ep` / `-exec`. Now `if_sid 92027, 100162` with the wider pattern; validated live (3/3 bypass forms alert, `RemoteSigned` stays quiet) | Done |

## D2 v2: workstation lookup (2026-10-13)

D2 v1 named its workstations inside the search: two Wazuh agent names and an IP
regex. That missed the third workstation (WIN11-PB026), and it broke silently when an
agent was re-added under a new name (`Win10` became `Windows10` on 2026-09-09). v2 reads
the workstation set from `splunk/lookups/soc_workstations.csv` (Windows hostname → IP)
and identifies the receiving host by the **Windows computer name in the event**, which
does not change when the agent is re-registered. Adding a workstation is one CSV row.

| Check | v1 | v2 |
|---|---|---|
| 60 days of 4624 type 3/10: OP-003 hop (09-28) and blind re-run hop (09-30) | 2 / 2 | 2 / 2 |
| Rows only one version returns | none | none |
| Self-logon on WIN11-OPS01 (source = destination), live | quiet | quiet |
| WIN11-PB026 user logging on to the DC (thousands of DC logons), live | quiet | quiet |
| Live hop WIN11-PB026 → Windows10 (`pb026_user`, type 3, 2026-10-13 03:17:39 UTC) | **missed** (10.10.2.8 not in its list) | **alert** |
| Live hop WIN11-PB026 → WIN11-OPS01 after Sysprep (`pb026_user`, type 3, 2026-10-13 05:58:30 UTC) | **missed** | **alert** |

**Lab findings from testing.** The first attempt, PB026 ↔ WIN11-OPS01, failed in both
directions (`0xc000006d` / `0x0`, NTLM and Kerberos, any account, no password involved).
Typing, NTLM settings, clock skew and the domain trust were each ruled out: WIN11-OPS01
was cloned from PB026 without Sysprep, so both share one machine SID and current Windows
refuses network logons between them. The hop was first
run PB026 → Windows10 instead, which first looked "missed" until Splunk showed the
Windows10 agent had stopped three minutes after it reconnected (a failed
`Restart-Service`), not a detection gap. Once the agent was running, D2 v2 fired.
PB026 was then Sysprepped (new machine SID) and rejoined; the PB026 → WIN11-OPS01
hop that had failed every time now succeeds, and D2 v2 caught it as well.

## D3 v2: tightened and redeployed (2026-10-13)

Publishing D3 found three problems, now fixed in the lab and in
`splunk/soc_run_runonce_key_modified.spl`:

1. **Key match was too loose.** `like(target, "%currentversion%run%")` also matched
   `Explorer\RunMRU` (Win+R history). v2 lists the Run-style keys explicitly.
2. **`dedup event_record_id` could drop real events.** Record IDs are only unique per
   host and channel. v2 dedups on host plus record ID.
3. **No host in the output.** v2 adds `agent_name`.

**Validation, before switching:**

| Check | v1 (old) | v2 |
|---|---|---|
| 60 days of real Run-key writes (OP-001, OP-002, PB-012, blind re-run; 12 key/host/writer combinations on 4 hosts) | 12 / 12 | 12 / 12 |
| Live `reg add ...\Run\D3v2Test` on WIN11-OPS01 | alert | alert |
| Live `reg add ...\Explorer\RunMRU\z` on WIN11-OPS01 | **false positive** | quiet |

**Lesson: test against real data, not just samples.** The first v2 draft matched
`\currentversion\run\` with single backslashes and passed every Sigma test, but on the
archive data it missed **all 12** real events: Wazuh double-escapes eventchannel strings,
so the decoded paths contain `\\` between parts. The side-by-side comparison against v1
caught it before deployment. v2 folds any run of backslashes to `/` before matching.
(EVTX Hunter already undoes the doubling when it reads Wazuh archives.)

## Adding a detection

1. Add the rule (`sigma/`, `wazuh/local_rules.xml`, or both).
2. Add `tests/cases/sigma/<rule-file-name>.yml` or `tests/cases/wazuh/<rule-id>.yml`
   with at least one `positive` and one `negative` case.
3. `pytest detections/tests`: CI blocks the merge if a rule has no tests.
