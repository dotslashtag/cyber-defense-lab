from evtx_hunter.hunt import applies_to, hunt

EXPECTED = {
    "Clustered Native Discovery Activity",
    "Run/RunOnce Key Modified By Script Host Or LOLBin",
    "PowerShell Launched With ExecutionPolicy Bypass",
    "Rundll32 Spawned By PowerShell",
    "Defender Tamper Protection Blocked A Configuration Change",
    "Workstation-To-Workstation Network Logon",
}


def test_sample_story_is_found(events, rules):
    findings = hunt(events, rules)
    assert {f.title for f in findings} == EXPECTED
    assert [f.time for f in findings] == sorted(f.time for f in findings)


def test_benign_activity_is_not_flagged(events, rules):
    findings = hunt(events, rules)
    flagged = {e.get("_source") for f in findings for e in f.events}
    benign = [e for e in events
              if "OneDrive" in (e.get("Image") or "")
              or "wazuh-agent" in (e.get("ParentImage") or "")
              or e.get("IpAddress") in ("127.0.0.1", "::1")]
    assert benign, "sample should contain benign events"
    assert not flagged & {e["_source"] for e in benign}


def test_correlation_window_and_tags(events, rules):
    d1 = next(f for f in hunt(events, rules) if f.correlation)
    assert d1.host == "WIN11-OPS01.soc.lab"
    # the 08:20 ipconfig /renew is an hour earlier and must not be in the window
    assert all(e["_time"] >= "2026-09-28T09:10" for e in d1.events)
    assert "T1033" in d1.attack  # inherited from the base rule


def test_informational_base_rule_is_not_reported_alone(events, rules):
    titles = {f.title for f in hunt(events, rules)}
    assert "Native Windows Discovery Command" not in titles
    titles_all = {f.title for f in hunt(events, rules, min_level="informational")}
    assert "Native Windows Discovery Command" in titles_all


def test_min_level_high(events, rules):
    assert {f.level for f in hunt(events, rules, min_level="high")} == {"high"}


def test_logsource_scoping(rules):
    """A process-creation rule must not fire on a registry or network event."""
    rundll = next(r for r in rules if r.title == "Rundll32 Spawned By PowerShell")
    proc = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}
    netconn = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 3}
    security = {"Channel": "Security", "EventID": 4688}
    assert applies_to(rundll, proc)
    assert applies_to(rundll, security)
    assert not applies_to(rundll, netconn)
