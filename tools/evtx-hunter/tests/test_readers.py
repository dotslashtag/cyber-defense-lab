import json

from evtx_hunter.readers import event_from_wazuh, event_from_xml, iso_utc, read_wazuh

SYSMON_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-09-28T09:10:05.1234567Z"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN11-OPS01.soc.lab</Computer>
  </System>
  <EventData>
    <Data Name="ProcessGuid">{aaaa}</Data>
    <Data Name="Image">C:\\Windows\\System32\\whoami.exe</Data>
    <Data Name="CommandLine">whoami /all</Data>
    <Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data>
  </EventData>
</Event>"""


def test_evtx_xml_record_is_flattened():
    e = event_from_xml(SYSMON_XML, "x.evtx#1")
    assert e["EventID"] == 1
    assert e["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert e["Computer"] == "WIN11-OPS01.soc.lab"
    assert e["Image"] == "C:\\Windows\\System32\\whoami.exe"
    assert e["_time"] == "2026-09-28T09:10:05.123456Z"
    assert e["_source"] == "x.evtx#1"


def test_wazuh_doubled_backslashes_are_undone():
    obj = {"data": {"win": {
        "system": {"eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational",
                   "computer": "h", "systemTime": "2026-09-28T09:00:00.0000000Z"},
        "eventdata": {"image": "C:\\\\Windows\\\\System32\\\\cmd.exe", "commandLine": "cmd"},
    }}}
    e = event_from_wazuh(obj)
    assert e["Image"] == "C:\\Windows\\System32\\cmd.exe"
    assert e["CommandLine"] == "cmd"  # first letter upper-cased to Sigma naming
    assert e["EventID"] == 1


def test_archives_log_prefix_and_root_win(tmp_path):
    record = {"win": {"system": {"eventID": "4624", "channel": "Security", "computer": "h",
                                 "systemTime": "2026-09-28T09:20:00Z"},
                      "eventdata": {"logonType": "3", "ipAddress": "10.10.2.9"}}}
    path = tmp_path / "archives.log"
    path.write_text(
        "2026 Sep 28 09:20:00 (Windows10) any->EventChannel " + json.dumps(record) + "\n"
        "not json at all\n"
        '{"no_win": true}\n'
    )
    events = list(read_wazuh(path))
    assert len(events) == 1
    assert events[0]["LogonType"] == "3"
    assert events[0]["_source"] == "archives.log:1"


def test_timestamp_normalisation():
    assert iso_utc("2026-09-28 09:10:05.123") == "2026-09-28T09:10:05.123Z"
    assert iso_utc("2026-09-28T09:10:05Z") == "2026-09-28T09:10:05Z"
    assert iso_utc("garbage") is None


def test_sample_parses(events):
    assert len(events) == 26
    assert {e["Computer"] for e in events} == {"WIN11-OPS01.soc.lab", "Win10.soc.lab"}
    assert all(e["_time"] for e in events)
