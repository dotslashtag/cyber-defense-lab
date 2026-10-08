"""Generate the synthetic sample `op002-style-archives.json`.

A Wazuh archives.json-style export (one JSON object per line) telling a short
intrusion story modelled on lab operations OP-002/OP-003, mixed with normal
activity. It is synthetic: no real hosts, hashes or users beyond the lab's
fictional names. Run `python make_sample.py` to rebuild it.

Like real Wazuh output, string values carry doubled backslashes
(`C:\\\\Windows\\\\...`), which the reader has to undo.
"""

import json
from itertools import count
from pathlib import Path

OUT = Path(__file__).with_name("op002-style-archives.json")
SYSMON = "Microsoft-Windows-Sysmon/Operational"
OPS01 = ("010", "WIN11-OPS01", "WIN11-OPS01.soc.lab")
WIN10 = ("006", "Windows10", "Win10.soc.lab")

_ids = count(1)
_guid_ids = count(0x1000)
lines: list[str] = []


def guid() -> str:
    return f"{{4b1d0c2e-{next(_guid_ids):04x}-66f1-0a00-000000005e00}}"


def wz(value):
    """Mimic Wazuh's doubled backslashes inside eventchannel string values."""
    return value.replace("\\", "\\\\") if isinstance(value, str) else value


def emit(agent, ts, channel, event_id, eventdata, provider="Microsoft-Windows-Sysmon"):
    agent_id, agent_name, computer = agent
    record = {
        "timestamp": f"2026-09-28T{ts}.000+0000",
        "agent": {"id": agent_id, "name": agent_name},
        "manager": {"name": "wazuh"},
        "decoder": {"name": "windows_eventchannel"},
        "location": "EventChannel",
        "data": {
            "win": {
                "system": {
                    "providerName": provider,
                    "eventID": str(event_id),
                    "eventRecordID": str(next(_ids)),
                    "channel": channel,
                    "computer": computer,
                    "systemTime": f"2026-09-28T{ts}.1234567Z",
                },
                "eventdata": {k: wz(v) for k, v in eventdata.items()},
            }
        },
    }
    lines.append(json.dumps(record))


def proc(agent, ts, image, cmd, parent, user="SOC\\ops_user"):
    """Sysmon Event 1. `parent` is (guid, image, cmd) of the parent process."""
    g = guid()
    emit(agent, ts, SYSMON, 1, {
        "utcTime": f"2026-09-28 {ts}.123",
        "processGuid": g,
        "processId": str(4000 + len(lines)),
        "image": image,
        "commandLine": cmd,
        "user": user,
        "integrityLevel": "Medium",
        "parentProcessGuid": parent[0],
        "parentImage": parent[1],
        "parentCommandLine": parent[2],
    })
    return (g, image, cmd)


def regset(agent, ts, writer, key, details):
    """Sysmon Event 13 (registry value set) by `writer`, a (guid, image, cmd) tuple."""
    emit(agent, ts, SYSMON, 13, {
        "eventType": "SetValue",
        "utcTime": f"2026-09-28 {ts}.456",
        "processGuid": writer[0],
        "image": writer[1],
        "targetObject": key,
        "details": details,
    })


S32 = "C:\\Windows\\System32\\"
RUN = "HKU\\S-1-5-21-1111111111-2222222222-3333333333-1105\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
PS = S32 + "WindowsPowerShell\\v1.0\\powershell.exe"

# --- normal activity on WIN11-OPS01 -------------------------------------------
userinit = (guid(), S32 + "userinit.exe", "userinit.exe")
explorer = proc(OPS01, "08:00:00", "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE", userinit)
onedrive = proc(OPS01, "08:00:05",
                "C:\\Users\\ops_user\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
                "\"OneDrive.exe\" /background", explorer)
regset(OPS01, "08:00:06", onedrive, RUN + "OneDrive",
       "\"C:\\Users\\ops_user\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background")
agent = (guid(), "C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe", "wazuh-agent.exe")
for ts in ("08:05:00", "08:10:00", "08:15:00"):
    proc(OPS01, ts, S32 + "net.exe", "net user", agent, user="NT AUTHORITY\\SYSTEM")
proc(OPS01, "08:20:00", S32 + "ipconfig.exe", "ipconfig /renew", explorer)

# --- the intrusion: native discovery burst (OP-004 D1) -------------------------
cmd = proc(OPS01, "09:10:00", S32 + "cmd.exe", "\"C:\\Windows\\system32\\cmd.exe\"", explorer)
for ts, exe, line in [
    ("09:10:05", "whoami.exe", "whoami /all"),
    ("09:10:09", "systeminfo.exe", "systeminfo"),
    ("09:10:14", "ipconfig.exe", "ipconfig /all"),
    ("09:10:18", "net.exe", "net user"),
    ("09:10:22", "net.exe", "net localgroup administrators"),
    ("09:10:27", "tasklist.exe", "tasklist /v"),
    ("09:10:31", "quser.exe", "quser"),
    ("09:10:35", "ROUTE.EXE", "route print"),
    ("09:10:40", "NETSTAT.EXE", "netstat -ano"),
]:
    proc(OPS01, ts, S32 + exe, line, cmd)

# --- persistence via reg.exe (OP-004 D3) ---------------------------------------
reg = proc(OPS01, "09:12:00", S32 + "reg.exe",
           "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v OP002Persist "
           "/t REG_SZ /d C:\\Users\\Public\\sync.exe /f", cmd)
regset(OPS01, "09:12:00", reg, RUN + "OP002Persist", "C:\\Users\\Public\\sync.exe")

# --- PowerShell with ExecutionPolicy Bypass, then rundll32 ---------------------
ps = proc(OPS01, "09:15:00", PS, "powershell.exe -ep bypass -nop -c \"iex (gc C:\\Users\\Public\\s.ps1 -raw)\"", cmd)
proc(OPS01, "09:15:10", S32 + "rundll32.exe", "rundll32.exe C:\\Users\\Public\\helper.dll,Start", ps)
emit(OPS01, "09:16:00", SYSMON, 3, {
    "utcTime": "2026-09-28 09:16:00.010", "processGuid": ps[0], "image": PS,
    "protocol": "tcp", "sourceIp": "10.10.2.9", "destinationIp": "10.10.3.5", "destinationPort": "8083",
})

# --- an attempt to switch off Defender, blocked by Tamper Protection -----------
emit(OPS01, "09:16:30", "Microsoft-Windows-Windows Defender/Operational", 5013, {
    "value": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring = 0x1",
}, provider="Microsoft-Windows-Windows Defender")

# --- lateral logon to a peer workstation (OP-004 D2), plus normal logons -------
def logon(ts, logon_type, ip, user="labuser"):
    emit(WIN10, ts, "Security", 4624, {
        "targetUserName": user, "targetDomainName": "SOC", "logonType": str(logon_type),
        "ipAddress": ip, "ipPort": "64866" if ip.startswith("10.") else "0",
        "authenticationPackageName": "NTLM", "workstationName": "WIN11-OPS01",
    }, provider="Microsoft-Windows-Security-Auditing")

logon("08:30:00", 2, "127.0.0.1")
logon("08:31:00", 3, "::1")
logon("09:20:00", 3, "10.10.2.9")

OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"wrote {OUT.name}: {len(lines)} events")
