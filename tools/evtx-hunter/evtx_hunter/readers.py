"""Read Windows events from EVTX files or Wazuh archives into one flat format.

Every event becomes a dict with the field names Sigma rules use: `EventID`,
`Channel`, `Computer`, `Provider_Name`, plus the event's own data fields
(`Image`, `CommandLine`, `TargetObject`, `IpAddress`, ...). Two extra keys
are added: `_time` (ISO-8601 UTC) and `_source` (file plus line or record number).
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterator

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_TS = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?")


def iso_utc(value: str | None) -> str | None:
    """Normalise Windows/Wazuh timestamps to `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`.

    Windows writes 7 fractional digits; Python's datetime handles 6, so the
    extra digit is dropped.
    """
    if not value:
        return None
    m = _TS.match(value.strip())
    if not m:
        return None
    frac = (m.group(3) or "")[:7]  # "." plus up to 6 digits
    return f"{m.group(1)}T{m.group(2)}{frac}Z"


# --------------------------------------------------------------------------- EVTX


def event_from_xml(xml: str, source: str = "") -> dict:
    """Convert one Windows event record (XML) into a flat event dict."""
    root = ET.fromstring(xml)
    system = root.find(f"{_NS}System")
    event: dict = {}
    if system is not None:
        provider = system.find(f"{_NS}Provider")
        event["Provider_Name"] = provider.get("Name") if provider is not None else None
        event["EventID"] = _int(system.findtext(f"{_NS}EventID"))
        event["Channel"] = system.findtext(f"{_NS}Channel")
        event["Computer"] = system.findtext(f"{_NS}Computer")
        created = system.find(f"{_NS}TimeCreated")
        event["_time"] = iso_utc(created.get("SystemTime") if created is not None else None)

    data = root.find(f"{_NS}EventData")
    if data is not None:
        for item in data.findall(f"{_NS}Data"):
            name = item.get("Name")
            if name:
                event[name] = item.text
    event["_source"] = source
    return event


def read_evtx(path: str | Path) -> Iterator[dict]:
    """Yield events from a `.evtx` file (needs the python-evtx package)."""
    from Evtx.Evtx import Evtx  # imported lazily: slow and only needed for EVTX

    path = Path(path)
    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                yield event_from_xml(record.xml(), f"{path.name}#{record.record_num()}")
            except ET.ParseError:
                continue  # a corrupt record should not stop the whole file


# -------------------------------------------------------------------- Wazuh JSON


def _wazuh_value(value):
    # Wazuh's eventchannel decoder doubles backslashes inside string values
    # ("C:\\\\Windows\\\\..."), so paths would never match a Sigma rule.
    if isinstance(value, str):
        return value.replace("\\\\", "\\")
    return value


def _sigma_name(key: str) -> str:
    # Wazuh lower-cases the first letter of each field (commandLine, targetObject).
    return key[:1].upper() + key[1:]


def event_from_wazuh(obj: dict, source: str = "") -> dict | None:
    """Convert one Wazuh alert/archive record into a flat event dict.

    Accepts both layouts: archives.json (`data.win`) and the JSON part of
    archives.log (`win` at the root). Returns None for non-Windows records.
    """
    win = (obj.get("data") or {}).get("win") or obj.get("win")
    if not isinstance(win, dict):
        return None
    system = win.get("system") or {}
    event: dict = {
        "EventID": _int(system.get("eventID")),
        "Channel": system.get("channel"),
        "Computer": system.get("computer"),
        "Provider_Name": system.get("providerName"),
        "_time": iso_utc(system.get("systemTime") or obj.get("timestamp")),
        "_agent": (obj.get("agent") or {}).get("name"),
        "_source": source,
    }
    for key, value in (win.get("eventdata") or {}).items():
        event[_sigma_name(key)] = _wazuh_value(value)
    return event


def read_wazuh(path: str | Path) -> Iterator[dict]:
    """Yield Windows events from a Wazuh archives.json / archives.log export.

    Lines may be pure JSON or carry a syslog-style prefix before the JSON
    (archives.log); anything that does not parse is skipped.
    """
    path = Path(path)
    with path.open(encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            start = line.find("{")
            if start < 0:
                continue
            try:
                obj = json.loads(line[start:])
            except json.JSONDecodeError:
                continue
            event = event_from_wazuh(obj, f"{path.name}:{lineno}")
            if event is not None:
                yield event


# ----------------------------------------------------------------------- helpers


def read_any(path: str | Path) -> Iterator[dict]:
    """Pick the reader from the file extension (.evtx, otherwise Wazuh JSON)."""
    path = Path(path)
    if path.suffix.lower() == ".evtx":
        yield from read_evtx(path)
    else:
        yield from read_wazuh(path)


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
