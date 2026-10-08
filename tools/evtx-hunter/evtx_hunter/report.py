"""Turn findings into a Markdown triage report or a JSON payload."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from evtx_hunter import __version__, tree
from evtx_hunter.hunt import LEVELS, Finding

# Fields worth showing as evidence, in priority order.
EVIDENCE_FIELDS = [
    "Image", "CommandLine", "ParentImage", "TargetObject", "Details",
    "TargetUserName", "IpAddress", "LogonType", "DestinationIp", "DestinationPort",
    "QueryName", "TargetFilename", "Value",
]

# TheHive severities: 1 low, 2 medium, 3 high, 4 critical.
THEHIVE_SEVERITY = {"informational": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}


def evidence(event: dict) -> dict:
    return {k: event[k] for k in EVIDENCE_FIELDS if event.get(k) not in (None, "")}


def summary(events: list[dict], findings: list[Finding], inputs: list[str]) -> dict:
    times = sorted(e["_time"] for e in events if e.get("_time"))
    top = max((LEVELS.index(f.level) for f in findings), default=0)
    return {
        "inputs": inputs,
        "events": len(events),
        "hosts": sorted({e["Computer"] for e in events if e.get("Computer")}),
        "first_event": times[0] if times else None,
        "last_event": times[-1] if times else None,
        "findings": len(findings),
        "by_level": dict(Counter(f.level for f in findings)),
        "highest_level": LEVELS[top] if findings else None,
        "thehive_severity": THEHIVE_SEVERITY[LEVELS[top]] if findings else None,
    }


def to_json(events: list[dict], findings: list[Finding], inputs: list[str]) -> dict:
    """Payload for files or a webhook (e.g. n8n → TheHive alert)."""
    return {
        "tool": "evtx-hunter",
        "version": __version__,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": summary(events, findings, inputs),
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "level": f.level,
                "attack": f.attack,
                "time": f.time,
                "host": f.host,
                "correlation": f.correlation,
                "event_count": len(f.events),
                "evidence": [evidence(e) for e in f.events[:20]],
                "sources": [e.get("_source") for e in f.events[:20]],
            }
            for f in findings
        ],
    }


def mark_tree(procs: dict[str, tree.Proc], findings: list[Finding]) -> set[str]:
    """Attach finding titles to the processes involved; return their GUIDs."""
    hit: set[str] = set()
    for f in findings:
        for e in f.events:
            guid = e.get("ProcessGuid")
            if guid in procs:
                if f.title not in procs[guid].marks:
                    procs[guid].marks.append(f.title)
                hit.add(guid)
    return hit


def _short(ts: str | None) -> str:
    """`2026-09-28T09:10:05.123456Z` → `2026-09-28 09:10:05` for tables."""
    return ts[:19].replace("T", " ") if ts else ""


def _cell(text) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def to_markdown(events: list[dict], findings: list[Finding], inputs: list[str],
                show_tree: bool = True) -> str:
    s = summary(events, findings, inputs)
    out = [
        "# EVTX Hunter triage report",
        "",
        f"- **Inputs:** {', '.join(f'`{i}`' for i in inputs)}",
        f"- **Events parsed:** {s['events']} from {len(s['hosts'])} host(s): "
        + ", ".join(f"`{h}`" for h in s["hosts"]),
        f"- **Time range (UTC):** {_short(s['first_event'])} → {_short(s['last_event'])}",
        f"- **Findings:** {s['findings']}"
        + (" (" + ", ".join(f"{n} {lvl}" for lvl, n in sorted(
            s["by_level"].items(), key=lambda kv: -LEVELS.index(kv[0]))) + ")" if findings else ""),
        "",
    ]
    if not findings:
        out += ["No rule matched. That is not proof of absence: check the rules cover these log sources.", ""]
        return "\n".join(out)

    out += ["## Timeline of findings", "",
            "| Time (UTC) | Host | Level | Finding | ATT&CK | Key evidence |",
            "|---|---|---|---|---|---|"]
    for f in findings:
        ev = evidence(f.events[0]) if f.events else {}
        key = (ev.get("CommandLine") or ev.get("TargetObject") or ev.get("IpAddress")
               or next(iter(ev.values()), ""))
        if f.correlation:
            key = f"{len(f.events)} events: " + ", ".join(
                sorted({tree._base(e.get("Image")) for e in f.events}))
        out.append(f"| {_short(f.time)} | {f.host or ''} | {f.level} | {_cell(f.title)} | "
                   f"{', '.join(f.attack)} | `{_cell(key)[:120]}` |")
    out.append("")

    if show_tree:
        procs = tree.build(events)
        hit = mark_tree(procs, findings)
        if hit:
            out += ["## Process tree around the findings", "",
                    "Ancestors and descendants of every process involved in a finding. "
                    "◀ marks the finding.", "", "```text",
                    tree.render(procs, only=tree.focus(procs, hit)), "```", ""]

    out += ["## Findings in detail", ""]
    for i, f in enumerate(findings, 1):
        out += [f"### {i}. {f.title}", "",
                f"- **Level:** {f.level} · **ATT&CK:** {', '.join(f.attack) or 'n/a'} · "
                f"**Rule ID:** `{f.rule_id}`",
                f"- **Host:** `{f.host}` · **First event:** {_short(f.time)}"
                + (f" · **Events in window:** {len(f.events)}" if f.correlation else ""), ""]
        for e in f.events[:10]:
            fields = ", ".join(f"{k}=`{_cell(v)}`" for k, v in evidence(e).items())
            out.append(f"- {_short(e.get('_time'))} · EventID {e.get('EventID')} · {fields} "
                       f"_(source: {e.get('_source')})_")
        if len(f.events) > 10:
            out.append(f"- … {len(f.events) - 10} more")
        out.append("")

    out += ["## Suggested next steps", "",
            "1. Confirm or rule out each finding against the host's normal activity.",
            "2. Scope it: search for the same command lines, Run values and source IPs on other hosts.",
            "3. If confirmed, open a case and request containment through the approval workflow.",
            ""]
    return "\n".join(out)
