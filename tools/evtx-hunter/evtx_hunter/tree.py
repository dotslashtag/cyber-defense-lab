"""Rebuild process trees from Sysmon process-creation events (Event ID 1).

Sysmon gives every process a ProcessGuid and records its parent's GUID, which,
unlike a process ID, is never reused. That makes the parent links reliable even
on a long-running host where PIDs repeat.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from evtx_hunter.hunt import SYSMON


@dataclass
class Proc:
    guid: str
    image: str
    command_line: str
    user: str | None
    time: str | None
    host: str | None
    parent_guid: str | None
    parent_image: str | None
    children: list["Proc"] = field(default_factory=list)
    marks: list[str] = field(default_factory=list)


def _base(path: str | None) -> str:
    return (path or "?").replace("/", "\\").rsplit("\\", 1)[-1]


def build(events: list[dict]) -> dict[str, Proc]:
    """Index Sysmon Event 1 records by ProcessGuid and link children to parents."""
    procs: dict[str, Proc] = {}
    for e in events:
        if e.get("EventID") != 1 or (e.get("Channel") or "").lower() != SYSMON.lower():
            continue
        guid = e.get("ProcessGuid")
        if not guid:
            continue
        procs[guid] = Proc(
            guid=guid,
            image=e.get("Image") or "?",
            command_line=e.get("CommandLine") or "",
            user=e.get("User"),
            time=e.get("_time"),
            host=e.get("Computer"),
            parent_guid=e.get("ParentProcessGuid"),
            parent_image=e.get("ParentImage"),
        )
    for p in procs.values():
        parent = procs.get(p.parent_guid or "")
        if parent is not None:
            parent.children.append(p)
    for p in procs.values():
        p.children.sort(key=lambda c: c.time or "")
    return procs


def roots(procs: dict[str, Proc]) -> list[Proc]:
    """Processes whose parent was not captured (the top of each visible tree)."""
    return sorted(
        (p for p in procs.values() if p.parent_guid not in procs),
        key=lambda p: p.time or "",
    )


def focus(procs: dict[str, Proc], guids: set[str]) -> set[str]:
    """The given processes plus all their ancestors and descendants."""
    keep: set[str] = set()
    for guid in guids:
        p = procs.get(guid)
        while p is not None and p.guid not in keep:  # walk up
            keep.add(p.guid)
            p = procs.get(p.parent_guid or "")
        stack = [procs[guid]] if guid in procs else []
        while stack:  # walk down
            node = stack.pop()
            keep.add(node.guid)
            stack.extend(node.children)
    return keep


def render(procs: dict[str, Proc], only: set[str] | None = None, width: int = 110) -> str:
    """ASCII tree. `only` limits output to these GUIDs; marked processes get ◀ notes."""
    lines: list[str] = []

    def walk(p: Proc, prefix: str, last: bool, top: bool) -> None:
        if only is not None and p.guid not in only:
            return
        time = (p.time or "")[11:19]
        label = f"{time} {_base(p.image)}"
        if p.command_line:
            label += f"  {p.command_line}"
        if len(label) > width:
            label = label[: width - 1] + "…"
        if p.marks:
            label += "  ◀ " + "; ".join(p.marks)
        connector = "" if top else ("└─ " if last else "├─ ")
        lines.append(f"{prefix}{connector}{label}")
        kids = [c for c in p.children if only is None or c.guid in only]
        child_prefix = prefix if top else prefix + ("   " if last else "│  ")
        for i, c in enumerate(kids):
            walk(c, child_prefix, i == len(kids) - 1, False)

    for r in roots(procs):
        if only is not None and r.guid not in only:
            continue
        host = f" [{r.host}]" if r.host else ""
        lines.append(f"({_base(r.parent_image)}){host}")
        walk(r, "  ", True, False)
    return "\n".join(lines)
