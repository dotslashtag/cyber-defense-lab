"""Run Sigma rules over normalised events and collect findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from evtx_hunter.sigma_eval import correlation_hits, rule_matches

SYSMON = "Microsoft-Windows-Sysmon/Operational"
SECURITY = "Security"

# Which events a Sigma logsource applies to: {key: [(channel, {event IDs} or None)]}.
# Without this, a rule like "Image endswith whoami.exe" written for process
# creation would also fire on network or registry events that carry an Image field.
LOGSOURCES: dict[tuple[str, str], list[tuple[str, set[int] | None]]] = {
    ("category", "process_creation"): [(SYSMON, {1}), (SECURITY, {4688})],
    ("category", "network_connection"): [(SYSMON, {3})],
    ("category", "image_load"): [(SYSMON, {7})],
    ("category", "file_event"): [(SYSMON, {11})],
    ("category", "registry_event"): [(SYSMON, {12, 13, 14})],
    ("category", "registry_add"): [(SYSMON, {12})],
    ("category", "registry_set"): [(SYSMON, {13})],
    ("category", "dns_query"): [(SYSMON, {22})],
    ("service", "security"): [(SECURITY, None)],
    ("service", "sysmon"): [(SYSMON, None)],
    ("service", "windefend"): [("Microsoft-Windows-Windows Defender/Operational", None)],
    ("service", "powershell"): [("Microsoft-Windows-PowerShell/Operational", None)],
}

LEVELS = ["informational", "low", "medium", "high", "critical"]


@dataclass
class Finding:
    rule_id: str
    title: str
    level: str
    tags: list[str]
    time: str | None
    host: str | None
    events: list[dict] = field(default_factory=list)
    correlation: bool = False

    @property
    def attack(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags if t.startswith("attack.t")]


def load_rules(paths: list[str | Path]) -> SigmaCollection:
    """Load every Sigma rule under the given files/folders as one collection."""
    files: list[Path] = []
    for p in map(Path, paths):
        files.extend(sorted(p.rglob("*.yml")) if p.is_dir() else [p])
    if not files:
        raise FileNotFoundError(f"no Sigma rules found in {', '.join(map(str, paths))}")
    # One multi-document stream, so correlations can resolve rules in other files.
    return SigmaCollection.from_yaml("\n---\n".join(f.read_text() for f in files))


def applies_to(rule: SigmaRule, event: dict) -> bool:
    """True if the event comes from the log source the rule was written for."""
    ls = rule.logsource
    key = ("category", ls.category) if ls.category else ("service", ls.service)
    targets = LOGSOURCES.get(key)
    if targets is None:
        return True  # unknown log source: let the detection logic decide
    channel = (event.get("Channel") or "").lower()
    return any(
        channel == ch.lower() and (ids is None or event.get("EventID") in ids)
        for ch, ids in targets
    )


def _level(rule) -> str:
    return rule.level.name.lower() if rule.level else "informational"


def _tags(rule) -> list[str]:
    return [str(t) for t in rule.tags]


def hunt(events: list[dict], rules: SigmaCollection, min_level: str = "low") -> list[Finding]:
    """Evaluate all rules; return findings at or above `min_level`, oldest first.

    Base rules referenced by a correlation (and below `min_level`) are used only
    as input to that correlation, so on their own they do not create findings.
    """
    floor = LEVELS.index(min_level)
    findings: list[Finding] = []

    for rule in rules:
        if isinstance(rule, SigmaCorrelationRule):
            base = [r.rule for r in rule.rules]
            scoped = [e for e in events if e.get("_time") and any(applies_to(b, e) for b in base)]
            for _key, window in correlation_hits(rule, scoped):
                # A correlation inherits the ATT&CK techniques of the rules it counts.
                tags = list(dict.fromkeys(_tags(rule) + [t for b in base for t in _tags(b)]))
                findings.append(
                    Finding(str(rule.id), rule.title, _level(rule), tags,
                            window[0].get("_time"), window[0].get("Computer"),
                            window, correlation=True)
                )
            continue

        if LEVELS.index(_level(rule)) < floor:
            continue
        for event in events:
            if applies_to(rule, event) and rule_matches(rule, event):
                findings.append(
                    Finding(str(rule.id), rule.title, _level(rule), _tags(rule),
                            event.get("_time"), event.get("Computer"), [event])
                )

    findings = [f for f in findings if LEVELS.index(f.level) >= floor]
    return sorted(findings, key=lambda f: f.time or "")

