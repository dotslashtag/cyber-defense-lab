"""Command-line interface: `evtx-hunter hunt` and `evtx-hunter tree`."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

from evtx_hunter import __version__, tree
from evtx_hunter.hunt import LEVELS, hunt, load_rules
from evtx_hunter.readers import read_any
from evtx_hunter.report import to_json, to_markdown


def _default_rules() -> Path | None:
    """Look for this repo's detections/sigma folder from the current directory up."""
    for d in [Path.cwd(), *Path.cwd().parents]:
        candidate = d / "detections" / "sigma"
        if candidate.is_dir():
            return candidate
    return None


def _load(files: list[str]) -> list[dict]:
    missing = [f for f in files if not Path(f).is_file()]
    if missing:
        raise SystemExit(f"error: file not found: {', '.join(missing)}")
    events: list[dict] = []
    for f in files:
        events.extend(read_any(f))
    return events


def _post(url: str, payload: dict) -> int:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - user-supplied URL by design
        return resp.status


def cmd_hunt(args: argparse.Namespace) -> int:
    rules_paths = args.rules or ([_default_rules()] if _default_rules() else [])
    if not rules_paths:
        print("error: no rules given and no detections/sigma folder found; use --rules", file=sys.stderr)
        return 2
    rules = load_rules(rules_paths)
    events = _load(args.files)
    findings = hunt(events, rules, min_level=args.min_level)
    inputs = [Path(f).name for f in args.files]

    if args.format == "json":
        text = json.dumps(to_json(events, findings, inputs), indent=2)
    else:
        text = to_markdown(events, findings, inputs, show_tree=not args.no_tree)

    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.output}: {len(events)} events, {len(findings)} findings", file=sys.stderr)
    else:
        print(text)

    if args.webhook:
        if not findings and not args.send_empty:
            print("no findings: webhook not called (use --send-empty to send anyway)", file=sys.stderr)
        else:
            status = _post(args.webhook, to_json(events, findings, inputs))
            print(f"webhook: HTTP {status}", file=sys.stderr)

    return 1 if findings and args.fail_on_findings else 0


def cmd_tree(args: argparse.Namespace) -> int:
    events = _load(args.files)
    if args.host:
        events = [e for e in events if (e.get("Computer") or "").lower().startswith(args.host.lower())]
    procs = tree.build(events)
    only = None
    if args.grep:
        needle = args.grep.lower()
        hits = {g for g, p in procs.items() if needle in (p.image + " " + p.command_line).lower()}
        for g in hits:
            procs[g].marks.append(f"matches '{args.grep}'")
        only = tree.focus(procs, hits)
    print(tree.render(procs, only=only) or "no Sysmon process-creation events (Event ID 1) found")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="evtx-hunter",
        description="Triage Windows event logs (.evtx or Wazuh archives JSON) with Sigma rules.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    h = sub.add_parser("hunt", help="run Sigma rules and write a triage report")
    h.add_argument("files", nargs="+", help=".evtx files or Wazuh archives.json/archives.log")
    h.add_argument("-r", "--rules", action="append",
                   help="Sigma rule file or folder (repeatable; default: ./detections/sigma)")
    h.add_argument("-l", "--min-level", choices=LEVELS, default="low",
                   help="ignore rules below this level (default: low)")
    h.add_argument("-f", "--format", choices=["markdown", "json"], default="markdown")
    h.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    h.add_argument("--no-tree", action="store_true", help="leave the process tree out of the report")
    h.add_argument("--webhook", help="POST the JSON findings to this URL (e.g. an n8n webhook)")
    h.add_argument("--send-empty", action="store_true", help="call the webhook even with no findings")
    h.add_argument("--fail-on-findings", action="store_true",
                   help="exit with status 1 when anything is found (for scripts and CI)")
    h.set_defaults(func=cmd_hunt)

    t = sub.add_parser("tree", help="print Sysmon process trees")
    t.add_argument("files", nargs="+")
    t.add_argument("--host", help="only this host (prefix match on Computer)")
    t.add_argument("--grep", help="only show branches containing this image/command-line text")
    t.set_defaults(func=cmd_tree)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
