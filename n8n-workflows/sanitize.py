"""Sanitize n8n workflow exports for publishing.

Removes instance-specific IDs, credential references, webhook IDs, Slack channel and user IDs and
anything that looks like a secret, then re-scans the result and fails if a secret pattern
survives. Lab IP addresses (10.10.x.x) are kept on purpose: they are fictional lab values.

    python n8n-workflows/sanitize.py raw-export.json -o n8n-workflows/workflows/name.json
    python n8n-workflows/sanitize.py --check n8n-workflows/workflows/*.json
"""
import argparse
import json
import re
import sys
from pathlib import Path

REDACTED = "<REDACTED>"
SLACK_CHANNEL = "C0SLACKCHANNEL"
SLACK_USER = "U0SLACKUSER"

# Top-level workflow keys that are instance metadata, run data or internal IDs.
DROP_WORKFLOW_KEYS = {
    "id", "versionId", "meta", "pinData", "staticData", "shared", "tags", "active",
    "isArchived", "triggerCount", "createdAt", "updatedAt", "_backup_meta", "activeVersion",
    "versionCounter", "nodeGroups", "parentFolder", "homeProject",
}
DROP_NODE_KEYS = {"id", "webhookId"}
KEEP_SETTINGS = {"executionOrder", "saveManualExecutions", "callerPolicy", "timezone"}

SECRET_PATTERNS = [
    ("slack token", re.compile(r"xox[abposr]-[A-Za-z0-9-]{10,}")),
    ("slack webhook", re.compile(r"https://hooks\.slack\.com/services/\S+")),
    ("bearer token", re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}")),
    ("aws key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("long hex", re.compile(r"\b[A-Fa-f0-9]{32,}\b")),
    ("assigned secret", re.compile(
        r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"][^'\"$`{}\s]{6,}['\"]")),
]
SLACK_CHANNEL_RE = re.compile(r"\b[CG]0[A-Z0-9]{7,11}\b")
# Slack user (U/W) and workspace (T) IDs, e.g. an approver allow-list in a Code node.
SLACK_USER_RE = re.compile(r"\b[UWT]0[A-Z0-9]{7,11}\b")
SENSITIVE_HEADER = re.compile(r"(?i)(auth|token|key|secret|signature|cookie|password)")


def _scrub_string(text, findings, where):
    for label, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            findings.append(f"{where}: {label}")
            text = pattern.sub(REDACTED, text)
    text = SLACK_CHANNEL_RE.sub(SLACK_CHANNEL, text)
    return SLACK_USER_RE.sub(SLACK_USER, text)


def _walk(value, findings, where):
    if isinstance(value, dict):
        return {k: _walk(v, findings, f"{where}.{k}") for k, v in value.items()}
    if isinstance(value, list):
        return [_walk(v, findings, f"{where}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, str):
        return _scrub_string(value, findings, where)
    return value


def _scrub_headers(params):
    for group in ("headerParameters", "queryParameters"):
        for item in (params.get(group) or {}).get("parameters", []) or []:
            if SENSITIVE_HEADER.search(str(item.get("name", ""))) and item.get("value"):
                item["value"] = REDACTED


def _scrub_workflow_ref(params):
    ref = params.get("workflowId")
    if isinstance(ref, dict):
        name = ref.get("cachedResultName") or "sub-workflow"
        params["workflowId"] = {"__rl": True, "mode": "list", "value": f"<workflow: {name}>",
                                "cachedResultName": name}
    elif isinstance(ref, str) and ref:
        params["workflowId"] = "<workflow>"


def sanitize(workflow):
    """Return (clean_workflow, findings). findings lists what was redacted as a secret."""
    if isinstance(workflow, list):
        if len(workflow) != 1:
            raise ValueError("expected one workflow per file")
        workflow = workflow[0]
    findings = []
    clean = {k: v for k, v in workflow.items() if k not in DROP_WORKFLOW_KEYS}
    clean["settings"] = {k: v for k, v in (workflow.get("settings") or {}).items() if k in KEEP_SETTINGS}
    nodes = []
    for node in workflow.get("nodes", []):
        node = {k: v for k, v in node.items() if k not in DROP_NODE_KEYS}
        if node.get("credentials"):
            node["credentials"] = {ctype: {"name": f"<{ctype} credential>"} for ctype in node["credentials"]}
        params = node.get("parameters") or {}
        _scrub_headers(params)
        _scrub_workflow_ref(params)
        nodes.append(node)
    clean["nodes"] = nodes
    clean = _walk(clean, findings, "workflow")
    return clean, findings


def check(workflow):
    """Return problems still present in an already-sanitized workflow."""
    problems = []
    for key in DROP_WORKFLOW_KEYS & set(workflow):
        problems.append(f"top-level key {key!r} present")
    for node in workflow.get("nodes", []):
        for key in DROP_NODE_KEYS & set(node):
            problems.append(f"node {node.get('name')!r}: {key!r} present")
        for ctype, cred in (node.get("credentials") or {}).items():
            if set(cred) != {"name"} or not cred["name"].startswith("<"):
                problems.append(f"node {node.get('name')!r}: credential {ctype!r} not redacted")
    text = json.dumps(workflow)
    for label, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            problems.append(f"secret pattern: {label}")
    placeholders_removed = text.replace(SLACK_CHANNEL, "").replace(SLACK_USER, "")
    if SLACK_CHANNEL_RE.search(placeholders_removed):
        problems.append("Slack channel id present")
    if SLACK_USER_RE.search(placeholders_removed):
        problems.append("Slack user or workspace id present")
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("-o", "--output", type=Path, help="output file (one input only)")
    ap.add_argument("--check", action="store_true", help="only verify already-sanitized files")
    args = ap.parse_args(argv)
    status = 0
    for path in args.files:
        data = json.loads(path.read_text(encoding="utf-8"))
        if args.check:
            problems = check(data)
            for p in problems:
                print(f"{path}: {p}")
            status |= bool(problems)
            continue
        clean, findings = sanitize(data)
        for f in findings:
            print(f"{path}: redacted {f}", file=sys.stderr)
        problems = check(clean)
        if problems:
            for p in problems:
                print(f"{path}: STILL PRESENT {p}", file=sys.stderr)
            return 1
        out = json.dumps(clean, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(out, encoding="utf-8")
        else:
            sys.stdout.write(out)
    return status


if __name__ == "__main__":
    sys.exit(main())
