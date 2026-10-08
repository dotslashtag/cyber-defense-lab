import json

from evtx_hunter import tree
from evtx_hunter.cli import main


def test_tree_links_children_by_guid(events):
    procs = tree.build(events)
    cmd = next(p for p in procs.values() if p.image.endswith("cmd.exe"))
    kids = [tree._base(c.image).lower() for c in cmd.children]
    assert kids[:2] == ["whoami.exe", "systeminfo.exe"]
    assert "reg.exe" in kids and "powershell.exe" in kids


def test_focus_keeps_ancestors_and_descendants(events):
    procs = tree.build(events)
    ps = next(g for g, p in procs.items() if p.image.endswith("powershell.exe"))
    kept = {tree._base(procs[g].image).lower() for g in tree.focus(procs, {ps})}
    assert kept == {"explorer.exe", "cmd.exe", "powershell.exe", "rundll32.exe"}


def test_cli_markdown_report(tmp_path, sample_path, rules_path):
    out = tmp_path / "report.md"
    assert main(["hunt", str(sample_path), "--rules", str(rules_path), "-o", str(out)]) == 0
    text = out.read_text()
    assert "## Timeline of findings" in text
    assert "## Process tree around the findings" in text
    assert "◀ Rundll32 Spawned By PowerShell" in text


def test_cli_json_and_fail_flag(tmp_path, sample_path, rules_path):
    out = tmp_path / "report.json"
    code = main(["hunt", str(sample_path), "--rules", str(rules_path), "-f", "json",
                 "-o", str(out), "--fail-on-findings"])
    assert code == 1
    data = json.loads(out.read_text())
    assert data["summary"]["findings"] == 6
    assert data["summary"]["thehive_severity"] == 3
    assert {"title", "level", "attack", "host", "evidence"} <= set(data["findings"][0])


def test_cli_tree_grep(capsys, sample_path):
    assert main(["tree", str(sample_path), "--grep", "rundll32"]) == 0
    out = capsys.readouterr().out
    assert "rundll32.exe" in out and "whoami.exe" not in out
