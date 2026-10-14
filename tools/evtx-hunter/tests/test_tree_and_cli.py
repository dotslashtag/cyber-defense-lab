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


class _Resp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _capture(monkeypatch):
    sent = {}

    def fake_urlopen(req, timeout=None, context=None):
        sent["headers"] = dict(req.header_items())
        sent["body"] = json.loads(req.data)
        sent["context"] = context
        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return sent


def test_webhook_sends_token_from_env(monkeypatch, capsys, tmp_path, sample_path, rules_path):
    sent = _capture(monkeypatch)
    monkeypatch.setenv("EVTX_HUNTER_WEBHOOK_TOKEN", "test-token-value")
    code = main(["hunt", str(sample_path), "--rules", str(rules_path), "-o", str(tmp_path / "r.md"),
                 "--webhook", "https://n8n.example/webhook/evtx-hunter"])
    assert code == 0
    assert sent["headers"]["X-webhook-token"] == "test-token-value"
    assert sent["body"]["tool"] == "evtx-hunter" and sent["body"]["summary"]["findings"] == 6
    err = capsys.readouterr().err
    assert "HTTP 200 (token sent)" in err and "test-token-value" not in err


def test_webhook_without_token_and_http_warning(monkeypatch, capsys, tmp_path, sample_path, rules_path):
    sent = _capture(monkeypatch)
    monkeypatch.delenv("EVTX_HUNTER_WEBHOOK_TOKEN", raising=False)
    main(["hunt", str(sample_path), "--rules", str(rules_path), "-o", str(tmp_path / "r.md"),
          "--webhook", "http://n8n.example/webhook/evtx-hunter"])
    assert "X-webhook-token" not in sent["headers"]
    assert "plain HTTP" not in capsys.readouterr().err  # only warns when a token is sent


def test_webhook_http_error_is_reported_not_raised(monkeypatch, capsys, tmp_path, sample_path, rules_path):
    import urllib.error

    def refuse(req, timeout=None, context=None):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", refuse)
    code = main(["hunt", str(sample_path), "--rules", str(rules_path), "-o", str(tmp_path / "r.md"),
                 "--webhook", "https://n8n.example/ingest/evtx-hunter"])
    assert code == 2
    assert "HTTP 403 Forbidden" in capsys.readouterr().err

