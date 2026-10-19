"""Tests for the n8n export sanitizer. Fake secrets are assembled at runtime so this file
itself never contains a secret-shaped string (keeps the gitleaks scan clean)."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sanitize", ROOT / "sanitize.py")
sanitize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sanitize)

FAKE_SLACK = "xo" + "xb-" + "1234567890-abcdefghijkl"
FAKE_HEX = "ab" * 20
FAKE_CHANNEL = "C0" + "ABCDEF1234"


def raw_workflow():
    return {
        "id": "WfId123", "versionId": "v-1", "active": True, "pinData": {"x": [1]},
        "meta": {"instanceId": "inst"}, "tags": [{"id": "t1", "name": "soar"}],
        "name": "Demo", "settings": {"executionOrder": "v1", "errorWorkflow": "Err123"},
        "connections": {"Webhook": {"main": [[{"node": "Post", "type": "main", "index": 0}]]}},
        "nodes": [
            {"id": "n1", "webhookId": "hook-uuid", "name": "Webhook",
             "type": "n8n-nodes-base.webhook", "parameters": {"path": "wazuh"}},
            {"id": "n2", "name": "Post", "type": "n8n-nodes-base.httpRequest",
             "credentials": {"slackApi": {"id": "cred1", "name": "SOC SOAR Bot"}},
             "parameters": {"url": "http://10.10.1.6:9000/api/v1/alert",
                            "headerParameters": {"parameters": [
                                {"name": "X-Webhook-Token", "value": "plain-value"},
                                {"name": "Content-Type", "value": "application/json"}]}}},
            {"id": "n3", "name": "Code", "type": "n8n-nodes-base.code",
             "parameters": {"jsCode": f"const ch = '{FAKE_CHANNEL}';\nconst t = '{FAKE_SLACK}';\n"
                                      f"const h = '{FAKE_HEX}';\nconst k = $env.SIGNING_KEY;"}},
            {"id": "n4", "name": "Enrich", "type": "n8n-nodes-base.executeWorkflow",
             "parameters": {"workflowId": {"__rl": True, "value": "Abc123",
                                           "cachedResultName": "SOAR Enrich IP"}}},
        ],
    }


def test_drops_instance_metadata_and_ids():
    clean, _ = sanitize.sanitize(raw_workflow())
    assert set(clean) == {"name", "nodes", "connections", "settings"}
    assert clean["settings"] == {"executionOrder": "v1"}
    for node in clean["nodes"]:
        assert "id" not in node and "webhookId" not in node


def test_credentials_keep_type_only():
    clean, _ = sanitize.sanitize(raw_workflow())
    assert clean["nodes"][1]["credentials"] == {"slackApi": {"name": "<slackApi credential>"}}


def test_sensitive_headers_redacted_others_kept():
    clean, _ = sanitize.sanitize(raw_workflow())
    headers = {h["name"]: h["value"] for h in clean["nodes"][1]["parameters"]["headerParameters"]["parameters"]}
    assert headers == {"X-Webhook-Token": "<REDACTED>", "Content-Type": "application/json"}


def test_code_secrets_and_channel_ids_redacted_env_refs_kept():
    clean, findings = sanitize.sanitize(raw_workflow())
    code = clean["nodes"][2]["parameters"]["jsCode"]
    assert FAKE_SLACK not in code and FAKE_HEX not in code and FAKE_CHANNEL not in code
    assert "C0SLACKCHANNEL" in code and "$env.SIGNING_KEY" in code
    assert {f.split(": ")[1] for f in findings} == {"slack token", "long hex"}


def test_subworkflow_reference_keeps_name_only():
    clean, _ = sanitize.sanitize(raw_workflow())
    ref = clean["nodes"][3]["parameters"]["workflowId"]
    assert ref["value"] == "<workflow: SOAR Enrich IP>" and "Abc123" not in json.dumps(clean)


def test_lab_ip_and_connections_kept():
    clean, _ = sanitize.sanitize(raw_workflow())
    assert clean["nodes"][1]["parameters"]["url"] == "http://10.10.1.6:9000/api/v1/alert"
    assert clean["connections"] == raw_workflow()["connections"]


def test_check_flags_raw_and_passes_clean():
    assert sanitize.check(raw_workflow())
    clean, _ = sanitize.sanitize(raw_workflow())
    assert sanitize.check(clean) == []


def test_published_workflows_are_clean():
    files = sorted((ROOT / "workflows").glob("*.json"))
    for path in files:
        assert sanitize.check(json.loads(path.read_text(encoding="utf-8"))) == [], path.name
