"""Wazuh local rules: structure checks plus field-pattern tests on sample alerts.

The parent rule (if_sid) and the decoder are not run here; that needs a Wazuh
manager (wazuh-logtest). These tests check that each rule's own field patterns
fire on the attack sample and stay quiet on the benign one.
"""

import re
import xml.etree.ElementTree as ET

import pytest

from detection_helpers import WAZUH_RULES, load_cases

CASES = load_cases("wazuh")
LOCAL_RANGE = range(510100, 510200)

# Rules with no ATT&CK ID on purpose.
NO_MITRE = {"510144": "an IOC match alone does not prove a technique"}
# Rules whose logic cannot be checked offline.
OFFLINE_UNTESTABLE = {"510144": "matches against a Wazuh CDB list on the manager"}

RULES = ET.parse(WAZUH_RULES).getroot().findall(".//rule")


def test_rules_present():
    assert RULES, "no rules found"


def test_rule_ids_unique_and_in_local_range():
    ids = [int(r.get("id")) for r in RULES]
    assert len(ids) == len(set(ids)), "duplicate rule IDs"
    assert all(i in LOCAL_RANGE for i in ids), "rule ID outside the lab's local range"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.get("id"))
def test_rule_structure(rule):
    rid = rule.get("id")
    assert rule.findtext("description", "").strip(), f"{rid}: no description"
    assert rule.findtext("if_sid"), f"{rid}: should narrow a parent rule with if_sid"
    if rid not in NO_MITRE:
        assert rule.findall("mitre/id"), f"{rid}: no ATT&CK ID"
    if rid not in OFFLINE_UNTESTABLE:
        case = CASES.get(rid)
        assert case and case.get("positive") and case.get("negative"), (
            f"{rid}: needs tests/cases/wazuh/{rid}.yml with positive and negative cases"
        )


def _get(event, dotted):
    for part in dotted.split("."):
        if not isinstance(event, dict):
            return None
        event = event.get(part)
    return event


def _fires(rule, event):
    for field in rule.findall("field"):
        value = _get(event, field.get("name"))
        if value is None or not re.search(field.text, str(value)):
            return False
    return True


def _cases(kind):
    for rule in RULES:
        for i, case in enumerate((CASES.get(rule.get("id")) or {}).get(kind) or []):
            yield pytest.param(rule, case, id=f"{rule.get('id')}-{i}")


@pytest.mark.parametrize("rule,case", list(_cases("positive")))
def test_fires_on_attack(rule, case):
    assert _fires(rule, case["event"]), f"should fire: {case['description']}"


@pytest.mark.parametrize("rule,case", list(_cases("negative")))
def test_quiet_on_benign(rule, case):
    assert not _fires(rule, case["event"]), f"should stay quiet: {case['description']}"
