"""Wazuh local rules: structure checks plus field-pattern tests on sample alerts.

The parent rule (if_sid), the decoder and frequency/correlation logic are not run
here; that needs a Wazuh manager (wazuh-logtest). For single-event rules, these
tests check that the rule's own field patterns fire on the attack sample and stay
quiet on the benign one.
"""

import re
import xml.etree.ElementTree as ET

import pytest

from detection_helpers import WAZUH_RULES, load_cases

CASES = load_cases("wazuh")
LOCAL_RANGE = range(510100, 510200)
# Rules outside the detection range on purpose.
EXTRA_IDS = {"910001": "n8n pipeline test marker, not a detection"}

# Rules with no ATT&CK ID on purpose.
NO_MITRE = {
    "510144": "an IOC match alone does not prove a technique",
    "910001": "pipeline test marker",
}
# Rules whose logic cannot be checked offline.
_CORRELATION = "frequency/correlation rule: needs a sequence of events on a Wazuh manager"
OFFLINE_UNTESTABLE = {
    "510144": "matches against a Wazuh CDB list on the manager",
    "910001": "pipeline test marker",
    **{rid: _CORRELATION for rid in
       ("510120", "510121", "510130", "510131", "510132", "510133")},
}

# A Wazuh rules file may hold several top-level <group> elements, so wrap it
# before parsing.
_TEXT = WAZUH_RULES.read_text(encoding="utf-8")
_TEXT = re.sub(r"^\s*<!--.*?-->", "", _TEXT, count=1, flags=re.S)
RULES = ET.fromstring(f"<rules>{_TEXT}</rules>").findall(".//rule")


def test_rules_present():
    assert RULES, "no rules found"


def test_rule_ids_unique_and_in_local_range():
    ids = [r.get("id") for r in RULES]
    assert len(ids) == len(set(ids)), "duplicate rule IDs"
    outside = [i for i in ids if int(i) not in LOCAL_RANGE and i not in EXTRA_IDS]
    assert not outside, f"rule IDs outside the lab's local range: {outside}"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.get("id"))
def test_rule_structure(rule):
    rid = rule.get("id")
    assert rule.findtext("description", "").strip(), f"{rid}: no description"
    if rid not in EXTRA_IDS:
        assert rule.findtext("if_sid") or rule.findtext("if_matched_sid"), (
            f"{rid}: should build on a parent rule (if_sid or if_matched_sid)"
        )
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
        hit = value is not None and re.search(field.text, str(value)) is not None
        if field.get("negate") == "yes":
            hit = value is not None and not hit
        if not hit:
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
