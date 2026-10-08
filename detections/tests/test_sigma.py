"""Sigma rules: metadata, Splunk conversion, and must-fire / must-stay-quiet tests."""

import re

import pytest
import yaml
from sigma.backends.splunk import SplunkBackend
from sigma.correlations import SigmaCorrelationRule

from detection_helpers import load_cases, sigma_files
from evtx_hunter.sigma_eval import correlation_matches, rule_matches

CASES = load_cases("sigma")
FILES = sigma_files()


def _rule_id(path):
    return str(yaml.safe_load(path.read_text())["id"])


@pytest.fixture(scope="session")
def rules_by_id(sigma_collection):
    return {str(r.id): r for r in sigma_collection}


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_rule_metadata(path):
    raw = yaml.safe_load(path.read_text())
    for key in ("title", "id", "status", "description", "author", "date", "level", "tags"):
        assert raw.get(key), f"{path.name}: missing {key}"
    assert any(t.startswith("attack.") for t in raw["tags"]), f"{path.name}: no ATT&CK tag"
    if "correlation" not in raw:
        assert any(re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t) for t in raw["tags"]), (
            f"{path.name}: detection rules need at least one ATT&CK technique tag"
        )


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_rule_has_cases(path):
    case = CASES.get(path.stem)
    assert case, f"no test cases file: tests/cases/sigma/{path.stem}.yml"
    assert case.get("positive"), f"{path.stem}: needs at least one must-fire case"
    assert case.get("negative"), f"{path.stem}: needs at least one must-stay-quiet case"


def test_collection_converts_to_splunk(sigma_collection):
    queries = SplunkBackend().convert(sigma_collection)
    # Base rules used by a correlation are folded into the correlation's query.
    docs = [yaml.safe_load(p.read_text()) for p in FILES]
    folded = {r for d in docs for r in (d.get("correlation") or {}).get("rules", [])}
    assert len(queries) == len(FILES) - len(folded)
    assert all(q.strip() for q in queries)


def _cases(kind):
    for path in FILES:
        for i, case in enumerate((CASES.get(path.stem) or {}).get(kind) or []):
            yield pytest.param(path, case, id=f"{path.stem}-{i}")


def _fires(rule, case):
    if isinstance(rule, SigmaCorrelationRule):
        return correlation_matches(rule, case["events"])
    return rule_matches(rule, case["event"])


@pytest.mark.parametrize("path,case", list(_cases("positive")))
def test_fires_on_attack(path, case, rules_by_id):
    rule = rules_by_id[_rule_id(path)]
    assert _fires(rule, case), f"should fire: {case['description']}"


@pytest.mark.parametrize("path,case", list(_cases("negative")))
def test_quiet_on_benign(path, case, rules_by_id):
    rule = rules_by_id[_rule_id(path)]
    assert not _fires(rule, case), f"should stay quiet: {case['description']}"
