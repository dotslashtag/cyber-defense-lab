from pathlib import Path

import pytest
import yaml
from sigma.collection import SigmaCollection

DETECTIONS = Path(__file__).resolve().parents[1]
SIGMA_DIR = DETECTIONS / "sigma"
WAZUH_RULES = DETECTIONS / "wazuh" / "local_rules.xml"
CASES = Path(__file__).resolve().parent / "cases"


def sigma_files():
    return sorted(SIGMA_DIR.rglob("*.yml"))


def load_cases(kind: str):
    return {p.stem: yaml.safe_load(p.read_text()) for p in sorted((CASES / kind).glob("*.yml"))}


@pytest.fixture(scope="session")
def sigma_collection():
    """All Sigma rules in one collection so correlations can resolve their base rules."""
    # Loaded as one multi-document stream: a correlation file on its own would fail
    # to resolve the base rule it references.
    return SigmaCollection.from_yaml("\n---\n".join(p.read_text() for p in sigma_files()))
