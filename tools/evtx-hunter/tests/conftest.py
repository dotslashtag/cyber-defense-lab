from pathlib import Path

import pytest

from evtx_hunter.hunt import load_rules
from evtx_hunter.readers import read_wazuh

TOOL = Path(__file__).resolve().parents[1]
REPO = TOOL.parents[1]
SAMPLE = TOOL / "samples" / "op002-style-archives.json"
RULES = REPO / "detections" / "sigma"


@pytest.fixture(scope="session")
def events():
    return list(read_wazuh(SAMPLE))


@pytest.fixture(scope="session")
def rules():
    return load_rules([RULES])


@pytest.fixture(scope="session")
def sample_path():
    return SAMPLE


@pytest.fixture(scope="session")
def rules_path():
    return RULES
