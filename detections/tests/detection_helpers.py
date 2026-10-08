"""Paths and loaders shared by the detection tests."""

from pathlib import Path

import yaml

DETECTIONS = Path(__file__).resolve().parents[1]
SIGMA_DIR = DETECTIONS / "sigma"
WAZUH_RULES = DETECTIONS / "wazuh" / "local_rules.xml"
CASES = Path(__file__).resolve().parent / "cases"


def sigma_files():
    return sorted(SIGMA_DIR.rglob("*.yml"))


def load_cases(kind: str):
    return {p.stem: yaml.safe_load(p.read_text()) for p in sorted((CASES / kind).glob("*.yml"))}
