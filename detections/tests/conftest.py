import pytest
from sigma.collection import SigmaCollection

from detection_helpers import sigma_files


@pytest.fixture(scope="session")
def sigma_collection():
    """All Sigma rules in one collection so correlations can resolve their base rules."""
    # Loaded as one multi-document stream: a correlation file on its own would fail
    # to resolve the base rule it references.
    return SigmaCollection.from_yaml("\n---\n".join(p.read_text() for p in sigma_files()))
