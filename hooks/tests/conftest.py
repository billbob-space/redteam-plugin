import sys
from pathlib import Path

HOOKS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HOOKS_DIR))

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

@pytest.fixture
def sample_scope_path():
    return FIXTURES / "sample_scope.yaml"

@pytest.fixture
def sample_scope_dict(sample_scope_path):
    import yaml
    with open(sample_scope_path) as f:
        return yaml.safe_load(f)
