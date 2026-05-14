"""Fixtures partagées : sample finding markdown + arbre engagement temporaire."""
from __future__ import annotations
from pathlib import Path

import pytest
import yaml


SAMPLE_FINDING_TEXT = """---
title: SQLi authentifiée sur /api/v1/users/search
severity: high
date: 2026-05-15
cvss: 8.1
owasp: "A03:2021"
cwe: 89
endpoint: https://app.acme/api/v1/users/search
method: GET
parameter: q
discovered_by: nuclei + manual
status: open
---

## Impact
Énumération possible de tous les utilisateurs via injection booléenne.

## Reproduction
```http
GET /api/v1/users/search?q=admin' OR '1'='1
```

## Remédiation
Requêtes paramétrées.
"""


SAMPLE_SCOPE_YAML = """client: acme-corp
engagement: pentest-web-2026
authorized_by: jane.doe@acme.com
ip: 203.0.113.42
window:
  start: 2026-01-01T00:00:00+00:00
  end:   2099-12-31T23:59:59+00:00
in_scope:
  domains:
    - "*.acme-corp.com"
    - "api.acme.io"
  cidrs:
    - "203.0.113.0/24"
out_of_scope:
  domains:
    - "blog.acme-corp.com"
constraints:
  max_rps: 10
intrusive_actions: []
"""


@pytest.fixture
def sample_finding_text() -> str:
    return SAMPLE_FINDING_TEXT


@pytest.fixture
def sample_finding_path(tmp_path) -> Path:
    p = tmp_path / "01-sqli.md"
    p.write_text(SAMPLE_FINDING_TEXT)
    return p


@pytest.fixture
def tmp_engagement(tmp_path) -> Path:
    """Crée engagements/acme-corp/ avec scope.yaml + 2 findings + recon."""
    root = tmp_path
    eng = root / "engagements" / "acme-corp"
    eng.mkdir(parents=True)
    (eng / "scope.yaml").write_text(SAMPLE_SCOPE_YAML)
    findings = eng / "findings"
    findings.mkdir()
    (findings / "01-sqli.md").write_text(SAMPLE_FINDING_TEXT)
    (findings / "02-xss.md").write_text("""---
title: XSS reflété
severity: medium
date: 2026-05-15
status: open
---
Body.
""")
    recon = eng / "recon"
    recon.mkdir()
    (recon / "subdomains.txt").write_text("app.acme-corp.com\napi.acme.io\n")
    return root
