"""Tests pour index_builder.py."""
from __future__ import annotations
import sys
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from index_builder import (
    _parse_report_frontmatter,
    _build_engagement_index,
    _build_global_index,
    regenerate_indexes,
    INDEX_FILENAME,
)


VALID_REPORT = """---
target: acme-corp
date: 2026-05-15
perimeter: external
risk_global: high
counts:
  critical: 0
  high: 3
  medium: 5
  low: 2
  info: 1
ip: 203.0.113.42
auditor: amaury
tool: claude-opus-4-7
playbook_version: v0.2.0
---

# Rapport
[contenu]
"""


def test_parse_report_frontmatter_valid(tmp_path):
    p = tmp_path / "2026-05-15.md"
    p.write_text(VALID_REPORT)
    fm = _parse_report_frontmatter(p)
    assert fm is not None
    assert fm["target"] == "acme-corp"
    assert fm["date"] == "2026-05-15"
    assert fm["risk_global"] == "high"
    assert fm["counts"]["high"] == 3


def test_parse_report_frontmatter_no_bloc(tmp_path, capsys):
    p = tmp_path / "broken.md"
    p.write_text("# Pas de frontmatter\nJuste du markdown.\n")
    assert _parse_report_frontmatter(p) is None
    err = capsys.readouterr().err
    assert "frontmatter manquant" in err


def test_parse_report_frontmatter_yaml_invalid(tmp_path, capsys):
    p = tmp_path / "broken.md"
    p.write_text("---\ntarget: [unclosed bracket\n---\nbody\n")
    assert _parse_report_frontmatter(p) is None
    err = capsys.readouterr().err
    assert "YAML invalide" in err


def test_parse_report_frontmatter_required_field_missing(tmp_path, capsys):
    p = tmp_path / "broken.md"
    p.write_text("---\ntarget: a\ndate: 2026-05-15\n---\nbody\n")
    assert _parse_report_frontmatter(p) is None
    err = capsys.readouterr().err
    assert "champ requis manquant" in err


def test_build_engagement_index_two_reports(tmp_engagement):
    eng = tmp_engagement / "engagements" / "acme-corp"
    rapports = eng / "rapports"
    rapports.mkdir()
    (rapports / "2026-04-20.md").write_text(VALID_REPORT.replace("2026-05-15", "2026-04-20"))
    (rapports / "2026-05-15.md").write_text(VALID_REPORT)
    out = _build_engagement_index(eng)
    assert "acme-corp" in out
    assert "2026-04-20" in out
    assert "2026-05-15" in out
    # Ordre asc : 2026-04-20 doit apparaître avant 2026-05-15
    assert out.index("2026-04-20") < out.index("2026-05-15")


def test_build_engagement_index_skips_broken(tmp_engagement, capsys):
    eng = tmp_engagement / "engagements" / "acme-corp"
    rapports = eng / "rapports"
    rapports.mkdir()
    (rapports / "2026-05-15.md").write_text(VALID_REPORT)
    (rapports / "broken.md").write_text("# Pas de frontmatter\n")
    out = _build_engagement_index(eng)
    assert "2026-05-15" in out
    err = capsys.readouterr().err
    assert "frontmatter manquant" in err


def test_build_engagement_index_no_reports(tmp_engagement):
    eng = tmp_engagement / "engagements" / "acme-corp"
    out = _build_engagement_index(eng)
    assert "Aucun rapport généré" in out


def test_build_engagement_index_includes_ip_from_scope(tmp_engagement):
    eng = tmp_engagement / "engagements" / "acme-corp"
    rapports = eng / "rapports"
    rapports.mkdir()
    (rapports / "2026-05-15.md").write_text(VALID_REPORT)
    out = _build_engagement_index(eng)
    assert "203.0.113.42" in out


def test_build_global_index_multiple_engagements(tmp_path):
    root = tmp_path
    engs = root / "engagements"
    engs.mkdir()

    for name in ("acme-corp", "customer-2", "empty-eng"):
        (engs / name).mkdir()
        (engs / name / "scope.yaml").write_text(f"client: {name}\n")

    # 2 engagements avec rapports
    (engs / "acme-corp" / "rapports").mkdir()
    (engs / "acme-corp" / "rapports" / "2026-05-15.md").write_text(VALID_REPORT)
    (engs / "customer-2" / "rapports").mkdir()
    (engs / "customer-2" / "rapports" / "2026-04-22.md").write_text(
        VALID_REPORT.replace("acme-corp", "customer-2").replace("2026-05-15", "2026-04-22")
    )
    # empty-eng : pas de rapports → exclu

    out = _build_global_index(engs)
    assert "acme-corp" in out
    assert "customer-2" in out
    assert "empty-eng" not in out


def test_build_global_index_ignores_template_prefix(tmp_path):
    root = tmp_path
    engs = root / "engagements"
    engs.mkdir()
    (engs / "_template").mkdir()
    (engs / "_template" / "rapports").mkdir()
    (engs / "_template" / "rapports" / "2026-05-15.md").write_text(VALID_REPORT)
    out = _build_global_index(engs)
    assert "_template" not in out


def test_build_global_index_picks_latest_report(tmp_path):
    root = tmp_path
    engs = root / "engagements"
    engs.mkdir()
    eng = engs / "acme-corp"
    eng.mkdir()
    (eng / "scope.yaml").write_text("client: acme-corp\n")
    rapports = eng / "rapports"
    rapports.mkdir()
    # Deux rapports ; le plus récent est 2026-05-15
    (rapports / "2026-04-01.md").write_text(VALID_REPORT.replace("2026-05-15", "2026-04-01"))
    (rapports / "2026-05-15.md").write_text(VALID_REPORT)
    out = _build_global_index(engs)
    assert "2026-05-15" in out
    assert "2026-04-01" not in out


def test_build_global_index_no_engagements(tmp_path):
    engs = tmp_path / "engagements"
    engs.mkdir()
    out = _build_global_index(engs)
    assert "Aucun engagement avec rapports" in out


def test_regenerate_indexes_end_to_end(tmp_path):
    root = tmp_path
    engs = root / "engagements"
    engs.mkdir()
    eng = engs / "acme-corp"
    eng.mkdir()
    (eng / "scope.yaml").write_text("client: acme-corp\nip: 1.2.3.4\n")
    rapports = eng / "rapports"
    rapports.mkdir()
    (rapports / "2026-05-15.md").write_text(VALID_REPORT)

    result = regenerate_indexes(root)
    assert result == {"engagements": 1, "global": 1}

    eng_idx = rapports / INDEX_FILENAME
    assert eng_idx.exists()
    assert "acme-corp" in eng_idx.read_text()
    assert "1.2.3.4" in eng_idx.read_text()

    global_idx = engs / INDEX_FILENAME
    assert global_idx.exists()
    assert "acme-corp" in global_idx.read_text()


def test_regenerate_indexes_no_engagements_dir(tmp_path):
    result = regenerate_indexes(tmp_path)
    assert result == {"engagements": 0, "global": 0}
    assert not (tmp_path / "engagements").exists()
