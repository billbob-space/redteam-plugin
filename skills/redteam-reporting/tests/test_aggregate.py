"""Tests pour aggregate_findings.py."""
from __future__ import annotations
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from aggregate_findings import (
    parse_finding,
    compute_counts,
    compute_risk_global,
    build_findings_block,
    build_actions_block,
    FindingValidationError,
    main,
)


# --- parse_finding ---

def test_parse_finding_valid(sample_finding_path):
    f = parse_finding(sample_finding_path, strict=True)
    assert f["title"] == "SQLi authentifiée sur /api/v1/users/search"
    assert f["severity"] == "high"
    assert f["date"] == "2026-05-15"
    assert f["status"] == "open"
    assert "Impact" in f["body"]


def test_parse_finding_no_frontmatter_block(tmp_path):
    p = tmp_path / "f.md"
    p.write_text("# Pas de bloc YAML\nJuste du markdown.\n")
    with pytest.raises(FindingValidationError, match="frontmatter manquant"):
        parse_finding(p, strict=True)


def test_parse_finding_yaml_invalid(tmp_path):
    p = tmp_path / "f.md"
    p.write_text("---\ntitle: [unclosed bracket\n---\nbody\n")
    with pytest.raises(FindingValidationError, match="YAML invalide"):
        parse_finding(p, strict=True)


def test_parse_finding_required_field_missing(tmp_path):
    p = tmp_path / "f.md"
    p.write_text("---\ntitle: only title\n---\nbody\n")
    with pytest.raises(FindingValidationError, match="champ.*requis.*manquant"):
        parse_finding(p, strict=True)


def test_parse_finding_severity_invalid(tmp_path):
    p = tmp_path / "f.md"
    p.write_text("---\ntitle: x\nseverity: très-haute\ndate: 2026-05-15\n---\nbody\n")
    with pytest.raises(FindingValidationError, match="severity.*invalide"):
        parse_finding(p, strict=True)


def test_parse_finding_date_not_iso(tmp_path):
    p = tmp_path / "f.md"
    p.write_text("---\ntitle: x\nseverity: high\ndate: hier\n---\nbody\n")
    with pytest.raises(FindingValidationError, match="date.*non parseable"):
        parse_finding(p, strict=True)


def test_parse_finding_status_invalid(tmp_path):
    p = tmp_path / "f.md"
    p.write_text("---\ntitle: x\nseverity: high\ndate: 2026-05-15\nstatus: ouvert\n---\nbody\n")
    with pytest.raises(FindingValidationError, match="status.*invalide"):
        parse_finding(p, strict=True)


def test_parse_finding_non_strict_returns_error_dict(tmp_path):
    p = tmp_path / "f.md"
    p.write_text("# Pas de frontmatter\n")
    result = parse_finding(p, strict=False)
    assert "_error" in result
    assert "frontmatter manquant" in result["_error"]
    assert result["path"] == str(p)


def test_parse_finding_status_defaults_to_open(tmp_path):
    p = tmp_path / "f.md"
    p.write_text("---\ntitle: x\nseverity: low\ndate: 2026-05-15\n---\nbody\n")
    f = parse_finding(p, strict=True)
    assert f["status"] == "open"


# --- compute_counts / compute_risk_global ---

def test_compute_counts_ignores_fixed_status():
    findings = [
        {"severity": "high", "status": "open"},
        {"severity": "high", "status": "fixed"},
        {"severity": "low",  "status": "open"},
        {"severity": "medium", "status": "accepted_risk"},
    ]
    assert compute_counts(findings) == {
        "critical": 0, "high": 1, "medium": 0, "low": 1, "info": 0,
    }


def test_compute_risk_global_critical():
    counts = {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
    assert compute_risk_global(counts) == "critical"


def test_compute_risk_global_high_when_no_critical():
    counts = {"critical": 0, "high": 3, "medium": 5, "low": 0, "info": 0}
    assert compute_risk_global(counts) == "high"


def test_compute_risk_global_none_when_all_zero():
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    assert compute_risk_global(counts) == "none"


# --- build_findings_block / build_actions_block ---

def test_build_findings_block_sorted_critical_to_info():
    findings = [
        {"severity": "low",     "title": "B", "status": "open", "body": "b"},
        {"severity": "critical","title": "A", "status": "open", "body": "a"},
        {"severity": "medium",  "title": "M", "status": "open", "body": "m"},
    ]
    out = build_findings_block(findings)
    assert out.index("[CRITICAL]") < out.index("[MEDIUM]") < out.index("[LOW]")


def test_build_findings_block_excludes_fixed():
    findings = [
        {"severity": "high", "title": "Open", "status": "open", "body": "o"},
        {"severity": "high", "title": "Fixed", "status": "fixed", "body": "f"},
    ]
    out = build_findings_block(findings)
    assert "Open" in out
    assert "Fixed" not in out


def test_build_actions_block_numbered_1_to_n():
    findings = [
        {"severity": "high", "title": "A", "status": "open"},
        {"severity": "low",  "title": "B", "status": "open"},
        {"severity": "high", "title": "C", "status": "open"},
    ]
    out = build_actions_block(findings)
    # 3 entrées numérotées
    assert "1. " in out
    assert "2. " in out
    assert "3. " in out
    # Ordre : les HIGH d'abord (A, C alpha) puis LOW (B)
    assert out.index("1. ") < out.index("2. ") < out.index("3. ")
    assert out.index("**[HIGH]** A") < out.index("**[HIGH]** C") < out.index("**[LOW]** B")


# --- main() end-to-end ---

def _write_template(root: Path) -> Path:
    """Copie le template bundled du plugin dans la racine tmp.

    Le template canonique vit dans `skills/redteam-reporting/templates/`. Pour les
    tests, on le copie sous `.tools/share/report-templates/` du root tmp afin que
    le résolveur `--template <relpath>` de aggregate_findings.py le trouve.
    """
    bundled = (
        Path(__file__).resolve().parent.parent / "templates" / "default.md.tmpl"
    )
    tpl_dir = root / ".tools" / "share" / "report-templates"
    tpl_dir.mkdir(parents=True)
    tpl = tpl_dir / "default.md.tmpl"
    tpl.write_text(bundled.read_text())
    return tpl


def test_main_end_to_end(tmp_engagement, monkeypatch):
    root = tmp_engagement
    _write_template(root)
    monkeypatch.chdir(root)
    monkeypatch.setattr(sys, "argv", ["aggregate", "--client", "acme-corp", "--root", str(root), "--date", "2026-05-15"])
    rc = main()
    assert rc == 0
    out_path = root / "engagements" / "acme-corp" / "rapports" / "2026-05-15.md"
    assert out_path.exists()
    text = out_path.read_text()
    # Sections H2 fixes présentes
    assert "## Résumé exécutif" in text
    assert "## Chaînes d'attaque confirmées" in text
    assert "## Ce qui a résisté" in text
    assert "## Risque résiduel" in text
    # Findings injectés
    assert "[HIGH]" in text
    assert "[MEDIUM]" in text
    # Frontmatter
    assert "target: acme-corp" in text
    assert "risk_global: high" in text
    # INDEX régénérés
    assert (root / "engagements" / "acme-corp" / "rapports" / "INDEX.md").exists()
    assert (root / "engagements" / "INDEX.md").exists()


def test_main_finding_invalid_exits_1(tmp_engagement, monkeypatch, capsys):
    root = tmp_engagement
    _write_template(root)
    # Corrompre un finding
    (root / "engagements" / "acme-corp" / "findings" / "03-broken.md").write_text("# pas de frontmatter\n")
    monkeypatch.setattr(sys, "argv", ["aggregate", "--client", "acme-corp", "--root", str(root)])
    rc = main()
    assert rc == 1
    err = capsys.readouterr().err
    assert "frontmatter manquant" in err


def test_main_missing_scope_exits_1(tmp_path, monkeypatch, capsys):
    root = tmp_path
    monkeypatch.setattr(sys, "argv", ["aggregate", "--client", "nonexistent", "--root", str(root)])
    rc = main()
    assert rc == 1
    err = capsys.readouterr().err
    assert "scope.yaml absent" in err


def test_main_perimeter_invalid_exits_2(tmp_engagement, monkeypatch):
    root = tmp_engagement
    monkeypatch.setattr(sys, "argv", ["aggregate", "--client", "acme-corp", "--root", str(root), "--perimeter", "lunar"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 2
