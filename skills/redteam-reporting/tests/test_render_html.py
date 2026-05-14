"""Tests pour render_html.py — rendu Markdown → HTML statique des rapports."""
from __future__ import annotations
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

pytest.importorskip("markdown")

from render_html import render  # noqa: E402


SAMPLE_REPORT_ACME = """---
title: Audit acme-corp
date: 2026-05-14
target: acme-corp.com
perimeter: external
risk_global: medium
counts:
  high: 1
  medium: 2
  low: 0
---

# Audit acme-corp

## Findings

- SQLi sur `/login`
- XSS reflected sur `/search`
"""


def _make_report(root: Path, client: str, date: str, body: str = SAMPLE_REPORT_ACME) -> Path:
    rapports = root / "engagements" / client / "rapports"
    rapports.mkdir(parents=True, exist_ok=True)
    p = rapports / f"{date}.md"
    p.write_text(body)
    return p


def test_render_creates_expected_files(tmp_path):
    _make_report(tmp_path, "acme-corp", "2026-05-14")
    out = tmp_path / "_html"
    render(client_filter=None, root=tmp_path, out_dir=out)

    assert (out / "index.html").is_file()
    assert (out / "style.css").is_file()
    assert (out / "acme-corp" / "index.html").is_file()
    assert (out / "acme-corp" / "2026-05-14.html").is_file()


def test_rendered_report_contains_markdown_body(tmp_path):
    _make_report(tmp_path, "acme-corp", "2026-05-14")
    out = tmp_path / "_html"
    render(client_filter=None, root=tmp_path, out_dir=out)

    html = (out / "acme-corp" / "2026-05-14.html").read_text()
    assert ">Audit acme-corp</h1>" in html  # tolère un id="..." injecté par toc
    assert "SQLi sur" in html
    assert "<code>/login</code>" in html


def test_global_index_lists_clients_with_reports(tmp_path):
    _make_report(tmp_path, "acme-corp", "2026-05-14")
    _make_report(tmp_path, "customer-2", "2026-05-13")
    out = tmp_path / "_html"
    render(client_filter=None, root=tmp_path, out_dir=out)

    idx = (out / "index.html").read_text()
    assert "acme-corp" in idx
    assert "customer-2" in idx


def test_template_prefix_ignored(tmp_path):
    _make_report(tmp_path, "_template", "2026-05-14")
    out = tmp_path / "_html"
    render(client_filter=None, root=tmp_path, out_dir=out)

    assert not (out / "_template").exists()
    idx = (out / "index.html").read_text()
    assert "_template" not in idx


def test_client_without_reports_excluded_from_global(tmp_path):
    (tmp_path / "engagements" / "empty").mkdir(parents=True)
    _make_report(tmp_path, "acme-corp", "2026-05-14")
    out = tmp_path / "_html"
    render(client_filter=None, root=tmp_path, out_dir=out)

    idx = (out / "index.html").read_text()
    assert "empty" not in idx
    assert "acme-corp" in idx


def test_client_filter_only_renders_target_client(tmp_path):
    _make_report(tmp_path, "acme-corp", "2026-05-14")
    _make_report(tmp_path, "customer-2", "2026-05-13")
    out = tmp_path / "_html"
    render(client_filter="acme-corp", root=tmp_path, out_dir=out)

    assert (out / "acme-corp" / "2026-05-14.html").is_file()
    assert not (out / "customer-2").exists()
    # Mais l'INDEX global reste complet (sinon perte de données au prochain --client X)
    idx = (out / "index.html").read_text()
    assert "acme-corp" in idx
    assert "customer-2" in idx


def test_per_client_index_lists_reports_desc(tmp_path):
    _make_report(tmp_path, "acme-corp", "2026-05-14")
    _make_report(tmp_path, "acme-corp", "2026-04-22")
    out = tmp_path / "_html"
    render(client_filter=None, root=tmp_path, out_dir=out)

    idx = (out / "acme-corp" / "index.html").read_text()
    p14 = idx.find("2026-05-14")
    p22 = idx.find("2026-04-22")
    assert p14 != -1 and p22 != -1
    assert p14 < p22, "le rapport le plus récent doit être listé en premier"


def test_warn_on_potential_credential(tmp_path, capsys):
    body = SAMPLE_REPORT_ACME + "\n\napi_key=AKIAIOSFODNN7EXAMPLEXX leaked\n"
    _make_report(tmp_path, "acme-corp", "2026-05-14", body=body)
    out = tmp_path / "_html"
    render(client_filter=None, root=tmp_path, out_dir=out)

    err = capsys.readouterr().err
    assert "WARN" in err
    assert "credential" in err.lower() or "secret" in err.lower()


def test_no_engagements_dir_exits_clean(tmp_path):
    out = tmp_path / "_html"
    with pytest.raises(SystemExit) as exc:
        render(client_filter=None, root=tmp_path, out_dir=out)
    assert exc.value.code != 0


def test_no_absolute_paths_in_output(tmp_path):
    """Garde-fou : les pages générées ne doivent JAMAIS contenir de chemin absolu de
    la machine de build (pas de /projects/..., /home/..., etc.). Seulement des liens
    relatifs."""
    _make_report(tmp_path, "acme-corp", "2026-05-14")
    out = tmp_path / "_html"
    render(client_filter=None, root=tmp_path, out_dir=out)

    for html in out.rglob("*.html"):
        text = html.read_text()
        assert "/projects/" not in text, f"chemin absolu dans {html}"
        assert "/home/" not in text, f"chemin absolu dans {html}"
        assert str(tmp_path) not in text, f"tmp_path leaké dans {html}"
