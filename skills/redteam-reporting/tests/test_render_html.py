"""Tests pour render_html.py — rendu Markdown → HTML statique des rapports."""
from __future__ import annotations
import re
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


def test_severity_badges_injected(tmp_path):
    body = """---
title: Audit X
date: 2026-05-14
target: x
perimeter: external
risk_global: critical
counts:
  critical: 1
  high: 1
  medium: 0
  low: 0
  info: 0
---

# Audit X

### [CRITICAL] Service exposé

Texte du finding.

### [HIGH] Cert expirant

Texte.
"""
    _make_report(tmp_path, "acme-corp", "2026-05-14", body=body)
    render(client_filter=None, root=tmp_path, out_dir=tmp_path / "_html")
    html = (tmp_path / "_html" / "acme-corp" / "2026-05-14.html").read_text()
    assert '<span class="sev sev-critical">Critical</span>' in html
    assert '<span class="sev sev-high">High</span>' in html


def test_summary_cards_rendered_from_frontmatter(tmp_path):
    body = """---
title: Audit X
date: 2026-05-14
target: x
perimeter: external
risk_global: high
counts:
  critical: 0
  high: 3
  medium: 1
  low: 2
  info: 0
---

# Audit X
"""
    _make_report(tmp_path, "acme-corp", "2026-05-14", body=body)
    render(client_filter=None, root=tmp_path, out_dir=tmp_path / "_html")
    html = (tmp_path / "_html" / "acme-corp" / "2026-05-14.html").read_text()
    assert 'class="summary-cards"' in html
    # Vérifie qu'on a bien 5 cards (toutes les sévérités), pas juste les non-zéro
    assert html.count('class="card sev-') == 5
    # Vérifie que les valeurs apparaissent au bon endroit
    assert '<div class="count">3</div>' in html  # high
    assert '<div class="count">2</div>' in html  # low


def test_findings_toc_lists_severity_headings(tmp_path):
    body = """---
title: Audit X
date: 2026-05-14
target: x
perimeter: external
risk_global: critical
counts:
  critical: 1
  high: 1
---

# Audit X

### [CRITICAL] Finding A

Texte.

### [HIGH] Finding B

Texte.
"""
    _make_report(tmp_path, "acme-corp", "2026-05-14", body=body)
    render(client_filter=None, root=tmp_path, out_dir=tmp_path / "_html")
    html = (tmp_path / "_html" / "acme-corp" / "2026-05-14.html").read_text()
    assert 'class="findings-toc"' in html
    assert "Finding A" in html
    assert "Finding B" in html
    # La TOC a au moins un lien cliquable href="#..." vers un finding
    assert re.search(r'<li><a href="#[^"]+">', html), "TOC sans lien <li><a href=\"#...\">"


def test_global_dashboard_shows_severity_badges(tmp_path):
    body = """---
title: Audit X
date: 2026-05-14
target: x
perimeter: external
risk_global: high
counts:
  high: 2
  medium: 1
---

# Audit X
"""
    _make_report(tmp_path, "acme-corp", "2026-05-14", body=body)
    render(client_filter=None, root=tmp_path, out_dir=tmp_path / "_html")
    idx = (tmp_path / "_html" / "index.html").read_text()
    # Badge "High 2" doit apparaître dans la card du client
    assert 'class="sev sev-high"' in idx
    assert "High 2" in idx
    assert 'Risque' in idx  # le badge "Risque <niveau>" doit être présent


REPORT_WITH_REMEDIATION = """---
title: Re-vérif acme-corp
date: 2026-05-15
target: acme-corp.com
perimeter: re-verif
risk_global: critical
counts:
  critical: 1
  high: 1
remediation:
  - id: F-01
    title: 7 certs TLS expirants
    anchor: high-finding-01-certs-fixed
    status: fixed
    before: { severity: high, cvss: "n/a" }
    after:  { severity: info, cvss: "364 j" }
  - id: F-08
    title: DNS open resolver
    status: open
    before: { severity: high, cvss: 7.5 }
    after:  { severity: high, cvss: "7.5 inchangé" }
  - id: F-11
    title: Squid open proxy
    status: escalated
    before: { severity: high, cvss: 7.4 }
    after:  { severity: critical, cvss: "9.1 ↑" }
---

# Re-vérif acme-corp
"""


def test_remediation_tiles_injected_when_frontmatter_present(tmp_path):
    _make_report(tmp_path, "acme-corp", "2026-05-15", body=REPORT_WITH_REMEDIATION)
    render(client_filter=None, root=tmp_path, out_dir=tmp_path / "_html")
    html = (tmp_path / "_html" / "acme-corp" / "2026-05-15.html").read_text()
    assert 'class="remediation-tiles"' in html
    # 3 tiles : ok (fixed), bad (open), warn (escalated)
    assert 'class="tile ok"' in html
    assert 'class="tile bad"' in html
    assert 'class="tile warn"' in html
    # Compteurs corrects : 1 fixed, 1 open, 1 escalated
    assert html.count('<p class="value">1</p>') == 3


def test_remediation_strip_renders_one_row_per_finding(tmp_path):
    _make_report(tmp_path, "acme-corp", "2026-05-15", body=REPORT_WITH_REMEDIATION)
    render(client_filter=None, root=tmp_path, out_dir=tmp_path / "_html")
    html = (tmp_path / "_html" / "acme-corp" / "2026-05-15.html").read_text()
    assert html.count('class="finding-row"') == 3
    # Préserve l'ordre auteur (F-01 en premier)
    pos_f01 = html.find("F-01")
    pos_f08 = html.find("F-08")
    pos_f11 = html.find("F-11")
    assert 0 < pos_f01 < pos_f08 < pos_f11
    # Status pills présentes
    assert 'class="status-pill fixed"' in html
    assert 'class="status-pill open"' in html
    assert 'class="status-pill escalated"' in html
    # Anchor href généré si fourni dans le frontmatter
    assert 'href="#high-finding-01-certs-fixed"' in html
    # Pas de href si anchor absent
    assert '<a href="#"' not in html


def test_remediation_strip_renders_before_after_severities(tmp_path):
    _make_report(tmp_path, "acme-corp", "2026-05-15", body=REPORT_WITH_REMEDIATION)
    render(client_filter=None, root=tmp_path, out_dir=tmp_path / "_html")
    html = (tmp_path / "_html" / "acme-corp" / "2026-05-15.html").read_text()
    # Squid : high → critical (escalade)
    # On cherche le pattern dans la zone autour de F-11
    f11_start = html.find("F-11")
    assert f11_start > 0
    f11_zone = html[f11_start:f11_start + 1200]
    assert 'sev sev-high' in f11_zone     # before
    assert 'sev sev-critical' in f11_zone  # after


def test_remediation_absent_no_strip_no_tiles(tmp_path):
    """Backwards compat : si pas de `remediation:` dans le frontmatter,
    le rendu ne change pas."""
    _make_report(tmp_path, "acme-corp", "2026-05-14")  # frontmatter sans remediation:
    render(client_filter=None, root=tmp_path, out_dir=tmp_path / "_html")
    html = (tmp_path / "_html" / "acme-corp" / "2026-05-14.html").read_text()
    assert 'class="remediation-tiles"' not in html
    assert 'class="finding-strip"' not in html
    assert 'class="finding-row"' not in html


def test_remediation_unknown_status_ignored_in_tile_count(tmp_path):
    """Un status inconnu (typo) ne crashe pas et n'incrémente aucun compteur."""
    body = """---
title: x
date: 2026-05-15
remediation:
  - id: F-01
    title: t
    status: wontfix
    before: { severity: high, cvss: 1 }
    after:  { severity: high, cvss: 1 }
---
# x
"""
    _make_report(tmp_path, "acme-corp", "2026-05-15", body=body)
    render(client_filter=None, root=tmp_path, out_dir=tmp_path / "_html")
    html = (tmp_path / "_html" / "acme-corp" / "2026-05-15.html").read_text()
    # Tiles présentes mais tous à 0
    assert 'class="remediation-tiles"' in html
    assert html.count('<p class="value">0</p>') == 3
    # Ligne quand même rendue
    assert html.count('class="finding-row"') == 1


def test_css_includes_remediation_components(tmp_path):
    """Le stylesheet global doit exposer les classes des composants
    de remédiation (remediation-tiles, finding-strip, status-pill) pour
    que les rapports de re-vérification n'aient pas besoin de `<style>`
    embarqué."""
    _make_report(tmp_path, "acme-corp", "2026-05-14")
    out = tmp_path / "_html"
    render(client_filter=None, root=tmp_path, out_dir=out)
    css = (out / "style.css").read_text()
    for cls in (
        ".remediation-tiles",
        ".remediation-tiles .tile.ok",
        ".remediation-tiles .tile.bad",
        ".remediation-tiles .tile.warn",
        ".finding-strip",
        ".finding-row",
        ".status-pill",
        ".status-pill.fixed",
        ".status-pill.open",
        ".status-pill.escalated",
    ):
        assert cls in css, f"classe manquante dans style.css: {cls}"


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
