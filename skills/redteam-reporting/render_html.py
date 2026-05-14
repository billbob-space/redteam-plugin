"""Rendu Markdown → HTML statique des rapports d'audit.

Génère un mini-site HTML autonome sous `<out>/` :

    <out>/
    ├── index.html          # dashboard global (un client = une ligne)
    ├── style.css           # CSS embarquée minimaliste
    └── <client>/
        ├── index.html      # liste des rapports du client
        └── <date>.html     # rapport rendu depuis le MD

Aucune URL absolue dans le HTML produit (uniquement des liens relatifs) : le
résultat est portable et peut être servi depuis n'importe quel webserver statique.

Usage :
    python render_html.py --root <repo> [--client <slug>] [--out <html-dir>]

Par défaut `--out` = `<root>/engagements/_html/`.
"""
from __future__ import annotations

import argparse
import html as _html
import re
import sys
from pathlib import Path

import markdown
import yaml


SECRET_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|bearer)\s*[:=]\s*\S{12,}"
)

# Détecte les headings type "### [CRITICAL] ..." pour injecter un badge coloré.
SEVERITY_HEADING_RE = re.compile(
    r'(<h3[^>]*>)\s*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+',
    re.IGNORECASE,
)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABEL = {
    "critical": "Critical", "high": "High",
    "medium": "Medium", "low": "Low", "info": "Info",
}

CSS = """\
:root {
  --sev-critical: #b91c1c;
  --sev-critical-bg: #fee2e2;
  --sev-high: #ea580c;
  --sev-high-bg: #ffedd5;
  --sev-medium: #d97706;
  --sev-medium-bg: #fef3c7;
  --sev-low: #2563eb;
  --sev-low-bg: #dbeafe;
  --sev-info: #6b7280;
  --sev-info-bg: #f3f4f6;
  --text: #1f2937;
  --muted: #6b7280;
  --border: #e5e7eb;
  --accent: #0a58ca;
}

* { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  max-width: 1100px; margin: 2em auto; padding: 0 1em;
  color: var(--text); line-height: 1.55;
  background: #fafafa;
}
h1, h2, h3 { color: #111827; line-height: 1.3; }
h1 { border-bottom: 2px solid #888; padding-bottom: 0.3em; margin-top: 0; }
h2 { border-bottom: 1px solid var(--border); padding-bottom: 0.2em; margin-top: 2em; }
h3 { margin-top: 1.5em; }
p { margin: 0.7em 0; }
code { background: #f4f4f4; padding: 0.15em 0.4em; border-radius: 3px;
       font-size: 0.92em; }
pre { background: #1f2937; color: #f9fafb; padding: 1em; border-radius: 6px;
      overflow-x: auto; font-size: 0.88em; }
pre code { background: none; padding: 0; color: inherit; }
table { border-collapse: collapse; margin: 1em 0; width: 100%; max-width: 100%; }
th, td { border: 1px solid var(--border); padding: 0.5em 0.9em; text-align: left; }
th { background: #f3f4f6; font-weight: 600; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
hr { border: none; border-top: 1px solid var(--border); margin: 2em 0; }
nav.top {
  margin-bottom: 1.5em; font-size: 0.9em; color: var(--muted);
  padding: 0.6em 0.9em; background: #fff; border: 1px solid var(--border);
  border-radius: 6px;
}
nav.top a { margin-right: 1em; }

/* Severity badges (inline, dans les titres de findings) */
.sev {
  display: inline-block;
  padding: 0.15em 0.55em;
  border-radius: 3px;
  font-size: 0.78em;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  vertical-align: middle;
  margin-right: 0.5em;
}
.sev-critical { color: #fff; background: var(--sev-critical); }
.sev-high     { color: #fff; background: var(--sev-high); }
.sev-medium   { color: #fff; background: var(--sev-medium); }
.sev-low      { color: #fff; background: var(--sev-low); }
.sev-info     { color: #fff; background: var(--sev-info); }

/* Summary cards (en haut du rapport) */
.summary-cards {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 0.75em;
  margin: 1.5em 0 2em 0;
}
.summary-cards .card {
  background: #fff;
  border-left: 4px solid var(--border);
  padding: 0.8em 1em;
  border-radius: 4px;
  box-shadow: 0 1px 2px rgba(0,0,0,0.04);
}
.summary-cards .card.sev-critical { border-left-color: var(--sev-critical); background: var(--sev-critical-bg); }
.summary-cards .card.sev-high     { border-left-color: var(--sev-high);     background: var(--sev-high-bg); }
.summary-cards .card.sev-medium   { border-left-color: var(--sev-medium);   background: var(--sev-medium-bg); }
.summary-cards .card.sev-low      { border-left-color: var(--sev-low);      background: var(--sev-low-bg); }
.summary-cards .card.sev-info     { border-left-color: var(--sev-info);     background: var(--sev-info-bg); }
.summary-cards .card .label {
  font-size: 0.72em; text-transform: uppercase;
  letter-spacing: 0.05em; color: var(--muted);
}
.summary-cards .card .count {
  font-size: 1.8em; font-weight: 700; line-height: 1;
}

/* TOC des findings (encadré à droite du résumé exécutif) */
.findings-toc {
  background: #fff;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.8em 1.2em;
  margin: 1.5em 0;
}
.findings-toc h3 { margin: 0 0 0.5em 0; font-size: 1em; color: var(--muted);
                    text-transform: uppercase; letter-spacing: 0.05em; }
.findings-toc ol { margin: 0; padding-left: 1.4em; }
.findings-toc li { margin: 0.3em 0; }
.findings-toc a { color: var(--text); }
.findings-toc a:hover { color: var(--accent); }

/* Layout report : 2 colonnes pour titre+cards si écran large */
.report-header {
  background: #fff;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1em 1.5em;
  margin-bottom: 1em;
}

/* Dashboard global : cards par client */
.client-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 1em; margin-top: 1em;
}
.client-card {
  background: #fff; border: 1px solid var(--border); border-radius: 6px;
  padding: 1em 1.2em;
}
.client-card h3 { margin: 0 0 0.4em 0; font-size: 1.1em; }
.client-card a { font-weight: 600; }
.client-card .meta { color: var(--muted); font-size: 0.88em; }

@media (max-width: 720px) {
  .summary-cards { grid-template-columns: repeat(2, 1fr); }
}

@media print {
  body { background: #fff; max-width: 100%; margin: 0; }
  nav.top, .findings-toc { display: none; }
  pre { background: #f4f4f4; color: #222; border: 1px solid #ddd; }
  a { color: #222; text-decoration: none; }
  .summary-cards .card { box-shadow: none; }
  h2, h3 { page-break-after: avoid; }
  pre, table { page-break-inside: avoid; }
}
"""


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="{css_path}">
</head>
<body>
<nav class="top">{nav}</nav>
{body}
</body>
</html>
"""


def _check_credentials(md_text: str, path: Path) -> None:
    """Warn (stderr) si un pattern type credential est trouvé. Ne bloque pas."""
    for m in SECRET_PATTERN.finditer(md_text):
        snippet = m.group(0)
        if len(snippet) > 60:
            snippet = snippet[:60] + "..."
        sys.stderr.write(
            f"WARN: possible credential/secret dans {path}: {snippet}\n"
        )


def _render_template(title: str, css_path: str, nav: str, body: str) -> str:
    return HTML_TEMPLATE.format(
        title=_html.escape(title), css_path=css_path, nav=nav, body=body
    )


def _find_md_reports(client_dir: Path) -> list[Path]:
    rapports = client_dir / "rapports"
    if not rapports.is_dir():
        return []
    return sorted(
        (p for p in rapports.glob("*.md") if p.name != "INDEX.md"),
        key=lambda p: p.stem,
        reverse=True,
    )


def _parse_frontmatter(md_text: str) -> dict:
    """Retourne le dict frontmatter (vide si absent/invalide). Ne lève pas."""
    m = re.match(r"^---\n(.*?)\n---\n", md_text, re.DOTALL)
    if not m:
        return {}
    try:
        return yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError:
        return {}


def _inject_severity_badges(html_body: str) -> str:
    """Remplace `<h3 id="...">[CRITICAL] ...` par `<h3 id="..."><span class="sev sev-critical">Critical</span> ...`."""
    def replace(m: re.Match) -> str:
        h3_open = m.group(1)
        sev = m.group(2).lower()
        return f'{h3_open}<span class="sev sev-{sev}">{SEVERITY_LABEL[sev]}</span> '
    return SEVERITY_HEADING_RE.sub(replace, html_body)


def _summary_cards_html(counts: dict) -> str:
    """Génère les cards de comptage à partir du frontmatter:counts."""
    if not counts:
        return ""
    cards = []
    for sev in SEVERITY_ORDER:
        n = int(counts.get(sev, 0) or 0)
        cards.append(
            f'<div class="card sev-{sev}">'
            f'<div class="label">{SEVERITY_LABEL[sev]}</div>'
            f'<div class="count">{n}</div>'
            f'</div>'
        )
    return '<div class="summary-cards">\n' + "\n".join(cards) + '\n</div>'


def _extract_findings_toc(html_body: str) -> str:
    """Construit une TOC des findings à partir des `<h3 ...>[SEV]...`."""
    # On re-parse le HTML déjà transformé (les badges ont été injectés).
    # Pattern: <h3 id="X"><span class="sev sev-Y">LABEL</span> TITLE</h3>
    pattern = re.compile(
        r'<h3 id="([^"]+)"><span class="sev sev-(critical|high|medium|low|info)">'
        r'([^<]+)</span>\s*([^<]+)</h3>',
        re.IGNORECASE,
    )
    items = []
    for m in pattern.finditer(html_body):
        anchor, sev, label, title = m.group(1), m.group(2), m.group(3), m.group(4).strip()
        items.append(
            f'<li><a href="#{anchor}">'
            f'<span class="sev sev-{sev}">{label}</span>'
            f'{_html.escape(title)}</a></li>'
        )
    if not items:
        return ""
    return (
        '<div class="findings-toc">\n'
        '<h3>Findings (cliquables)</h3>\n'
        '<ol>\n' + "\n".join(items) + '\n</ol>\n'
        '</div>'
    )


def _render_report(md_path: Path, out_path: Path, css_path: str, nav: str) -> None:
    md_text = md_path.read_text(encoding="utf-8")
    _check_credentials(md_text, md_path)

    fm = _parse_frontmatter(md_text)
    counts = fm.get("counts") or {}

    # Retire le frontmatter YAML pour ne pas le rendre tel quel.
    md_clean = re.sub(r"^---\n.*?\n---\n", "", md_text, count=1, flags=re.DOTALL)
    body_raw = markdown.markdown(
        md_clean, extensions=["tables", "fenced_code", "toc", "sane_lists"]
    )

    # Injection des badges sévérité
    body_with_badges = _inject_severity_badges(body_raw)

    # Construction TOC findings
    toc_html = _extract_findings_toc(body_with_badges)

    # Cards récap
    cards_html = _summary_cards_html(counts)

    # Insère cards + TOC juste après le premier <h1>
    final_body = re.sub(
        r"(</h1>)",
        r"\1\n" + cards_html + ("\n" + toc_html if toc_html else ""),
        body_with_badges,
        count=1,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        _render_template(md_path.stem, css_path, nav, final_body),
        encoding="utf-8",
    )


def _render_client_index(client: str, reports: list[Path], out_dir: Path) -> None:
    items = "\n".join(
        f'<li><a href="{r.stem}.html">{_html.escape(r.stem)}</a></li>' for r in reports
    )
    body = (
        f"<h1>Engagement : {_html.escape(client)}</h1>\n"
        f"<ul>\n{items}\n</ul>"
    )
    nav = '<a href="../index.html">← dashboard</a>'
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "index.html").write_text(
        _render_template(f"Engagement {client}", "../style.css", nav, body),
        encoding="utf-8",
    )


def _client_latest_summary(reports: list[Path]) -> tuple[str, str, dict]:
    """Retourne (date_str, risk_global, counts) du rapport le plus récent."""
    if not reports:
        return ("", "", {})
    latest = reports[0]
    fm = _parse_frontmatter(latest.read_text(encoding="utf-8"))
    return (
        latest.stem,
        str(fm.get("risk_global", "?")),
        fm.get("counts") or {},
    )


def _render_global_index(
    clients_with_reports: dict[str, list[Path]], out_dir: Path
) -> None:
    cards = []
    for client in sorted(clients_with_reports):
        reports = clients_with_reports[client]
        if not reports:
            continue
        latest = reports[0]
        date_str, risk, counts = _client_latest_summary(reports)
        # Badges compacts par sévérité
        badges_inline = []
        for sev in SEVERITY_ORDER:
            n = int(counts.get(sev, 0) or 0)
            if n > 0:
                badges_inline.append(
                    f'<span class="sev sev-{sev}">{SEVERITY_LABEL[sev]} {n}</span>'
                )
        badges_html = " ".join(badges_inline) if badges_inline else \
                      '<span class="meta">aucun finding</span>'
        risk_badge = (
            f'<span class="sev sev-{risk.lower()}">Risque {risk}</span>'
            if risk.lower() in SEVERITY_ORDER else ""
        )
        cards.append(
            '<div class="client-card">\n'
            f'<h3><a href="{client}/index.html">{_html.escape(client)}</a></h3>\n'
            f'<div class="meta">Dernier rapport : <a href="{client}/{latest.stem}.html">{_html.escape(date_str)}</a> · {len(reports)} rapport(s) total</div>\n'
            f'<div style="margin-top:0.5em">{risk_badge} {badges_html}</div>\n'
            '</div>'
        )
    grid = (
        '<div class="client-grid">\n' + "\n".join(cards) + '\n</div>'
        if cards else "<p>Aucun rapport pour l'instant.</p>"
    )
    body = "<h1>Dashboard des audits</h1>\n" + grid
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "style.css").write_text(CSS, encoding="utf-8")
    (out_dir / "index.html").write_text(
        _render_template("Audits", "style.css", "", body), encoding="utf-8"
    )


def render(client_filter: str | None, root: Path, out_dir: Path) -> None:
    """Rend les rapports MD en HTML statique sous `out_dir`.

    Si `client_filter` est fourni, seul ce client est re-rendu en per-client
    pages, mais le dashboard global est toujours reconstruit à partir de tous
    les engagements (pour éviter la perte de lignes au prochain run filtré).
    """
    engagements = root / "engagements"
    if not engagements.is_dir():
        sys.stderr.write(f"ERROR: pas de répertoire engagements/ sous {root}\n")
        sys.exit(1)

    all_clients: dict[str, list[Path]] = {}
    for client_dir in sorted(engagements.iterdir()):
        if not client_dir.is_dir() or client_dir.name.startswith("_"):
            continue
        reports = _find_md_reports(client_dir)
        all_clients[client_dir.name] = reports

        if client_filter is not None and client_dir.name != client_filter:
            continue
        if not reports:
            continue

        client_out = out_dir / client_dir.name
        nav = (
            '<a href="../index.html">← dashboard</a> '
            f'<a href="index.html">← {_html.escape(client_dir.name)}</a>'
        )
        for r in reports:
            _render_report(r, client_out / f"{r.stem}.html", "../style.css", nav)
        _render_client_index(client_dir.name, reports, client_out)

    _render_global_index(all_clients, out_dir)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--root", default=".",
        help="Racine du repo qui contient engagements/ (défaut: .)",
    )
    p.add_argument(
        "--client", default=None,
        help="Slug d'un client à rendre seul (sinon : tous)",
    )
    p.add_argument(
        "--out", default=None,
        help="Dir de sortie HTML (défaut: <root>/engagements/_html/)",
    )
    args = p.parse_args()
    root = Path(args.root).resolve()
    out = Path(args.out).resolve() if args.out else root / "engagements" / "_html"
    render(args.client, root, out)
    sys.stderr.write(f"OK: HTML écrit dans {out}\n")


if __name__ == "__main__":
    main()
