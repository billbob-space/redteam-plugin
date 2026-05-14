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


SECRET_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|bearer)\s*[:=]\s*\S{12,}"
)

CSS = """\
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       max-width: 900px; margin: 2em auto; padding: 0 1em;
       color: #222; line-height: 1.5; }
h1, h2, h3 { color: #1a1a1a; }
h1 { border-bottom: 2px solid #888; padding-bottom: 0.3em; }
h2 { border-bottom: 1px solid #ddd; padding-bottom: 0.2em; margin-top: 1.8em; }
code { background: #f4f4f4; padding: 0.15em 0.4em; border-radius: 3px;
       font-size: 0.92em; }
pre { background: #f4f4f4; padding: 1em; border-radius: 5px; overflow-x: auto; }
pre code { background: none; padding: 0; }
table { border-collapse: collapse; margin: 1em 0; }
th, td { border: 1px solid #ccc; padding: 0.4em 0.8em; text-align: left; }
th { background: #f0f0f0; }
a { color: #0a58ca; }
nav { margin-bottom: 1.5em; font-size: 0.9em; color: #555; }
nav a { margin-right: 1em; }
"""


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>{title}</title>
<link rel="stylesheet" href="{css_path}">
</head>
<body>
<nav>{nav}</nav>
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


def _render_report(md_path: Path, out_path: Path, css_path: str, nav: str) -> None:
    md_text = md_path.read_text(encoding="utf-8")
    _check_credentials(md_text, md_path)
    # Retire le frontmatter YAML pour ne pas le rendre tel quel.
    md_clean = re.sub(r"^---\n.*?\n---\n", "", md_text, count=1, flags=re.DOTALL)
    body = markdown.markdown(
        md_clean, extensions=["tables", "fenced_code", "toc", "sane_lists"]
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        _render_template(md_path.stem, css_path, nav, body), encoding="utf-8"
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


def _render_global_index(
    clients_with_reports: dict[str, list[Path]], out_dir: Path
) -> None:
    rows = []
    for client in sorted(clients_with_reports):
        reports = clients_with_reports[client]
        if not reports:
            continue
        latest = reports[0]
        rows.append(
            f"<tr>"
            f'<td><a href="{client}/index.html">{_html.escape(client)}</a></td>'
            f'<td><a href="{client}/{latest.stem}.html">{_html.escape(latest.stem)}</a></td>'
            f"<td>{len(reports)}</td>"
            f"</tr>"
        )
    table = (
        "<table>\n"
        "<tr><th>Client</th><th>Dernier rapport</th><th>Total</th></tr>\n"
        + "\n".join(rows)
        + "\n</table>"
    ) if rows else "<p>Aucun rapport pour l'instant.</p>"
    body = "<h1>Dashboard des audits</h1>\n" + table
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
