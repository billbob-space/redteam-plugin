"""Régénère engagements/<X>/rapports/INDEX.md et engagements/INDEX.md à partir
des frontmatter de chaque rapport. Warn-and-skip sur frontmatter invalide
(ne bloque pas le workflow ; aggregate_findings.py hard-fail en amont).
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

import yaml

INDEX_FILENAME = "INDEX.md"
REQUIRED_REPORT_FIELDS = ("target", "date", "perimeter", "risk_global", "counts")


def _parse_report_frontmatter(path: Path) -> dict | None:
    """Retourne le frontmatter dict, ou None si invalide (warn imprimé)."""
    try:
        text = path.read_text()
    except OSError as e:
        print(f"warn: {path}: I/O ({e})", file=sys.stderr)
        return None
    m = re.match(r"^---\n(.*?)\n---", text, re.DOTALL)
    if not m:
        print(f"warn: {path}: frontmatter manquant — ignoré dans l'INDEX", file=sys.stderr)
        return None
    try:
        fm = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError as e:
        print(f"warn: {path}: YAML invalide ({e}) — ignoré", file=sys.stderr)
        return None
    if not all(k in fm for k in REQUIRED_REPORT_FIELDS):
        print(f"warn: {path}: champ requis manquant — ignoré", file=sys.stderr)
        return None
    # Normalise date → str (YAML parse YYYY-MM-DD non-quoté comme datetime.date)
    if "date" in fm and not isinstance(fm["date"], str):
        fm["date"] = fm["date"].isoformat() if hasattr(fm["date"], "isoformat") else str(fm["date"])
    return fm


def _build_engagement_index(eng_dir: Path) -> str:
    """Construit le contenu de engagements/<X>/rapports/INDEX.md."""
    scope_path = eng_dir / "scope.yaml"
    client = eng_dir.name
    ip = ""
    if scope_path.is_file():
        try:
            scope = yaml.safe_load(scope_path.read_text()) or {}
            client = scope.get("client", client)
            ip = scope.get("ip", "") or ""
        except (yaml.YAMLError, OSError):
            pass

    rapports_dir = eng_dir / "rapports"
    rows: list[dict] = []
    if rapports_dir.exists():
        for p in sorted(rapports_dir.glob("*.md")):
            if p.name == INDEX_FILENAME:
                continue
            fm = _parse_report_frontmatter(p)
            if fm is None:
                continue
            counts = fm.get("counts") or {}
            rows.append({
                "date": str(fm["date"]),
                "perimeter": str(fm["perimeter"]),
                "risk": str(fm["risk_global"]),
                "crit": int(counts.get("critical", 0)),
                "high": int(counts.get("high", 0)),
                "med": int(counts.get("medium", 0)),
                "low": int(counts.get("low", 0)),
                "info": int(counts.get("info", 0)),
            })
    rows.sort(key=lambda r: r["date"])

    lines = [f"# {client} — Historique des audits", ""]
    if ip:
        lines.append(f"**IP** : {ip}")
        lines.append("")
    if not rows:
        lines.append("_Aucun rapport généré._")
        return "\n".join(lines) + "\n"
    lines.append("| Date | Périmètre | Risque | Crit | Hau | Moy | Bas | Info |")
    lines.append("|------|-----------|--------|------|-----|-----|-----|------|")
    for r in rows:
        lines.append(
            f"| {r['date']} | {r['perimeter']} | **{r['risk'].upper()}** | "
            f"{r['crit']} | {r['high']} | {r['med']} | {r['low']} | {r['info']} |"
        )
    return "\n".join(lines) + "\n"


def _build_global_index(engagements_root: Path) -> str:
    """Construit engagements/INDEX.md — une ligne par client, dernier audit."""
    lines = ["# Engagements — Tableau de bord", ""]
    lines.append("| Client | Dernier audit | Périmètre | Risque | Crit | Hau | Moy | Bas |")
    lines.append("|--------|---------------|-----------|--------|------|-----|-----|-----|")

    has_row = False
    for eng_dir in sorted(engagements_root.iterdir()):
        if not eng_dir.is_dir() or eng_dir.name.startswith("_"):
            continue
        rapports_dir = eng_dir / "rapports"
        if not rapports_dir.exists():
            continue
        latest = None
        for p in sorted(rapports_dir.glob("*.md")):
            if p.name == INDEX_FILENAME:
                continue
            fm = _parse_report_frontmatter(p)
            if fm is None:
                continue
            if latest is None or str(fm["date"]) > str(latest["date"]):
                latest = fm
        if latest is None:
            continue
        counts = latest.get("counts") or {}
        has_row = True
        lines.append(
            f"| {eng_dir.name} | {latest['date']} | {latest['perimeter']} | "
            f"**{str(latest['risk_global']).upper()}** | "
            f"{counts.get('critical', 0)} | {counts.get('high', 0)} | "
            f"{counts.get('medium', 0)} | {counts.get('low', 0)} |"
        )
    if not has_row:
        lines = ["# Engagements — Tableau de bord", "", "_Aucun engagement avec rapports._"]
    return "\n".join(lines) + "\n"


def regenerate_indexes(root: Path) -> dict[str, int]:
    """Régénère per-engagement INDEX + global INDEX. Retourne {"engagements": n, "global": 0|1}."""
    root = Path(root).resolve()
    engagements_root = root / "engagements"
    if not engagements_root.is_dir():
        return {"engagements": 0, "global": 0}

    n = 0
    for eng_dir in engagements_root.iterdir():
        if not eng_dir.is_dir() or eng_dir.name.startswith("_"):
            continue
        rapports_dir = eng_dir / "rapports"
        rapports_dir.mkdir(parents=True, exist_ok=True)
        idx_path = rapports_dir / INDEX_FILENAME
        idx_path.write_text(_build_engagement_index(eng_dir))
        n += 1

    global_path = engagements_root / INDEX_FILENAME
    global_path.write_text(_build_global_index(engagements_root))
    return {"engagements": n, "global": 1}
