#!/usr/bin/env python3
"""Agrège engagements/<X>/findings/*.md → engagements/<X>/rapports/YYYY-MM-DD.md
et régénère les INDEX par engagement + global.

Validation stricte des findings : refuse de générer le rapport si un
finding a un frontmatter invalide. Le but est de protéger l'intégrité
du livrable client.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from index_builder import regenerate_indexes


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
PERIMETER_VALUES = {"external", "internal", "external+internal", "web", "network", "config"}
STATUS_VALUES = {"open", "fixed", "accepted_risk", "false_positive"}
REQUIRED_FINDING_FIELDS = {"title", "severity", "date"}


class FindingValidationError(Exception):
    """Levé sur un finding au frontmatter invalide (mode strict)."""


def parse_finding(path: Path, strict: bool = True) -> dict:
    """Parse un finding. En mode strict, lève FindingValidationError sur invalide.
    En mode non-strict, retourne un dict {"_error": <msg>, "path": <str>}.
    """
    text = path.read_text()
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
    if not m:
        msg = f"{path}: frontmatter manquant (attendu un bloc YAML entre ---)"
        if strict:
            raise FindingValidationError(msg)
        return {"_error": msg, "path": str(path)}
    try:
        front = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError as e:
        msg = f"{path}: YAML invalide ({e})"
        if strict:
            raise FindingValidationError(msg)
        return {"_error": msg, "path": str(path)}

    missing = REQUIRED_FINDING_FIELDS - set(front.keys())
    if missing:
        msg = f"{path}: champ(s) requis manquant(s): {sorted(missing)}"
        if strict:
            raise FindingValidationError(msg)
        return {"_error": msg, "path": str(path)}

    sev = str(front["severity"]).lower()
    if sev not in SEVERITY_ORDER:
        msg = f"{path}: severity '{front['severity']}' invalide (attendu: {SEVERITY_ORDER})"
        if strict:
            raise FindingValidationError(msg)
        return {"_error": msg, "path": str(path)}
    front["severity"] = sev

    try:
        front["date"] = date.fromisoformat(str(front["date"])).isoformat()
    except (ValueError, TypeError):
        msg = f"{path}: date '{front['date']}' non parseable (attendu YYYY-MM-DD)"
        if strict:
            raise FindingValidationError(msg)
        return {"_error": msg, "path": str(path)}

    status = str(front.get("status", "open")).lower()
    if status not in STATUS_VALUES:
        msg = f"{path}: status '{status}' invalide (attendu: {sorted(STATUS_VALUES)})"
        if strict:
            raise FindingValidationError(msg)
        return {"_error": msg, "path": str(path)}
    front["status"] = status

    front["body"] = m.group(2).strip()
    front["path"] = str(path)
    front.setdefault("title", path.stem)
    return front


def compute_counts(findings: list[dict]) -> dict[str, int]:
    """Compte les findings status=open par sévérité."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        if f.get("status", "open") != "open":
            continue
        sev = f.get("severity")
        if sev in counts:
            counts[sev] += 1
    return counts


def compute_risk_global(counts: dict[str, int]) -> str:
    """Plus haute sévérité avec count > 0, sinon 'none'."""
    for sev in SEVERITY_ORDER:
        if counts.get(sev, 0) > 0:
            return sev
    return "none"


def build_findings_block(findings: list[dict]) -> str:
    """Concatène les findings status=open, triés par sévérité puis titre."""
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    sorted_findings = sorted(
        [f for f in findings if f.get("status", "open") == "open"],
        key=lambda f: (order.get(f["severity"], 99), f.get("title", "")),
    )
    if not sorted_findings:
        return "_Aucun finding ouvert._"
    out = []
    for f in sorted_findings:
        out.append(f"### [{f['severity'].upper()}] {f.get('title', '')}\n")
        out.append(f.get("body", ""))
        out.append("\n---\n")
    return "\n".join(out)


def build_actions_block(findings: list[dict]) -> str:
    """Liste numérotée des findings open par sévérité décroissante."""
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    items = sorted(
        [f for f in findings if f.get("status", "open") == "open"],
        key=lambda f: (order.get(f["severity"], 99), f.get("title", "")),
    )
    if not items:
        return "_Pas de finding ouvert nécessitant d'action._"
    lines = []
    for i, f in enumerate(items, 1):
        lines.append(f"{i}. **[{f['severity'].upper()}]** {f.get('title', '')}")
    return "\n".join(lines)


def _read_playbook_version(root: Path) -> str:
    plugin_json = root / ".claude" / "plugins" / "redteam" / "plugin.json"
    if plugin_json.is_file():
        try:
            return json.loads(plugin_json.read_text()).get("version", "unknown")
        except (json.JSONDecodeError, OSError):
            return "unknown"
    return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--client", required=True)
    ap.add_argument("--root", default=".")
    ap.add_argument(
        "--template",
        default=str(Path(__file__).resolve().parent / "templates" / "default.md.tmpl"),
        help="Chemin du template Markdown. Par défaut: bundled du plugin.",
    )
    ap.add_argument("--perimeter", default="external", choices=sorted(PERIMETER_VALUES))
    ap.add_argument("--date", default=None, help="ISO date, default = today UTC")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    eng = root / "engagements" / args.client
    scope_path = eng / "scope.yaml"
    if not scope_path.is_file():
        print(f"engagements/{args.client}/scope.yaml absent", file=sys.stderr)
        return 1

    try:
        scope = yaml.safe_load(scope_path.read_text()) or {}
    except yaml.YAMLError as e:
        print(f"scope.yaml invalide : {e}", file=sys.stderr)
        return 1

    today = args.date or datetime.now(timezone.utc).date().isoformat()

    findings_dir = eng / "findings"
    findings: list[dict] = []
    if findings_dir.exists():
        for p in sorted(findings_dir.glob("*.md")):
            try:
                findings.append(parse_finding(p, strict=True))
            except FindingValidationError as e:
                print(f"erreur finding : {e}", file=sys.stderr)
                return 1

    counts = compute_counts(findings)
    risk = compute_risk_global(counts)

    template_path = Path(args.template)
    if not template_path.is_absolute():
        template_path = root / template_path
    tpl = template_path.read_text()

    sub_file = eng / "recon" / "subdomains.txt"
    subdomain_count = sum(1 for _ in sub_file.open()) if sub_file.exists() else 0
    in_scope_doms = (scope.get("in_scope") or {}).get("domains") or []
    in_scope_summary = ", ".join(in_scope_doms[:3]) + ("..." if len(in_scope_doms) > 3 else "")

    substitutions = {
        "{{ target }}": str(scope.get("client", args.client)),
        "{{ date }}": today,
        "{{ perimeter }}": args.perimeter,
        "{{ risk_global }}": risk,
        "{{ count_critical }}": str(counts["critical"]),
        "{{ count_high }}":     str(counts["high"]),
        "{{ count_medium }}":   str(counts["medium"]),
        "{{ count_low }}":      str(counts["low"]),
        "{{ count_info }}":     str(counts["info"]),
        "{{ ip }}":             str(scope.get("ip", "") or ""),
        "{{ auditor }}":        str(scope.get("authorized_by", "") or ""),
        "{{ tool }}":           "claude",
        "{{ playbook_version }}": _read_playbook_version(root),
        "{{ subdomain_count }}": str(subdomain_count),
        "{{ in_scope_summary }}": in_scope_summary,
        "{{ in_scope_block }}":  yaml.safe_dump(scope.get("in_scope") or {}, sort_keys=False),
        "{{ out_of_scope_block }}": yaml.safe_dump(scope.get("out_of_scope") or {}, sort_keys=False),
        "{{ findings_block }}":  build_findings_block(findings),
        "{{ actions_block }}":   build_actions_block(findings),
    }
    rendered = tpl
    for k, v in substitutions.items():
        rendered = rendered.replace(k, v)

    rapports_dir = eng / "rapports"
    rapports_dir.mkdir(parents=True, exist_ok=True)
    out_path = rapports_dir / f"{today}.md"
    out_path.write_text(rendered)
    print(f"Rapport écrit : {out_path}")

    regenerate_indexes(root)
    return 0


if __name__ == "__main__":
    sys.exit(main())
