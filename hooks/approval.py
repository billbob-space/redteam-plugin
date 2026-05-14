"""Gestion des approbations intrusive_actions[] avec granularité par flags.

Une approbation a 5 champs sur disque :
  - tool        (str)
  - target      (str, comparé après normalize_target)
  - approved_at (ISO 8601)
  - approved_by (str)
  - approved_flags (list[str], défaut []) — couvre les flags dangereux

is_approved() renvoie un ApprovalResult à 3 valeurs.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from urllib.parse import urlparse

import yaml

from scope import Scope

APPROVAL_TTL_HOURS = 24


class ApprovalResult(Enum):
    APPROVED = "approved"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    NOT_APPROVED = "not_approved"


DANGEROUS_FLAGS_BY_TOOL: dict[str, set[str]] = {
    "sqlmap": {
        "--os-shell", "--os-pwn", "--os-cmd", "--os-bof",
        "--dump-all", "--dump", "--passwords", "--privileges",
        "--sql-shell", "--reg-add", "--reg-del",
        "--file-write", "--file-read", "--eval",
    },
    "commix": {
        "--root", "--web-root", "--file-write",
        "--shellshock", "--reverse-tcp",
    },
    "nuclei": set(),
    "dalfox": set(),
    "arjun": set(),
}


def find_dangerous_flags(tool: str, flags: list[str]) -> list[str]:
    dangerous = DANGEROUS_FLAGS_BY_TOOL.get(tool, set())
    result = []
    for f in flags:
        base = f.split("=", 1)[0]
        if base in dangerous:
            result.append(f)
    return result


def normalize_target(target: str) -> str:
    """Clé de comparaison stable pour les approvals.

    URL : (scheme, lowercase host, path sans trailing '/'). Query/fragment dropés.
    @file:... : passthrough.
    Host nu : lowercase + drop trailing '/'.
    """
    if target.startswith("@file:"):
        return target
    if target.startswith(("http://", "https://", "ws://", "wss://")):
        p = urlparse(target)
        host = (p.hostname or "").lower()
        port_part = f":{p.port}" if p.port is not None else ""
        path = p.path.rstrip("/") or "/"
        return f"{p.scheme}://{host}{port_part}{path}"
    return target.lower().rstrip("/")


def _coerce_dt(value) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def is_approved(
    scope: Scope,
    *,
    tool: str,
    target: str,
    used_dangerous_flags: list[str] | None = None,
    now: datetime | None = None,
) -> ApprovalResult:
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=APPROVAL_TTL_HOURS)
    needed = set(used_dangerous_flags or [])
    target_key = normalize_target(target)

    found_target_match = False
    for action in scope.intrusive_actions:
        if action.get("tool") != tool:
            continue
        if normalize_target(action.get("target", "")) != target_key:
            continue
        approved_at = _coerce_dt(action.get("approved_at"))
        if approved_at is None or not (cutoff <= approved_at <= now):
            continue
        found_target_match = True
        approved_flags = set(action.get("approved_flags") or [])
        if needed.issubset(approved_flags):
            return ApprovalResult.APPROVED
    if found_target_match and needed:
        return ApprovalResult.INSUFFICIENT_SCOPE
    return ApprovalResult.NOT_APPROVED


def append_approval(
    scope: Scope,
    *,
    tool: str,
    target: str,
    approved_by: str,
    approved_flags: list[str] | None = None,
    approved_at: datetime | None = None,
) -> None:
    if scope.path is None:
        raise RuntimeError("Scope chargé sans chemin sur disque, impossible d'écrire.")
    approved_at = approved_at or datetime.now(timezone.utc)
    with open(scope.path) as f:
        raw = yaml.safe_load(f)
    actions = list(raw.get("intrusive_actions") or [])
    entry = {
        "tool": tool,
        "target": target,
        "approved_at": approved_at.isoformat(),
        "approved_by": approved_by,
    }
    if approved_flags:
        entry["approved_flags"] = list(approved_flags)
    actions.append(entry)
    raw["intrusive_actions"] = actions
    with open(scope.path, "w") as f:
        yaml.safe_dump(raw, f, sort_keys=False, default_flow_style=False)
