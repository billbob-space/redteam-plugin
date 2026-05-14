#!/usr/bin/env python3
"""Hook PreToolUse — gate par scope pour les commandes Bash.

Pipeline : detector → classifier → scope → approval → decide → audit_log.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from detector import detect
from scope import Scope, ScopeResult, load_scope, is_recon_artifact_file
from classifier import classify, Category
from approval import is_approved, find_dangerous_flags, ApprovalResult
import audit_log


@dataclass(frozen=True)
class Decision:
    permission: str  # "allow" | "deny" | "ask"
    reason: str


def _find_engagement_dir(cwd: str, env: dict) -> Path | None:
    client = env.get("REDTEAM_CLIENT")
    if client:
        root = env.get("REDTEAM_ROOT") or cwd
        candidate = Path(root) / "engagements" / client
        if (candidate / "scope.yaml").is_file():
            return candidate
    path = Path(cwd).resolve()
    for parent in [path, *path.parents]:
        if parent.parent.name == "engagements" and (parent / "scope.yaml").is_file():
            return parent
    return None


def _summary_category(invocations) -> str | None:
    cats = [classify(inv).value for inv in invocations]
    if "intrusive" in cats:
        return "intrusive"
    if "active_light" in cats:
        return "active_light"
    if "passive" in cats:
        return "passive"
    return None


def decide(command: str, cwd: str, env: dict, now_iso: str | None = None) -> Decision:
    eng = _find_engagement_dir(cwd, env)
    if eng is None:
        return Decision("allow", "Pas d'engagement actif (cwd hors engagements/<X>/).")

    invocations = detect(command)
    if not invocations:
        return Decision("allow", "Commande non offensive (pas d'outil red-team détecté).")

    scope = load_scope(eng / "scope.yaml")
    now = datetime.fromisoformat(now_iso) if now_iso else datetime.now(timezone.utc)

    if not scope.window_open(now=now):
        return Decision(
            "deny",
            f"Fenêtre d'engagement fermée ({scope.window_start.isoformat()} → {scope.window_end.isoformat()}).",
        )

    for inv in invocations:
        cat = classify(inv)
        if cat is Category.PASSIVE:
            continue
        if not inv.targets:
            return Decision(
                "deny",
                f"Outil '{inv.tool}' actif sans cible explicite — refusé par prudence.",
            )
        for target in inv.targets:
            if is_recon_artifact_file(target, eng):
                continue
            res = scope.contains(target)
            if res is ScopeResult.UNKNOWN:
                return Decision(
                    "deny",
                    f"Cible '{target}' non vérifiable contre le scope (fail-closed).",
                )
            if res is ScopeResult.OUT:
                return Decision(
                    "deny",
                    f"Cible '{target}' hors scope pour le client '{scope.client}'.",
                )
        if cat is Category.INTRUSIVE:
            danger_flags = find_dangerous_flags(inv.tool, inv.flags)
            for target in inv.targets:
                if is_recon_artifact_file(target, eng):
                    continue
                result = is_approved(
                    scope, tool=inv.tool, target=target,
                    used_dangerous_flags=danger_flags, now=now,
                )
                if result is ApprovalResult.NOT_APPROVED:
                    return Decision(
                        "ask",
                        f"Action intrusive '{inv.tool}' sur {target} — confirmation requise.",
                    )
                if result is ApprovalResult.INSUFFICIENT_SCOPE:
                    return Decision(
                        "ask",
                        f"Flags dangereux {danger_flags} non couverts par l'approbation existante pour {target} — confirmation requise.",
                    )
    return Decision("allow", "Toutes les cibles sont in_scope et la fenêtre est ouverte.")


def _deny_response(reason: str) -> str:
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }})


def _log_decision(eng: Path, command: str, decision: Decision, invocations) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "phase": "pre",
        "cmd_sha256": hashlib.sha256(command.encode()).hexdigest(),
        "decision": decision.permission,
        "reason": decision.reason,
    }
    cat = _summary_category(invocations) if invocations else None
    if cat:
        record["category"] = cat
    if invocations:
        record["tool"] = ",".join(inv.tool for inv in invocations)
        targets = [t for inv in invocations for t in inv.targets]
        if targets:
            record["target"] = ",".join(targets)
    audit_log.append(eng, record)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(_deny_response("Hook payload non-JSON — fail-closed."))
        return 0

    tool_name = payload.get("tool_name", "")
    if tool_name != "Bash":
        return 0

    command = (payload.get("tool_input") or {}).get("command", "")
    cwd = payload.get("cwd", os.getcwd())
    env = dict(os.environ)

    decision = decide(command, cwd=cwd, env=env)

    eng = _find_engagement_dir(cwd, env)
    if eng is not None:
        try:
            invocations = detect(command)
            _log_decision(eng, command, decision, invocations)
        except audit_log.AuditChainCorrupted as e:
            print(_deny_response(f"Audit log corrompu, action refusée : {e}"))
            return 0
        except OSError as e:
            print(_deny_response(f"Audit log écriture impossible : {e}"))
            return 0

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision.permission,
            "permissionDecisionReason": decision.reason,
        }
    }
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
