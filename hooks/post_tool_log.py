#!/usr/bin/env python3
"""Hook PostToolUse — append du résultat d'exécution dans audit.jsonl."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import audit_log


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


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    if payload.get("tool_name") != "Bash":
        return 0

    cmd = (payload.get("tool_input") or {}).get("command", "")
    cwd = payload.get("cwd", os.getcwd())
    env = dict(os.environ)

    eng = _find_engagement_dir(cwd, env)
    if eng is None:
        return 0

    cmd_sha = hashlib.sha256(cmd.encode()).hexdigest()
    pre = audit_log.find_last_pre(eng, cmd_sha)
    now = datetime.now(timezone.utc)
    duration_s = None
    if pre and isinstance(pre.get("ts"), str):
        try:
            ts_pre = datetime.fromisoformat(pre["ts"])
            duration_s = (now - ts_pre).total_seconds()
        except ValueError:
            duration_s = None

    tool_response = payload.get("tool_response") or {}
    stderr = tool_response.get("stderr") or ""
    record = {
        "ts": now.isoformat(),
        "phase": "post",
        "cmd_sha256": cmd_sha,
        "exit_code": tool_response.get("exit_code"),
        "duration_s": duration_s,
        "stderr_tail": stderr[-200:],
        "pre_missing": pre is None,
    }
    try:
        audit_log.append(eng, record)
    except (audit_log.AuditChainCorrupted, OSError):
        # PostToolUse ne doit pas bloquer : si le log est cassé, on
        # tait silencieusement (la PreToolUse aurait déjà fail-closed).
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
