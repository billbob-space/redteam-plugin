"""Append JSONL hash-chaîné pour audit trail des engagements.

Hypothèses :
- Le hook Claude Code est sérialisé (une commande à la fois), donc pas de flock.
- Lignes JSON < 4096 octets : write append atomique sur Linux.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ZERO_HASH = "0" * 64
AUDIT_FILENAME = "audit.jsonl"


class AuditChainCorrupted(Exception):
    """Levé quand la dernière ligne du JSONL est inexploitable."""


def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def _compute_hash(record_without_hash: dict, prev_hash: str) -> str:
    payload = _canonical(record_without_hash)
    return hashlib.sha256((prev_hash + payload).encode()).hexdigest()


def _read_last_hash(path: Path) -> str:
    if not path.exists() or path.stat().st_size == 0:
        return ZERO_HASH
    size = path.stat().st_size
    window = 4096
    max_window = 1024 * 1024  # 1 MB cap, beyond that read everything
    with open(path, "rb") as f:
        while True:
            seek_to = max(0, size - window)
            f.seek(seek_to)
            tail = f.read().decode("utf-8", errors="replace")
            if seek_to == 0 or "\n" in tail[:-1]:  # tail[:-1] to ignore trailing \n
                break
            if window >= max_window:
                # Give up trying to find a newline — read the whole file.
                f.seek(0)
                tail = f.read().decode("utf-8", errors="replace")
                break
            window *= 2
    lines = [l for l in tail.splitlines() if l.strip()]
    if not lines:
        return ZERO_HASH
    try:
        last = json.loads(lines[-1])
    except json.JSONDecodeError as e:
        raise AuditChainCorrupted(f"dernière ligne non-JSON : {e}") from e
    h = last.get("hash")
    if not isinstance(h, str) or len(h) != 64:
        raise AuditChainCorrupted("dernière ligne sans hash valide")
    return h


def append(engagement_dir: Path, record: dict) -> None:
    if "ts" not in record:
        raise ValueError("record manque le champ 'ts'")
    path = Path(engagement_dir) / AUDIT_FILENAME
    prev = _read_last_hash(path)
    rec_with_prev = {**record, "prev_hash": prev}
    rec_with_prev["hash"] = _compute_hash(rec_with_prev, prev)
    payload = json.dumps(rec_with_prev) + "\n"
    # Garantit qu'on commence sur une nouvelle ligne même si le précédent
    # write a été tronqué (pas de \n final).
    if path.exists() and path.stat().st_size > 0:
        with open(path, "rb") as r:
            r.seek(-1, 2)
            if r.read(1) != b"\n":
                payload = "\n" + payload
    with open(path, "a") as f:
        f.write(payload)


def verify_chain(path: Path) -> tuple[bool, int]:
    """Rejoue la chaîne. Retourne (ok, n_lignes_vérifiées_avant_échec)."""
    path = Path(path)
    if not path.exists():
        return (True, 0)
    prev = ZERO_HASH
    n = 0
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return (False, n)
            stored = rec.get("hash")
            stored_prev = rec.get("prev_hash")
            rec_no_hash = {k: v for k, v in rec.items() if k != "hash"}
            expected = _compute_hash(rec_no_hash, stored_prev)
            if expected != stored or stored_prev != prev:
                return (False, n)
            prev = stored
            n += 1
    return (True, n)


def find_last_pre(engagement_dir: Path, cmd_sha256: str) -> dict | None:
    path = Path(engagement_dir) / AUDIT_FILENAME
    if not path.exists():
        return None
    match = None
    with open(path) as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("phase") == "pre" and rec.get("cmd_sha256") == cmd_sha256:
                match = rec
    return match
