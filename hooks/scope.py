"""Modèle de scope : charge scope.yaml, teste l'appartenance d'une cible."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse

import yaml


class ScopeResult(Enum):
    IN = "in"
    OUT = "out"
    UNKNOWN = "unknown"


def _matches_domain(target_host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return target_host == pattern[2:] or target_host.endswith(suffix)
    return target_host == pattern


def _target_to_host_or_ip(target: str) -> tuple[str | None, str | None]:
    if target.startswith("@file:"):
        return (None, None)
    if target.startswith(("http://", "https://", "ws://", "wss://")):
        parsed = urlparse(target)
        if parsed.hostname:
            target = parsed.hostname
    try:
        ip = ipaddress.ip_address(target)
        return (None, str(ip))
    except ValueError:
        pass
    if re.match(r"^[A-Za-z0-9._-]+$", target):
        return (target.lower(), None)
    return (None, None)


@dataclass(frozen=True)
class Scope:
    client: str
    window_start: datetime
    window_end: datetime
    in_domains: list[str] = field(default_factory=list)
    in_cidrs: list[str] = field(default_factory=list)
    out_domains: list[str] = field(default_factory=list)
    out_cidrs: list[str] = field(default_factory=list)
    constraints: dict = field(default_factory=dict)
    intrusive_actions: list[dict] = field(default_factory=list)
    path: Path | None = None

    def _matches_any_domain(self, host: str, patterns: list[str]) -> bool:
        return any(_matches_domain(host, p) for p in patterns)

    def _matches_any_cidr(self, ip: str, cidrs: list[str]) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(c) for c in cidrs)

    def contains(self, target: str) -> ScopeResult:
        host, ip = _target_to_host_or_ip(target)
        if host is None and ip is None:
            return ScopeResult.UNKNOWN
        if host and self._matches_any_domain(host, self.out_domains):
            return ScopeResult.OUT
        if ip and self._matches_any_cidr(ip, self.out_cidrs):
            return ScopeResult.OUT
        if host and self._matches_any_domain(host, self.in_domains):
            return ScopeResult.IN
        if ip and self._matches_any_cidr(ip, self.in_cidrs):
            return ScopeResult.IN
        return ScopeResult.OUT

    def window_open(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return self.window_start <= now <= self.window_end


def _parse_dt(s) -> datetime:
    if isinstance(s, datetime):
        return s if s.tzinfo else s.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(s)


def load_scope(path: str | Path) -> Scope:
    path = Path(path)
    with open(path) as f:
        raw = yaml.safe_load(f)
    win = raw.get("window") or {}
    return Scope(
        client=raw.get("client", "unknown"),
        window_start=_parse_dt(win.get("start", "1970-01-01T00:00:00+00:00")),
        window_end=_parse_dt(win.get("end", "1970-01-01T00:00:00+00:00")),
        in_domains=list((raw.get("in_scope") or {}).get("domains") or []),
        in_cidrs=list((raw.get("in_scope") or {}).get("cidrs") or []),
        out_domains=list((raw.get("out_of_scope") or {}).get("domains") or []),
        out_cidrs=list((raw.get("out_of_scope") or {}).get("cidrs") or []),
        constraints=raw.get("constraints") or {},
        intrusive_actions=list(raw.get("intrusive_actions") or []),
        path=path,
    )


def is_recon_artifact_file(target: str, engagement_dir: Path) -> bool:
    """True si target est '@file:<chemin>' pointant un fichier sous engagement_dir/recon/.

    Resolve les paths avant comparaison pour bloquer '@file:.../recon/../../etc/passwd'.
    """
    if not target.startswith("@file:"):
        return False
    try:
        path = Path(target[6:]).resolve()
        recon_dir = (Path(engagement_dir) / "recon").resolve()
        path.relative_to(recon_dir)
    except (ValueError, OSError):
        return False
    return path.is_file()
