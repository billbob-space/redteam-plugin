"""Détection robuste d'invocations d'outils dans une commande Bash.

Combine :
- unwrap_command : récursion sur bash -c / sh -c / eval pour exposer le
  vrai payload au parser existant.
- scan_offensive_tokens : filet de sécurité quand le parser ne trouve
  rien — scanne tous les tokens à la recherche d'un nom d'outil connu.
- detect : API publique combinée.
"""
from __future__ import annotations

import re
import shlex

from parser import KNOWN_TOOLS, ToolInvocation, parse_command

MAX_UNWRAP_DEPTH = 3
WRAPPER_TOOLS = {"bash", "sh", "eval"}


def _payload_for_wrapper(tokens: list[str]) -> str | None:
    """Extrait le payload d'un wrapper. Retourne None si introuvable."""
    if not tokens:
        return None
    head = tokens[0]
    if head not in WRAPPER_TOOLS:
        return None
    # eval: prend tous les args et les joint
    if head == "eval":
        rest = tokens[1:]
        return " ".join(rest) if rest else None
    # bash/sh -c "..."
    for i, t in enumerate(tokens[1:], start=1):
        if t == "-c" and i + 1 < len(tokens):
            return tokens[i + 1]
    return None


def unwrap_command(cmd: str, depth: int = 0) -> list[str]:
    """Retourne la liste des sous-commandes à analyser, en dépliant les wrappers."""
    if depth >= MAX_UNWRAP_DEPTH:
        return [cmd]
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return [cmd]
    inner = _payload_for_wrapper(tokens)
    if inner is None:
        return [cmd]
    return unwrap_command(inner, depth + 1)


_TOOL_RE_CACHE: re.Pattern | None = None


def _build_tool_regex() -> re.Pattern:
    """Compile une regex qui matche tout nom d'outil de KNOWN_TOOLS,
    indépendamment des espaces / quotes / paths qui l'entourent.

    Limites alphanumériques + underscore + tiret : un tool ne matche pas
    s'il fait partie d'un identifiant plus long (ex: 'xsqlmap', 'sqlmap_v2').
    Le slash et le point sont autorisés en bordure pour matcher des paths
    type '/usr/local/bin/sqlmap'.
    """
    global _TOOL_RE_CACHE
    if _TOOL_RE_CACHE is None:
        tools = sorted(KNOWN_TOOLS, key=len, reverse=True)
        alt = "|".join(re.escape(t) for t in tools)
        _TOOL_RE_CACHE = re.compile(
            rf"(?<![A-Za-z0-9_-])({alt})(?![A-Za-z0-9_-])"
        )
    return _TOOL_RE_CACHE


def scan_offensive_tokens(cmd: str) -> list[str]:
    """Scanne le cmd brut à la recherche d'outils connus.

    Utilise une regex avec word-boundaries permissives (slash, point et
    quotes en bordure OK ; underscore et tiret bloquent le match) pour
    couvrir :
      - quotes posix qui aplatissent en un seul token shlex
      - paths absolus '/usr/local/bin/sqlmap'
      - bypass exotiques (xargs, substitution, timeout, pipe-into-bash).

    Faux positifs assumés (echo nuclei → DENY).
    """
    seen: list[str] = []
    for m in _build_tool_regex().finditer(cmd):
        t = m.group(1)
        if t not in seen:
            seen.append(t)
    return seen


def detect(cmd: str) -> list[ToolInvocation]:
    """Pipeline complet : unwrap → parse → fallback lexical."""
    invs: list[ToolInvocation] = []
    for sub in unwrap_command(cmd):
        invs.extend(parse_command(sub))
    if invs:
        return invs
    return [ToolInvocation(tool=t, targets=[], flags=[])
            for t in scan_offensive_tokens(cmd)]
