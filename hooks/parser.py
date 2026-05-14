"""Parse une commande Bash en liste d'invocations d'outils offensifs."""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

KNOWN_TOOLS = {
    "subfinder", "assetfinder", "dnsx", "httpx", "tlsx", "katana",
    "gau", "waybackurls", "nuclei", "ffuf", "feroxbuster", "dalfox",
    "sqlmap", "commix", "arjun",
}

TARGET_FLAGS = {"-u", "-target", "--target", "-d", "-domain", "--url", "-h", "--host"}
TARGET_FILE_FLAGS = {"-l", "-list", "--list", "-i", "--input"}
# Flags qui consomment la valeur suivante mais ne désignent PAS de cible
# (wordlists, threads, output, headers, etc.).
VALUE_FLAGS = {
    "-w", "--wordlist",
    "-t", "--threads",
    "-o", "--output",
    "-c", "--config",
    "-x", "--ext",
    "-mc", "-fc", "-ms", "-fs",
    "-H", "--header",
    "-r",
    "-data", "--data",
    "-rate", "-rate-limit", "--rate-limit",
    "-timeout", "--timeout",
}

PIPELINE_SEPARATORS = re.compile(r"\s*(?:\|\||&&|\||;)\s*")


@dataclass(frozen=True)
class ToolInvocation:
    tool: str
    targets: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)


def _looks_like_target(token: str) -> bool:
    if token.startswith(("http://", "https://", "ws://", "wss://")):
        return True
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$", token):
        return True
    if re.match(r"^[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+$", token):
        return True
    return False


def _parse_stage(tokens: list[str]) -> ToolInvocation | None:
    if not tokens:
        return None
    tool = tokens[0]
    if tool not in KNOWN_TOOLS:
        return None
    targets: list[str] = []
    flags: list[str] = []
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok in TARGET_FLAGS and i + 1 < len(tokens):
            targets.append(tokens[i + 1])
            flags.append(tok)
            i += 2
            continue
        if tok in TARGET_FILE_FLAGS and i + 1 < len(tokens):
            targets.append(f"@file:{tokens[i + 1]}")
            flags.append(tok)
            i += 2
            continue
        if tok in VALUE_FLAGS and i + 1 < len(tokens):
            flags.append(tok)
            flags.append(tokens[i + 1])
            i += 2
            continue
        if tok.startswith("-"):
            flags.append(tok)
        elif _looks_like_target(tok):
            if not any(t == tok for t in targets):
                targets.append(tok)
        i += 1
    return ToolInvocation(tool=tool, targets=targets, flags=flags)


def parse_command(command: str) -> list[ToolInvocation]:
    invocations: list[ToolInvocation] = []
    stages = PIPELINE_SEPARATORS.split(command)
    for stage in stages:
        stage = stage.strip()
        if not stage:
            continue
        try:
            tokens = shlex.split(stage)
        except ValueError:
            return []
        inv = _parse_stage(tokens)
        if inv is not None:
            invocations.append(inv)
    return invocations
