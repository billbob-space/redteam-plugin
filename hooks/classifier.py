"""Classe une invocation d'outil en passif / actif-léger / intrusif."""
from __future__ import annotations

from enum import Enum

from parser import ToolInvocation


class Category(Enum):
    PASSIVE = "passive"
    ACTIVE_LIGHT = "active_light"
    INTRUSIVE = "intrusive"


PASSIVE_TOOLS = {"subfinder", "assetfinder", "dnsx", "tlsx", "gau", "waybackurls"}
ACTIVE_LIGHT_TOOLS = {"katana", "feroxbuster", "ffuf"}
INTRUSIVE_TOOLS = {"sqlmap", "commix", "dalfox", "arjun"}

ACTIVE_FLAGS_FOR_PASSIVE = {
    "httpx": {"-fr", "--follow-redirects", "-fetch", "-fetch-redirect-chain"},
}


def _flag_value(flags: list[str], names: set[str]) -> str | None:
    for i, f in enumerate(flags):
        if f in names and i + 1 < len(flags):
            return flags[i + 1]
    return None


def _max_threads(flags: list[str]) -> int | None:
    val = _flag_value(flags, {"-t", "--threads", "-c", "--concurrency"})
    if val is None:
        return None
    try:
        return int(val)
    except ValueError:
        return None


def classify(inv: ToolInvocation) -> Category:
    tool, flags = inv.tool, inv.flags

    if tool == "httpx":
        if any(f in ACTIVE_FLAGS_FOR_PASSIVE["httpx"] for f in flags):
            return Category.ACTIVE_LIGHT
        return Category.PASSIVE

    if tool == "nuclei":
        sev = _flag_value(flags, {"-severity", "-s", "--severity"}) or ""
        if any(level in sev.lower() for level in ("critical", "high")):
            return Category.INTRUSIVE
        return Category.ACTIVE_LIGHT

    if tool in PASSIVE_TOOLS:
        return Category.PASSIVE

    if tool in INTRUSIVE_TOOLS:
        return Category.INTRUSIVE

    if tool in ACTIVE_LIGHT_TOOLS:
        threads = _max_threads(flags)
        if threads is not None and threads > 20:
            return Category.INTRUSIVE
        return Category.ACTIVE_LIGHT

    return Category.ACTIVE_LIGHT
