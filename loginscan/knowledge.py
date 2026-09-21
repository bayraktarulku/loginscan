"""CWE / OWASP references, sourced from each check (single source of truth).

Every check module may declare `CWE` and `OWASP` constants; this module collects
them so reports (text/JSON/HTML/SARIF) can annotate findings. Plugins that declare
the same constants are picked up too.
"""
from __future__ import annotations

from .checks import ALL_CHECKS


def _collect() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for mod in ALL_CHECKS:
        name = getattr(mod, "CHECK", None)
        if not name:
            continue
        entry: dict[str, str] = {}
        if getattr(mod, "CWE", None):
            entry["cwe"] = mod.CWE
        if getattr(mod, "OWASP", None):
            entry["owasp"] = mod.OWASP
        out[name] = entry
    return out


CHECK_META = _collect()


def meta_for(check: str) -> dict[str, str]:
    if check in CHECK_META:
        return CHECK_META[check]
    # Fall back to a plugin's own constants if it isn't a built-in.
    from .registry import all_checks
    for mod in all_checks():
        if getattr(mod, "CHECK", None) == check:
            entry = {}
            if getattr(mod, "CWE", None):
                entry["cwe"] = mod.CWE
            if getattr(mod, "OWASP", None):
                entry["owasp"] = mod.OWASP
            return entry
    return {}
