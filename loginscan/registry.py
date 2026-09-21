"""Check registry: built-in checks plus third-party plugins.

A check is any object exposing `CHECK` (str name) and `run(client, cfg) -> [Finding]`.
Plugins register via the `loginscan.checks` entry-point group; a plain function is
wrapped, using its entry-point name as the check name.
"""
from __future__ import annotations

import importlib.metadata as _md
from typing import Any

from .checks import ALL_CHECKS

ENTRY_POINT_GROUP = "loginscan.checks"


class _FunctionCheck:
    def __init__(self, name, func):
        self.CHECK = name
        self._func = func

    def run(self, client, cfg):
        return self._func(client, cfg)


def _normalize(name, obj):
    if hasattr(obj, "run") and hasattr(obj, "CHECK"):
        return obj
    if callable(obj):
        return _FunctionCheck(name, obj)
    return None


def plugin_checks() -> list[Any]:
    eps: Any
    try:
        eps = _md.entry_points(group=ENTRY_POINT_GROUP)  # type: ignore[call-arg]
    except TypeError:  # Python 3.9 API
        eps = _md.entry_points().get(ENTRY_POINT_GROUP, [])
    out = []
    for ep in eps:
        try:
            check = _normalize(ep.name, ep.load())
        except Exception:  # noqa: BLE001 - a bad plugin must not break scanning
            check = None
        if check is not None:
            out.append(check)
    return out


def all_checks() -> list[Any]:
    """Built-in + plugin checks, ordered by each check's declared ORDER.

    ORDER (default 100) expresses run-order constraints as data, e.g. enumeration
    (70) runs before sqli (80) so sqli's failed logins don't trip the rate limiter,
    and ratelimit (200) runs last. Plugins slot in by their own ORDER.
    """
    checks: list[Any] = list(ALL_CHECKS)
    seen = {getattr(c, "CHECK", None) for c in checks}
    for c in plugin_checks():
        if getattr(c, "CHECK", None) not in seen:
            checks.append(c)
            seen.add(c.CHECK)
    return sorted(checks, key=lambda c: getattr(c, "ORDER", 100))


def select(checks: list[Any], only: list[str] | None = None,
           skip: list[str] | None = None) -> list[Any]:
    result = checks
    if only:
        wanted = set(only)
        result = [c for c in result if getattr(c, "CHECK", None) in wanted]
    if skip:
        unwanted = set(skip)
        result = [c for c in result if getattr(c, "CHECK", None) not in unwanted]
    return result


def check_names(checks: list[Any] | None = None) -> list[str]:
    return [getattr(c, "CHECK", "?") for c in (checks if checks is not None else all_checks())]
