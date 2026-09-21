"""Check modules. Each exposes run(ctx, cfg) -> List[Finding]."""
from . import (
    cache,
    cookies,
    cors,
    csrf,
    enumeration,
    headers,
    jwt,
    open_redirect,
    ratelimit,
    session,
    session_fixation,
    sqli,
    verb,
)

# The set of built-in checks. Run order is decided by each check's ORDER
# constant (see registry.all_checks), not by the position in this list.
ALL_CHECKS = [headers, csrf, cors, cache, verb, open_redirect, enumeration,
              sqli, cookies, session, session_fixation, jwt, ratelimit]

__all__ = ["ALL_CHECKS", "sqli", "enumeration", "ratelimit", "cookies", "session",
           "session_fixation", "headers", "csrf", "jwt", "open_redirect", "verb",
           "cors", "cache"]
