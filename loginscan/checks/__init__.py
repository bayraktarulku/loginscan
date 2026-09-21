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

# enumeration runs before sqli so sqli's many failed logins don't trip the
# target's rate limiter and pollute the enumeration measurement. ratelimit is
# last because it is the most request-heavy.
ALL_CHECKS = [headers, csrf, cors, cache, verb, open_redirect, enumeration,
              sqli, cookies, session, session_fixation, jwt, ratelimit]

__all__ = ["ALL_CHECKS", "sqli", "enumeration", "ratelimit", "cookies", "session",
           "session_fixation", "headers", "csrf", "jwt", "open_redirect", "verb",
           "cors", "cache"]
