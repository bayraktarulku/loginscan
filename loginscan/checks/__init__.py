"""Check modules. Each exposes run(ctx, cfg) -> List[Finding]."""
from . import (
    cache,
    cookies,
    cors,
    csrf,
    debug_leak,
    enumeration,
    headers,
    host_injection,
    jwt,
    open_redirect,
    ratelimit,
    ratelimit_bypass,
    session,
    session_fixation,
    spray,
    sqli,
    verb,
)

# The set of built-in checks. Run order is decided by each check's ORDER
# constant (see registry.all_checks), not by the position in this list.
ALL_CHECKS = [headers, csrf, cors, cache, verb, open_redirect, enumeration,
              sqli, cookies, session, session_fixation, jwt, spray, ratelimit,
              ratelimit_bypass, host_injection, debug_leak]

__all__ = ["ALL_CHECKS", "sqli", "enumeration", "ratelimit", "cookies", "session",
           "session_fixation", "headers", "csrf", "jwt", "open_redirect", "verb",
           "cors", "cache", "spray", "ratelimit_bypass", "host_injection", "debug_leak"]
