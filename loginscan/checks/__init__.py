"""Check modules. Each exposes run(client, cfg) -> List[Finding]."""
from . import (cookies, csrf, enumeration, headers, jwt, open_redirect,
               ratelimit, session, sqli)

# enumeration runs before sqli so sqli's many failed logins don't trip the
# target's rate limiter and pollute the enumeration measurement.
ALL_CHECKS = [headers, csrf, open_redirect, enumeration, sqli, cookies,
              session, jwt, ratelimit]

__all__ = ["ALL_CHECKS", "sqli", "enumeration", "ratelimit", "cookies", "session",
           "headers", "csrf", "jwt", "open_redirect"]
