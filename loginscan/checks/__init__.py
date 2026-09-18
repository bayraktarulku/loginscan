"""Check modules. Each exposes run(client, cfg) -> List[Finding]."""
from . import cookies, enumeration, headers, ratelimit, session, sqli

# enumeration runs before sqli so sqli's many failed logins don't trip the
# target's rate limiter and pollute the enumeration measurement.
ALL_CHECKS = [headers, enumeration, sqli, cookies, session, ratelimit]

__all__ = ["ALL_CHECKS", "sqli", "enumeration", "ratelimit", "cookies", "session", "headers"]
