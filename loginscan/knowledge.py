"""Static knowledge: maps each check to CWE and OWASP Top 10 (2021) references."""
from __future__ import annotations

CHECK_META: dict[str, dict[str, str]] = {
    "sqli": {"cwe": "CWE-89", "owasp": "A03:2021 Injection"},
    "enumeration": {"cwe": "CWE-204", "owasp": "A07:2021 Identification and Authentication Failures"},
    "ratelimit": {"cwe": "CWE-307", "owasp": "A07:2021 Identification and Authentication Failures"},
    "cookies": {"cwe": "CWE-1004", "owasp": "A05:2021 Security Misconfiguration"},
    "session": {"cwe": "CWE-330", "owasp": "A07:2021 Identification and Authentication Failures"},
    "session_fixation": {"cwe": "CWE-384", "owasp": "A07:2021 Identification and Authentication Failures"},
    "csrf": {"cwe": "CWE-352", "owasp": "A01:2021 Broken Access Control"},
    "jwt": {"cwe": "CWE-347", "owasp": "A02:2021 Cryptographic Failures"},
    "open_redirect": {"cwe": "CWE-601", "owasp": "A01:2021 Broken Access Control"},
    "verb": {"cwe": "CWE-650", "owasp": "A05:2021 Security Misconfiguration"},
    "cors": {"cwe": "CWE-942", "owasp": "A05:2021 Security Misconfiguration"},
    "cache": {"cwe": "CWE-525", "owasp": "A05:2021 Security Misconfiguration"},
    "headers": {"cwe": "CWE-693", "owasp": "A05:2021 Security Misconfiguration"},
}


def meta_for(check: str) -> dict[str, str]:
    return CHECK_META.get(check, {})
