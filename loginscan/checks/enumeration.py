"""User enumeration detection: does the server treat existing vs unknown users differently?"""
from __future__ import annotations

from typing import List

from ..http import HttpClient
from ..models import Finding, ScanConfig, Severity, Status
from .base import random_username, submit_login

CHECK = "enumeration"

LEN_DIFF_RATIO = 0.15
TIME_DIFF_SECONDS = 0.5


def _norm_body(text: str) -> str:
    return " ".join(text.split())[:400].lower()


def run(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    wrong_pw = "wrong-Password-123"
    r_absent = submit_login(client, cfg, random_username("ghost"), wrong_pw)

    if not cfg.known_username:
        r_absent2 = submit_login(client, cfg, random_username("ghost2"), wrong_pw)
        consistent = _norm_body(r_absent.body) == _norm_body(r_absent2.body)
        return [Finding(
            check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
            title="Enumeration test limited (no known_username)",
            detail=("Provide a username that really exists (password not needed) for a full test. "
                    + ("Two unknown-user responses were consistent."
                       if consistent else "Two unknown-user responses differed, which is suspicious.")),
            remediation="Re-run with --user / known_username.",
        )]

    r_present = submit_login(client, cfg, cfg.known_username, wrong_pw)

    if 429 in (r_present.status, r_absent.status):
        return [Finding(
            check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
            title="Enumeration test unreliable due to rate limiting",
            detail="One request returned HTTP 429, so the responses cannot be compared fairly.",
            remediation="Re-run with a higher --delay or after the rate-limit window resets.",
            evidence={"http": f"{r_present.status} vs {r_absent.status}"},
        )]

    body_diff = _norm_body(r_present.body) != _norm_body(r_absent.body)
    len_a, len_b = len(r_present.body), len(r_absent.body)
    len_diff = abs(len_a - len_b) / max(len_a, len_b, 1) > LEN_DIFF_RATIO
    status_diff = r_present.status != r_absent.status
    time_diff = abs(r_present.elapsed - r_absent.elapsed) > TIME_DIFF_SECONDS

    if body_diff or len_diff or status_diff:
        return [Finding(
            check=CHECK, status=Status.VULNERABLE, severity=Severity.MEDIUM,
            title="User enumeration possible",
            detail="The server answers existing and unknown users differently; valid usernames leak.",
            remediation="Return the same generic message and HTTP status in both cases.",
            evidence={"body_differs": body_diff, "length": f"{len_a} vs {len_b}",
                      "http": f"{r_present.status} vs {r_absent.status}"},
        )]
    if time_diff:
        return [Finding(
            check=CHECK, status=Status.WARNING, severity=Severity.LOW,
            title="Timing difference (possible enumeration)",
            detail="Bodies match but response times differ, hinting password hashing runs only for real users.",
            remediation="Run a dummy hash verification for unknown users to equalize timing.",
            evidence={"time": f"{r_present.elapsed:.3f}s vs {r_absent.elapsed:.3f}s"},
        )]
    return [Finding(
        check=CHECK, status=Status.OK, severity=Severity.INFO,
        title="Responses consistent against enumeration",
        detail="Existing and unknown users were indistinguishable.",
    )]
