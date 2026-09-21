"""Session token strength check: predictable, short, sequential or low-entropy tokens."""
from __future__ import annotations

import math
from collections import Counter

from ..context import CheckContext
from ..models import Finding, ScanConfig, Severity, Status

CHECK = "session"
ORDER = 100

MIN_TOKEN_LEN = 16


def _entropy_bits(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    per_char = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return per_char * n


def run(ctx: CheckContext, cfg: ScanConfig) -> list[Finding]:
    tokens = [v for _, v in ctx.session_tokens()]
    if not tokens:
        return [Finding(
            check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
            title="No session token observed",
            detail="Server issued no session token here (usually set only on success). Skipped.",
        )]

    uniq = list(dict.fromkeys(tokens))
    sample = uniq[0]

    numeric = [t for t in uniq if t.isdigit()]
    if len(numeric) >= 2:
        nums = sorted(int(t) for t in numeric)
        if all(b - a == 1 for a, b in zip(nums, nums[1:])):
            return [Finding(
                check=CHECK, status=Status.VULNERABLE, severity=Severity.HIGH,
                title="Session token is sequential and predictable",
                detail=f"Tokens are consecutive numbers: {nums}. An attacker can guess other sessions.",
                remediation="Use cryptographically random tokens (e.g. secrets.token_urlsafe(32)); never counters.",
                evidence={"samples": nums[:5]},
            )]

    reasons = []
    if len(sample) < MIN_TOKEN_LEN:
        reasons.append(f"too short ({len(sample)} chars)")
    if sample.isdigit():
        reasons.append("all numeric")
    entropy = _entropy_bits(sample)
    if entropy < 64:
        reasons.append(f"low entropy (~{entropy:.0f} bits)")

    if reasons:
        return [Finding(
            check=CHECK, status=Status.WARNING, severity=Severity.MEDIUM,
            title="Session token looks weak",
            detail="Weak on: " + ", ".join(reasons) + ".",
            remediation="Use a cryptographically random token with at least 128 bits of entropy.",
            evidence={"sample_len": len(sample), "entropy_bits": round(entropy)},
        )]
    return [Finding(
        check=CHECK, status=Status.OK, severity=Severity.INFO,
        title="Session token looks reasonable",
        detail=f"Length {len(sample)}, ~{entropy:.0f} bits of entropy.",
    )]
