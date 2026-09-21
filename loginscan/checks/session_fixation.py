"""Session fixation check (stateful; needs YOUR OWN test account).

If the server keeps the same session identifier before and after login, an attacker
who fixes a victim's pre-auth session cookie keeps access once the victim logs in.
Runs only when a test username + password are supplied; uses the cookie jar.
"""
from __future__ import annotations

from ..context import CheckContext
from ..models import Finding, ScanConfig, Severity, Status
from .base import baseline_fail, looks_like_success, submit_login

CHECK = "session_fixation"
ORDER = 110


def _snapshot(ctx: CheckContext) -> dict[str, str]:
    snap: dict[str, str] = {}
    for name, value in ctx.session_tokens():
        snap[name] = value
    return snap


def run(ctx: CheckContext, cfg: ScanConfig) -> list[Finding]:
    if not (cfg.known_username and cfg.password):
        return [Finding(
            check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
            title="Session fixation test skipped",
            detail="Provide a test account (known_username + password) to run stateful checks.")]

    base = baseline_fail(ctx, cfg)  # reference for confirming a real login
    ctx.get(cfg.login_page_url or cfg.url)  # obtain any pre-auth session cookie
    pre = _snapshot(ctx)

    resp = submit_login(ctx, cfg, cfg.known_username, cfg.password)
    if not looks_like_success(resp, base, cfg):
        return [Finding(
            check=CHECK, status=Status.SKIPPED, severity=Severity.INFO,
            title="Could not confirm login with the test account",
            detail="The provided credentials did not produce a success-like response; check them.")]

    post = _snapshot(ctx)
    for name, pre_val in pre.items():
        if post.get(name) == pre_val:
            return [Finding(
                check=CHECK, status=Status.VULNERABLE, severity=Severity.HIGH,
                title="Session fixation: session id not rotated on login",
                detail=f"Cookie '{name}' kept the same value before and after authentication.",
                remediation="Issue a brand-new session identifier on every successful login.",
                evidence={"cookie": name})]

    if pre:
        return [Finding(
            check=CHECK, status=Status.OK, severity=Severity.INFO,
            title="Session id rotates on login",
            detail="The session identifier changed after authentication.")]
    return [Finding(
        check=CHECK, status=Status.OK, severity=Severity.INFO,
        title="No pre-auth session to fixate",
        detail="No session cookie was set before login.")]
