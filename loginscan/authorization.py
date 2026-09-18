"""Authorization gate. Only scan systems you own or are permitted to test."""
from __future__ import annotations

AUTHORIZATION_NOTICE = (
    "WARNING: loginscan must only be used against systems you own or have written\n"
    "permission to test. Unauthorized scanning is illegal and unethical. By scanning,\n"
    "you assert that you are authorized to test the target."
)


class NotAuthorized(Exception):
    pass


def ensure_authorized(authorized: bool) -> None:
    if not authorized:
        raise NotAuthorized(
            "Scan refused: authorization not confirmed.\n\n"
            + AUTHORIZATION_NOTICE
            + "\n\nPython API: Scanner(config, authorized=True)\n"
            "CLI:        add the --i-own-this flag."
        )
