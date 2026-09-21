"""Logging configuration for the CLI (-v/-vv/--quiet)."""
from __future__ import annotations

import logging
import sys


def configure_logging(verbosity: int = 0, quiet: bool = False) -> None:
    if quiet:
        level = logging.ERROR
    elif verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger("loginscan")
    root.handlers[:] = [handler]
    root.setLevel(level)
    root.propagate = False
