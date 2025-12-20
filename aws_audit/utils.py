from __future__ import annotations

import logging

_LOGGER: logging.Logger | None = None


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def log() -> logging.Logger:
    global _LOGGER
    if _LOGGER is None:
        _LOGGER = logging.getLogger("aws_audit")
    return _LOGGER
