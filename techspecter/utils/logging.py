"""Logging configuration utilities."""

from __future__ import annotations

import logging
import sys
from typing import Final

DEFAULT_LOG_FORMAT: Final[str] = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DEFAULT_DATE_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S"


def configure_logging(level: str = "INFO") -> None:
    """Configure root logging for TechSpecter.

    Args:
        level: Logging level name (e.g. ``INFO``, ``DEBUG``, ``WARNING``).
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format=DEFAULT_LOG_FORMAT,
        datefmt=DEFAULT_DATE_FORMAT,
        stream=sys.stdout,
        force=True,
    )


def get_logger(name: str) -> logging.Logger:
    """Return a named logger instance.

    Args:
        name: Logger name, typically ``__name__`` of the calling module.

    Returns:
        A configured ``logging.Logger`` instance.
    """
    return logging.getLogger(name)
