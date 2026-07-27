"""Logging configuration utilities."""

from __future__ import annotations

import logging
import sys
from typing import Final

DEFAULT_LOG_FORMAT: Final[str] = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DEFAULT_DATE_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S"
_NOISY_LOGGERS: Final[tuple[str, ...]] = ("httpx", "httpcore", "hpack")

_handler: logging.Handler | None = None


def configure_logging(level: str = "INFO") -> None:
    """Configure application logging exactly once per process.

    Logging is written to ``stderr`` so CLI test runners that capture or close
    ``stdout`` do not trigger handler I/O errors. Subsequent calls update the
    configured log level without adding duplicate handlers.

    Args:
        level: Logging level name (e.g. ``INFO``, ``DEBUG``, ``WARNING``).
    """
    global _handler

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()

    if _handler is None:
        _handler = logging.StreamHandler(sys.stderr)
        _handler.setFormatter(
            logging.Formatter(DEFAULT_LOG_FORMAT, datefmt=DEFAULT_DATE_FORMAT)
        )
        root.addHandler(_handler)

    root.setLevel(numeric_level)
    _handler.setLevel(numeric_level)

    for logger_name in _NOISY_LOGGERS:
        logging.getLogger(logger_name).setLevel(logging.WARNING)


def reset_logging() -> None:
    """Remove configured handlers.

    Intended for test isolation. Production code should not call this helper.
    """
    global _handler

    root = logging.getLogger()
    if _handler is not None:
        root.removeHandler(_handler)
        _handler.close()
        _handler = None


def get_logger(name: str) -> logging.Logger:
    """Return a named logger instance.

    Args:
        name: Logger name, typically ``__name__`` of the calling module.

    Returns:
        A configured ``logging.Logger`` instance.
    """
    return logging.getLogger(name)
