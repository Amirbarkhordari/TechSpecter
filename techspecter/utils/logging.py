"""Logging configuration utilities."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Final

from techspecter.configuration.models import LoggingConfig

DEFAULT_LOG_FORMAT: Final[str] = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DEFAULT_DATE_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S"
_NOISY_LOGGERS: Final[tuple[str, ...]] = ("httpx", "httpcore", "hpack")

_handlers: list[logging.Handler] = []


class StructuredFormatter(logging.Formatter):
    """JSON structured log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as JSON."""
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(level: str = "INFO", config: LoggingConfig | None = None) -> None:
    """Configure application logging exactly once per process."""
    global _handlers

    logging_config = config or LoggingConfig(level=level)
    numeric_level = getattr(logging, logging_config.level.upper(), logging.INFO)
    if logging_config.debug:
        numeric_level = logging.DEBUG

    root = logging.getLogger()
    if not _handlers:
        if logging_config.console:
            console_handler = logging.StreamHandler(sys.stderr)
            if logging_config.structured:
                console_handler.setFormatter(StructuredFormatter())
            else:
                console_handler.setFormatter(
                    logging.Formatter(DEFAULT_LOG_FORMAT, datefmt=DEFAULT_DATE_FORMAT)
                )
            root.addHandler(console_handler)
            _handlers.append(console_handler)

        if logging_config.file and logging_config.file_path:
            file_handler = logging.FileHandler(logging_config.file_path, encoding="utf-8")
            if logging_config.structured:
                file_handler.setFormatter(StructuredFormatter())
            else:
                file_handler.setFormatter(
                    logging.Formatter(DEFAULT_LOG_FORMAT, datefmt=DEFAULT_DATE_FORMAT)
                )
            root.addHandler(file_handler)
            _handlers.append(file_handler)

    root.setLevel(numeric_level)
    for handler in _handlers:
        handler.setLevel(numeric_level)

    for logger_name in _NOISY_LOGGERS:
        logging.getLogger(logger_name).setLevel(logging.WARNING)


def reset_logging() -> None:
    """Remove configured handlers."""
    global _handlers

    root = logging.getLogger()
    for handler in _handlers:
        root.removeHandler(handler)
        handler.close()
    _handlers = []


def get_logger(name: str) -> logging.Logger:
    """Return a named logger instance."""
    return logging.getLogger(name)
