"""Application configuration and settings management."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

DEFAULT_USER_AGENT: Final[str] = (
    "TechSpecter/0.2.0 (+https://github.com/Amirbarkhordari/TechSpecter)"
)
ENV_PREFIX: Final[str] = "TECHSPECTER_"


def _env_bool(key: str, default: bool = False) -> bool:
    """Parse a boolean environment variable.

    Args:
        key: Environment variable name.
        default: Value returned when the variable is unset.

    Returns:
        Parsed boolean value.
    """
    value = os.environ.get(key)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(key: str, default: float) -> float:
    """Parse a float environment variable.

    Args:
        key: Environment variable name.
        default: Value returned when the variable is unset or invalid.

    Returns:
        Parsed float value.
    """
    value = os.environ.get(key)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _env_int(key: str, default: int) -> int:
    """Parse an integer environment variable.

    Args:
        key: Environment variable name.
        default: Value returned when the variable is unset or invalid.

    Returns:
        Parsed integer value.
    """
    value = os.environ.get(key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


@dataclass(frozen=True, slots=True)
class Settings:
    """Runtime configuration for TechSpecter.

    Attributes:
        app_name: Human-readable application name.
        version: Current package version string.
        debug: Enable verbose debug output when ``True``.
        user_agent: Default HTTP User-Agent header value.
        request_timeout: Default HTTP request timeout in seconds.
        max_retries: Maximum number of HTTP retry attempts.
        max_concurrency: Maximum concurrent download operations.
        log_level: Logging level name (e.g. ``INFO``, ``DEBUG``).
    """

    app_name: str = "TechSpecter"
    version: str = "0.2.0"
    debug: bool = False
    user_agent: str = DEFAULT_USER_AGENT
    request_timeout: float = 30.0
    max_retries: int = 3
    max_concurrency: int = 10
    log_level: str = "INFO"


def get_settings() -> Settings:
    """Load application settings from environment variables.

    Environment variables use the ``TECHSPECTER_`` prefix (e.g.
    ``TECHSPECTER_DEBUG=true``).

    Returns:
        A ``Settings`` instance populated from the current environment.
    """
    return Settings(
        app_name=os.environ.get(f"{ENV_PREFIX}APP_NAME", "TechSpecter"),
        version=os.environ.get(f"{ENV_PREFIX}VERSION", "0.2.0"),
        debug=_env_bool(f"{ENV_PREFIX}DEBUG", False),
        user_agent=os.environ.get(f"{ENV_PREFIX}USER_AGENT", DEFAULT_USER_AGENT),
        request_timeout=_env_float(f"{ENV_PREFIX}REQUEST_TIMEOUT", 30.0),
        max_retries=_env_int(f"{ENV_PREFIX}MAX_RETRIES", 3),
        max_concurrency=_env_int(f"{ENV_PREFIX}MAX_CONCURRENCY", 10),
        log_level=os.environ.get(f"{ENV_PREFIX}LOG_LEVEL", "INFO"),
    )
