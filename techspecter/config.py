"""Application configuration and settings management."""

from __future__ import annotations

import os
from dataclasses import dataclass

from techspecter.configuration.defaults import DEFAULT_USER_AGENT
from techspecter.configuration.env import ENV_PREFIX
from techspecter.configuration.manager import get_configuration_manager

__all__ = ["DEFAULT_USER_AGENT", "ENV_PREFIX", "Settings", "get_settings"]


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
    version: str = "1.0.0rc1"
    debug: bool = False
    user_agent: str = DEFAULT_USER_AGENT
    request_timeout: float = 30.0
    max_retries: int = 3
    max_concurrency: int = 10
    log_level: str = "INFO"


def get_settings() -> Settings:
    """Load application settings from the centralized configuration manager.

    Returns:
        A ``Settings`` instance derived from the active configuration.
    """
    from techspecter import __version__

    config = get_configuration_manager().config
    return Settings(
        app_name=os.environ.get(f"{ENV_PREFIX}APP_NAME", "TechSpecter"),
        version=__version__,
        debug=config.logging.debug,
        user_agent=config.downloader.user_agent,
        request_timeout=config.downloader.request_timeout,
        max_retries=config.downloader.max_retries,
        max_concurrency=config.downloader.max_concurrency,
        log_level=config.logging.level,
    )
