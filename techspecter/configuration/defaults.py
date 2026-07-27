"""Default configuration values."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from techspecter.configuration.models import TechSpecterConfig

try:
    _APP_VERSION = version("techspecter")
except PackageNotFoundError:
    _APP_VERSION = "0.7.0"

DEFAULT_USER_AGENT = f"TechSpecter/{_APP_VERSION} (+https://github.com/Amirbarkhordari/TechSpecter)"


def default_config() -> TechSpecterConfig:
    """Return the default TechSpecter configuration."""
    config = TechSpecterConfig()
    return config.model_copy(
        update={
            "downloader": config.downloader.model_copy(
                update={"user_agent": DEFAULT_USER_AGENT},
            ),
        },
    )
