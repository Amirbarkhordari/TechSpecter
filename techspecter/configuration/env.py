"""Environment variable configuration mapping."""

from __future__ import annotations

import os
from typing import Any

ENV_PREFIX = "TECHSPECTER_"


def _env_bool(key: str, default: bool = False) -> bool:
    """Parse a boolean environment variable."""
    value = os.environ.get(key)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(key: str, default: float) -> float:
    """Parse a float environment variable."""
    value = os.environ.get(key)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _env_int(key: str, default: int) -> int:
    """Parse an integer environment variable."""
    value = os.environ.get(key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def load_env_overrides() -> dict[str, Any]:
    """Load configuration overrides from environment variables."""
    overrides: dict[str, Any] = {}

    downloader: dict[str, Any] = {}
    if os.environ.get(f"{ENV_PREFIX}REQUEST_TIMEOUT"):
        downloader["request_timeout"] = _env_float(f"{ENV_PREFIX}REQUEST_TIMEOUT", 30.0)
    if os.environ.get(f"{ENV_PREFIX}MAX_RETRIES"):
        downloader["max_retries"] = _env_int(f"{ENV_PREFIX}MAX_RETRIES", 3)
    if os.environ.get(f"{ENV_PREFIX}MAX_CONCURRENCY"):
        downloader["max_concurrency"] = _env_int(f"{ENV_PREFIX}MAX_CONCURRENCY", 10)
    if os.environ.get(f"{ENV_PREFIX}USER_AGENT"):
        downloader["user_agent"] = os.environ[f"{ENV_PREFIX}USER_AGENT"]
    if os.environ.get(f"{ENV_PREFIX}MAX_RESPONSE_SIZE"):
        downloader["max_response_size"] = _env_int(f"{ENV_PREFIX}MAX_RESPONSE_SIZE", 10_485_760)
    if downloader:
        overrides["downloader"] = downloader

    logging_cfg: dict[str, Any] = {}
    if _env_bool(f"{ENV_PREFIX}DEBUG"):
        logging_cfg["debug"] = True
    if os.environ.get(f"{ENV_PREFIX}LOG_LEVEL"):
        logging_cfg["level"] = os.environ[f"{ENV_PREFIX}LOG_LEVEL"]
    elif logging_cfg.get("debug"):
        logging_cfg["level"] = "DEBUG"
    if os.environ.get(f"{ENV_PREFIX}LOG_FILE"):
        logging_cfg["file"] = True
        logging_cfg["file_path"] = os.environ[f"{ENV_PREFIX}LOG_FILE"]
    if _env_bool(f"{ENV_PREFIX}STRUCTURED_LOGGING"):
        logging_cfg["structured"] = True
    if logging_cfg:
        overrides["logging"] = logging_cfg

    analysis: dict[str, Any] = {}
    if os.environ.get(f"{ENV_PREFIX}MIN_CONFIDENCE"):
        analysis["min_confidence"] = _env_float(f"{ENV_PREFIX}MIN_CONFIDENCE", 0.0)
    if os.environ.get(f"{ENV_PREFIX}DISABLED_ANALYZERS"):
        analysis["disabled_analyzers"] = [
            item.strip()
            for item in os.environ[f"{ENV_PREFIX}DISABLED_ANALYZERS"].split(",")
            if item.strip()
        ]
    if os.environ.get(f"{ENV_PREFIX}ENABLED_ANALYZERS"):
        analysis["enabled_analyzers"] = [
            item.strip()
            for item in os.environ[f"{ENV_PREFIX}ENABLED_ANALYZERS"].split(",")
            if item.strip()
        ]
    if analysis:
        overrides["analysis"] = analysis

    reporting: dict[str, Any] = {}
    if os.environ.get(f"{ENV_PREFIX}REPORT_OUTPUT_DIR"):
        reporting["output_directory"] = os.environ[f"{ENV_PREFIX}REPORT_OUTPUT_DIR"]
    if os.environ.get(f"{ENV_PREFIX}REPORT_THEME"):
        reporting["theme"] = os.environ[f"{ENV_PREFIX}REPORT_THEME"]
    if reporting:
        overrides["reporting"] = reporting

    return overrides
