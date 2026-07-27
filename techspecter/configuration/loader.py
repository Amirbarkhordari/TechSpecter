"""Configuration file loading utilities."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from techspecter.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


def load_config_file(path: Path | str) -> dict[str, Any]:
    """Load a configuration file from YAML or JSON."""
    file_path = Path(path)
    if not file_path.is_file():
        msg = f"Configuration file not found: {file_path}"
        raise ConfigurationError(msg)

    content = file_path.read_text(encoding="utf-8")
    suffix = file_path.suffix.lower()

    try:
        if suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(content)
        elif suffix == ".json":
            data = json.loads(content)
        else:
            msg = f"Unsupported configuration format: {suffix}"
            raise ConfigurationError(msg)
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        msg = f"Invalid configuration file {file_path}: {exc}"
        raise ConfigurationError(msg) from exc

    if data is None:
        return {}
    if not isinstance(data, dict):
        msg = f"Configuration file must contain a mapping: {file_path}"
        raise ConfigurationError(msg)

    logger.info("Loaded configuration from %s", file_path)
    return data


def export_config_file(config: dict[str, Any], path: Path | str, *, fmt: str | None = None) -> str:
    """Export configuration to YAML or JSON."""
    file_path = Path(path)
    export_format = fmt or file_path.suffix.lower().lstrip(".")
    if export_format in {"yaml", "yml"}:
        content = yaml.safe_dump(config, sort_keys=False)
    elif export_format == "json":
        content = json.dumps(config, indent=2)
    else:
        msg = f"Unsupported export format: {export_format}"
        raise ConfigurationError(msg)

    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")
    logger.info("Exported configuration to %s", file_path)
    return content
