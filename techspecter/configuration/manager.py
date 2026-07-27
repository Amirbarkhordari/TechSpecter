"""Central configuration manager."""

from __future__ import annotations

import logging
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from techspecter.configuration.defaults import default_config
from techspecter.configuration.env import load_env_overrides
from techspecter.configuration.loader import export_config_file, load_config_file
from techspecter.configuration.merge import deep_merge
from techspecter.configuration.models import TechSpecterConfig
from techspecter.configuration.validator import ConfigurationValidator

logger = logging.getLogger(__name__)

_active_manager: ContextVar[ConfigurationManager | None] = ContextVar(
    "techspecter_configuration_manager",
    default=None,
)


@dataclass(slots=True)
class ConfigurationManager:
    """Load, merge, validate, and export TechSpecter configuration."""

    config: TechSpecterConfig = field(default_factory=default_config)
    validator: ConfigurationValidator = field(default_factory=ConfigurationValidator)
    _cli_overrides: dict[str, Any] = field(default_factory=dict, init=False)

    @classmethod
    def load(
        cls,
        *,
        config_path: Path | str | None = None,
        cli_overrides: dict[str, Any] | None = None,
        apply_env: bool = True,
    ) -> ConfigurationManager:
        """Build a configuration manager from defaults, file, env, and CLI layers."""
        manager = cls()
        data = manager.config.model_dump(mode="python")

        if config_path is not None:
            file_data = load_config_file(config_path)
            data = deep_merge(data, file_data)

        if apply_env:
            env_data = load_env_overrides()
            data = deep_merge(data, env_data)

        if cli_overrides:
            manager._cli_overrides = cli_overrides
            data = deep_merge(data, cli_overrides)

        manager.config = TechSpecterConfig.model_validate(data)
        manager.validator.validate_or_raise(manager.config)
        logger.debug("Configuration loaded successfully")
        return manager

    def apply_cli_overrides(self, overrides: dict[str, Any]) -> None:
        """Apply CLI overrides to the active configuration."""
        data = deep_merge(self.config.model_dump(mode="python"), overrides)
        self._cli_overrides = deep_merge(self._cli_overrides, overrides)
        self.config = TechSpecterConfig.model_validate(data)
        self.validator.validate_or_raise(self.config)

    def export(self, path: Path | str | None = None, *, fmt: str = "yaml") -> str:
        """Export the active configuration."""
        payload = self.config.model_dump(mode="python")
        if path is None:
            if fmt in {"yaml", "yml"}:
                import yaml

                return str(yaml.safe_dump(payload, sort_keys=False))
            import json

            return json.dumps(payload, indent=2)
        return export_config_file(payload, path, fmt=fmt)

    def to_dict(self) -> dict[str, Any]:
        """Return the active configuration as a dictionary."""
        return self.config.model_dump(mode="python")


def get_configuration_manager() -> ConfigurationManager:
    """Return the active configuration manager, loading defaults when unset."""
    manager = _active_manager.get()
    if manager is None:
        manager = ConfigurationManager.load()
        _active_manager.set(manager)
    return manager


def set_configuration_manager(manager: ConfigurationManager | None) -> None:
    """Set the active configuration manager for the current context."""
    _active_manager.set(manager)


def reset_configuration_manager() -> None:
    """Clear the active configuration manager."""
    _active_manager.set(None)
