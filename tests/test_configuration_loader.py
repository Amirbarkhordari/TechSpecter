"""Tests for configuration loading."""

from __future__ import annotations

import pytest

from techspecter.configuration.loader import export_config_file, load_config_file
from techspecter.configuration.manager import ConfigurationManager
from techspecter.exceptions import ConfigurationError
from tests.configuration_fixtures import write_json_config, write_yaml_config


def test_load_yaml_configuration(tmp_path) -> None:
    """Verify YAML configuration files load correctly."""
    config_path = tmp_path / "config.yaml"
    write_yaml_config(config_path)
    data = load_config_file(config_path)
    assert data["logging"]["level"] == "WARNING"
    assert data["downloader"]["request_timeout"] == 45


def test_load_json_configuration(tmp_path) -> None:
    """Verify JSON configuration files load correctly."""
    config_path = tmp_path / "config.json"
    write_json_config(config_path)
    data = load_config_file(config_path)
    assert data["logging"]["level"] == "ERROR"


def test_missing_configuration_file_raises(tmp_path) -> None:
    """Verify missing configuration files raise ConfigurationError."""
    with pytest.raises(ConfigurationError, match="not found"):
        load_config_file(tmp_path / "missing.yaml")


def test_manager_loads_file_configuration(tmp_path) -> None:
    """Verify the configuration manager loads file-based settings."""
    config_path = tmp_path / "config.yaml"
    write_yaml_config(config_path)
    manager = ConfigurationManager.load(config_path=config_path, apply_env=False)
    assert manager.config.logging.level == "WARNING"
    assert manager.config.analysis.min_confidence == 25
    assert "legacy-analyzer" in manager.config.analysis.disabled_analyzers


def test_export_configuration(tmp_path) -> None:
    """Verify active configuration can be exported."""
    manager = ConfigurationManager.load(apply_env=False)
    export_path = tmp_path / "exported.yaml"
    content = manager.export(export_path)
    assert "downloader" in content
    assert export_path.is_file()
