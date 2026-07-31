"""Shared pytest fixtures and test isolation helpers."""

from __future__ import annotations

import logging

import pytest

from techspecter.configuration.manager import ConfigurationManager, set_configuration_manager
from techspecter.utils.logging import reset_logging


@pytest.fixture(autouse=True, scope="session")
def rebuild_pydantic_forward_refs() -> None:
    """Ensure Pydantic forward references are resolved before model use."""
    import techspecter.crawler.discovery  # noqa: F401
    import techspecter.fingerprinting.rebuild  # noqa: F401


@pytest.fixture(autouse=True)
def isolate_logging() -> None:
    """Reset logging handlers after each test to avoid cross-test interference."""
    yield
    reset_logging()
    logging.getLogger().setLevel(logging.WARNING)


@pytest.fixture
def config_manager() -> ConfigurationManager:
    """Return a fresh default configuration manager."""
    manager = ConfigurationManager.load()
    set_configuration_manager(manager)
    return manager


@pytest.fixture(autouse=True)
def reset_performance_caches() -> None:
    """Reset shared performance caches before each test."""
    from techspecter.performance.cache import reset_analysis_cache
    from techspecter.performance.plugin_cache import reset_shared_plugin_manager
    from techspecter.rules.shared import reset_shared_rule_resources

    reset_analysis_cache()
    reset_shared_plugin_manager()
    reset_shared_rule_resources()
    manager = ConfigurationManager.load()
    set_configuration_manager(manager)
    yield
    reset_analysis_cache()
    reset_shared_plugin_manager()
    reset_shared_rule_resources()
