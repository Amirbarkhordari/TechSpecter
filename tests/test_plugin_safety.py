"""Tests for plugin safety utilities."""

from __future__ import annotations

import pytest

from techspecter.plugins.exceptions import PluginExecutionError
from techspecter.plugins.safety import safe_call, safe_call_or_raise


def test_safe_call_returns_default_on_failure() -> None:
    """Verify safe_call returns default when callback fails."""

    def failing() -> str:
        raise RuntimeError("boom")

    assert safe_call(failing, label="test", default="fallback") == "fallback"


def test_safe_call_or_raise_wraps_exception() -> None:
    """Verify safe_call_or_raise wraps failures in PluginExecutionError."""

    def failing() -> None:
        raise RuntimeError("boom")

    with pytest.raises(PluginExecutionError, match="failed during test"):
        safe_call_or_raise(failing, label="test", plugin_id="sample")
