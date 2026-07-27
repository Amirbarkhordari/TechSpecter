"""Plugin execution safety utilities."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TypeVar

from techspecter.plugins.exceptions import PluginExecutionError

logger = logging.getLogger(__name__)

T = TypeVar("T")


def safe_call(
    callback: Callable[..., T],
    *args: object,
    label: str,
    plugin_id: str | None = None,
    default: T | None = None,
) -> T | None:
    """Execute a callback and isolate failures."""
    try:
        return callback(*args)
    except Exception as exc:
        prefix = f"Plugin '{plugin_id}'" if plugin_id else "Plugin runtime"
        logger.warning("%s failed during %s: %s", prefix, label, exc, exc_info=True)
        return default


def safe_call_or_raise(
    callback: Callable[..., T],
    *args: object,
    label: str,
    plugin_id: str | None = None,
) -> T:
    """Execute a callback and wrap failures in PluginExecutionError."""
    try:
        return callback(*args)
    except PluginExecutionError:
        raise
    except Exception as exc:
        message = f"Plugin execution failed during {label}"
        if plugin_id:
            message = f"Plugin '{plugin_id}' failed during {label}"
        raise PluginExecutionError(message) from exc
