"""Shared plugin manager cache for faster pipeline startup."""

from __future__ import annotations

import logging
from threading import Lock

from techspecter.plugins.manager import PluginManager

logger = logging.getLogger(__name__)

_shared_manager: PluginManager | None = None
_lock = Lock()


def get_shared_plugin_manager(*, load_builtins: bool = True) -> PluginManager:
    """Return a process-wide plugin manager, loading builtins once."""
    global _shared_manager
    with _lock:
        if _shared_manager is None:
            manager = PluginManager()
            if load_builtins:
                loaded = manager.load_plugins(load_builtins=True)
                logger.debug("Shared plugin manager loaded %d plugins", len(loaded))
            _shared_manager = manager
        return _shared_manager


def reset_shared_plugin_manager() -> None:
    """Shutdown and reset the shared plugin manager (primarily for tests)."""
    global _shared_manager
    with _lock:
        if _shared_manager is not None:
            _shared_manager.shutdown()
        _shared_manager = None
