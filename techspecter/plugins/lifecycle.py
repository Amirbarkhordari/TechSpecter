"""Plugin lifecycle management."""

from __future__ import annotations

import logging

from techspecter.plugins.context import PluginContext
from techspecter.plugins.interfaces import Plugin

logger = logging.getLogger(__name__)


class PluginLifecycle:
    """Manage plugin initialization and shutdown."""

    def initialize_plugin(self, plugin: Plugin, context: PluginContext) -> None:
        """Run initialize, register, start, and enable lifecycle hooks."""
        plugin.initialize(context)
        plugin.register(context)
        plugin.start(context)
        plugin.setup()
        plugin.enable(context)
        plugin._initialized = True
        plugin._enabled = True
        context.logger.info("Plugin initialized")

    def shutdown_plugin(self, plugin: Plugin, context: PluginContext) -> None:
        """Run disable, shutdown, and cleanup lifecycle hooks."""
        plugin.disable(context)
        plugin.shutdown(context)
        plugin.cleanup(context)
        plugin.teardown()
        plugin._enabled = False
        context.logger.info("Plugin shutdown complete")

    def enable_plugin(self, plugin: Plugin, context: PluginContext) -> None:
        """Enable a registered plugin."""
        plugin.enable(context)
        plugin._enabled = True

    def disable_plugin(self, plugin: Plugin, context: PluginContext) -> None:
        """Disable a registered plugin without unloading it."""
        plugin.disable(context)
        plugin._enabled = False

    def safe_initialize(self, plugin: Plugin, context: PluginContext) -> bool:
        """Initialize a plugin without raising on failure."""
        try:
            self.initialize_plugin(plugin, context)
        except Exception as exc:
            logger.warning(
                "Plugin '%s' failed during initialization: %s",
                context.plugin_id,
                exc,
            )
            return False
        return True

    def safe_shutdown(self, plugin: Plugin, context: PluginContext) -> None:
        """Shutdown a plugin without raising on failure."""
        try:
            self.shutdown_plugin(plugin, context)
        except Exception as exc:
            logger.warning(
                "Plugin '%s' failed during shutdown: %s",
                context.plugin_id,
                exc,
            )
