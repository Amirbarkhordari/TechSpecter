"""Built-in server fingerprint analyzer plugin."""

from __future__ import annotations

from techspecter.analysis.http.analyzers.server_fingerprint import ServerFingerprintAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="server-fingerprint-analyzer-plugin",
    name="Server Fingerprint Analyzer Plugin",
    description="Built-in plugin for passive server fingerprint analysis.",
    analyzer_factory=ServerFingerprintAnalyzer,
)
