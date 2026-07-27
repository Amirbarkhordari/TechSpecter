"""Built-in OpenID Connect Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.openid_connect import OpenIdConnectAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="openid-connect-analyzer-plugin",
    name="OpenID Connect Analyzer Plugin",
    description="Built-in plugin for passive openid connect analyzer analysis.",
    analyzer_factory=OpenIdConnectAnalyzer,
)
