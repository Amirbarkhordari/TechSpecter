"""Generate artifact plugin wrapper modules."""

from __future__ import annotations

from pathlib import Path

PLUGINS = [
    ("api_key", "ApiKeyAnalyzer", "api-key-analyzer-plugin", "API Key Analyzer Plugin"),
    ("jwt", "JwtAnalyzer", "jwt-analyzer-plugin", "JWT Analyzer Plugin"),
    (
        "oauth_metadata",
        "OAuthMetadataAnalyzer",
        "oauth-metadata-analyzer-plugin",
        "OAuth Metadata Analyzer Plugin",
    ),
    (
        "openid_connect",
        "OpenIdConnectAnalyzer",
        "openid-connect-analyzer-plugin",
        "OpenID Connect Analyzer Plugin",
    ),
    (
        "graphql_metadata",
        "GraphqlMetadataAnalyzer",
        "graphql-metadata-analyzer-plugin",
        "GraphQL Metadata Analyzer Plugin",
    ),
    ("openapi", "OpenApiAnalyzer", "openapi-analyzer-plugin", "OpenAPI Analyzer Plugin"),
    ("firebase", "FirebaseAnalyzer", "firebase-analyzer-plugin", "Firebase Analyzer Plugin"),
    (
        "aws_metadata",
        "AwsMetadataAnalyzer",
        "aws-metadata-analyzer-plugin",
        "AWS Metadata Analyzer Plugin",
    ),
    (
        "azure_metadata",
        "AzureMetadataAnalyzer",
        "azure-metadata-analyzer-plugin",
        "Azure Metadata Analyzer Plugin",
    ),
    (
        "google_cloud_metadata",
        "GoogleCloudMetadataAnalyzer",
        "google-cloud-metadata-analyzer-plugin",
        "Google Cloud Metadata Analyzer Plugin",
    ),
    ("cdn", "CdnAnalyzer", "cdn-analyzer-plugin", "CDN Analyzer Plugin"),
    (
        "third_party_service",
        "ThirdPartyServiceAnalyzer",
        "third-party-service-analyzer-plugin",
        "Third-Party Service Analyzer Plugin",
    ),
    (
        "analytics_service",
        "AnalyticsServiceAnalyzer",
        "analytics-service-analyzer-plugin",
        "Analytics Service Analyzer Plugin",
    ),
    (
        "monitoring_service",
        "MonitoringServiceAnalyzer",
        "monitoring-service-analyzer-plugin",
        "Monitoring Service Analyzer Plugin",
    ),
    (
        "technology_exposure",
        "TechnologyExposureAnalyzer",
        "technology-exposure-analyzer-plugin",
        "Technology Exposure Analyzer Plugin",
    ),
]

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "techspecter" / "plugins" / "builtin" / "artifact"
TARGET.mkdir(parents=True, exist_ok=True)
(TARGET / "__init__.py").write_text('"""Built-in artifact analyzer plugins."""\n', encoding="utf-8")

for module, cls, plugin_id, name in PLUGINS:
    desc = f"Built-in plugin for passive {name.replace(' Plugin', '').lower()} analysis."
    content = f'''"""Built-in {name}."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.{module} import {cls}
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="{plugin_id}",
    name="{name}",
    description="{desc}",
    analyzer_factory={cls},
)
'''
    (TARGET / f"{module}.py").write_text(content, encoding="utf-8")

print(f"Generated {len(PLUGINS)} plugin modules")
