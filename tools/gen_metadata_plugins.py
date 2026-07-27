"""Generate metadata plugin wrapper modules."""

from __future__ import annotations

from pathlib import Path

PLUGINS = [
    ("robots", "RobotsTxtAnalyzer", "robots-analyzer-plugin", "Robots.txt Analyzer Plugin"),
    ("sitemap", "SitemapAnalyzer", "sitemap-analyzer-plugin", "Sitemap Analyzer Plugin"),
    (
        "security_txt",
        "SecurityTxtAnalyzer",
        "security-txt-analyzer-plugin",
        "Security.txt Analyzer Plugin",
    ),
    ("manifest", "ManifestAnalyzer", "manifest-analyzer-plugin", "Manifest Analyzer Plugin"),
    (
        "web_app_manifest",
        "WebAppManifestAnalyzer",
        "web-app-manifest-analyzer-plugin",
        "Web App Manifest Analyzer Plugin",
    ),
    (
        "browserconfig",
        "BrowserConfigAnalyzer",
        "browserconfig-analyzer-plugin",
        "BrowserConfig Analyzer Plugin",
    ),
    ("humans_txt", "HumansTxtAnalyzer", "humans-txt-analyzer-plugin", "Humans.txt Analyzer Plugin"),
    ("ads_txt", "AdsTxtAnalyzer", "ads-txt-analyzer-plugin", "Ads.txt Analyzer Plugin"),
    (
        "assetlinks",
        "AssetLinksAnalyzer",
        "assetlinks-analyzer-plugin",
        "AssetLinks Analyzer Plugin",
    ),
    (
        "apple_app_site_association",
        "AppleAppSiteAssociationAnalyzer",
        "apple-app-site-association-analyzer-plugin",
        "Apple App Site Association Analyzer Plugin",
    ),
    (
        "html_metadata",
        "HtmlMetadataAnalyzer",
        "html-metadata-analyzer-plugin",
        "HTML Metadata Analyzer Plugin",
    ),
    (
        "html_comment",
        "HtmlCommentAnalyzer",
        "html-comment-analyzer-plugin",
        "HTML Comment Analyzer Plugin",
    ),
    ("opengraph", "OpenGraphAnalyzer", "opengraph-analyzer-plugin", "OpenGraph Analyzer Plugin"),
    (
        "twitter_card",
        "TwitterCardAnalyzer",
        "twitter-card-analyzer-plugin",
        "Twitter Card Analyzer Plugin",
    ),
    (
        "canonical_link",
        "CanonicalLinkAnalyzer",
        "canonical-link-analyzer-plugin",
        "Canonical Link Analyzer Plugin",
    ),
    (
        "alternate_link",
        "AlternateLinkAnalyzer",
        "alternate-link-analyzer-plugin",
        "Alternate Link Analyzer Plugin",
    ),
    (
        "generator_meta",
        "GeneratorMetaAnalyzer",
        "generator-meta-analyzer-plugin",
        "Generator Meta Analyzer Plugin",
    ),
    (
        "theme_color",
        "ThemeColorAnalyzer",
        "theme-color-analyzer-plugin",
        "Theme Color Analyzer Plugin",
    ),
    (
        "application_metadata",
        "ApplicationMetadataAnalyzer",
        "application-metadata-analyzer-plugin",
        "Application Metadata Analyzer Plugin",
    ),
    ("language", "LanguageAnalyzer", "language-analyzer-plugin", "Language Analyzer Plugin"),
    ("favicon", "FaviconAnalyzer", "favicon-analyzer-plugin", "Favicon Analyzer Plugin"),
    ("sourcemap", "SourceMapAnalyzer", "sourcemap-analyzer-plugin", "SourceMap Analyzer Plugin"),
    (
        "service_worker",
        "ServiceWorkerAnalyzer",
        "service-worker-analyzer-plugin",
        "Service Worker Analyzer Plugin",
    ),
    (
        "framework_metadata",
        "FrameworkMetadataAnalyzer",
        "framework-metadata-analyzer-plugin",
        "Framework Metadata Analyzer Plugin",
    ),
]

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "techspecter" / "plugins" / "builtin" / "metadata"
TARGET.mkdir(parents=True, exist_ok=True)
(TARGET / "__init__.py").write_text('"""Built-in metadata analyzer plugins."""\n', encoding="utf-8")

for module, cls, plugin_id, name in PLUGINS:
    desc = f"Built-in plugin for passive {name.replace(' Plugin', '').lower()} analysis."
    content = f'''"""Built-in {name}."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.{module} import {cls}
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
