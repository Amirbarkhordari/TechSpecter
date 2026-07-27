"""Specialized passive metadata analyzers."""

from techspecter.analysis.metadata.analyzers.ads_txt import AdsTxtAnalyzer
from techspecter.analysis.metadata.analyzers.alternate_link import AlternateLinkAnalyzer
from techspecter.analysis.metadata.analyzers.apple_app_site_association import (
    AppleAppSiteAssociationAnalyzer,
)
from techspecter.analysis.metadata.analyzers.application_metadata import ApplicationMetadataAnalyzer
from techspecter.analysis.metadata.analyzers.assetlinks import AssetLinksAnalyzer
from techspecter.analysis.metadata.analyzers.base import PassiveMetadataAnalyzer
from techspecter.analysis.metadata.analyzers.browserconfig import BrowserConfigAnalyzer
from techspecter.analysis.metadata.analyzers.canonical_link import CanonicalLinkAnalyzer
from techspecter.analysis.metadata.analyzers.favicon import FaviconAnalyzer
from techspecter.analysis.metadata.analyzers.framework_metadata import FrameworkMetadataAnalyzer
from techspecter.analysis.metadata.analyzers.generator_meta import GeneratorMetaAnalyzer
from techspecter.analysis.metadata.analyzers.html_comment import HtmlCommentAnalyzer
from techspecter.analysis.metadata.analyzers.html_metadata import HtmlMetadataAnalyzer
from techspecter.analysis.metadata.analyzers.humans_txt import HumansTxtAnalyzer
from techspecter.analysis.metadata.analyzers.language import LanguageAnalyzer
from techspecter.analysis.metadata.analyzers.manifest import ManifestAnalyzer
from techspecter.analysis.metadata.analyzers.opengraph import OpenGraphAnalyzer
from techspecter.analysis.metadata.analyzers.robots import RobotsTxtAnalyzer
from techspecter.analysis.metadata.analyzers.security_txt import SecurityTxtAnalyzer
from techspecter.analysis.metadata.analyzers.service_worker import ServiceWorkerAnalyzer
from techspecter.analysis.metadata.analyzers.sitemap import SitemapAnalyzer
from techspecter.analysis.metadata.analyzers.sourcemap import SourceMapAnalyzer
from techspecter.analysis.metadata.analyzers.theme_color import ThemeColorAnalyzer
from techspecter.analysis.metadata.analyzers.twitter_card import TwitterCardAnalyzer
from techspecter.analysis.metadata.analyzers.web_app_manifest import WebAppManifestAnalyzer

__all__ = [
    "AdsTxtAnalyzer",
    "AlternateLinkAnalyzer",
    "AppleAppSiteAssociationAnalyzer",
    "ApplicationMetadataAnalyzer",
    "AssetLinksAnalyzer",
    "BrowserConfigAnalyzer",
    "CanonicalLinkAnalyzer",
    "FaviconAnalyzer",
    "FrameworkMetadataAnalyzer",
    "GeneratorMetaAnalyzer",
    "HtmlCommentAnalyzer",
    "HtmlMetadataAnalyzer",
    "HumansTxtAnalyzer",
    "LanguageAnalyzer",
    "ManifestAnalyzer",
    "OpenGraphAnalyzer",
    "PassiveMetadataAnalyzer",
    "RobotsTxtAnalyzer",
    "SecurityTxtAnalyzer",
    "ServiceWorkerAnalyzer",
    "SitemapAnalyzer",
    "SourceMapAnalyzer",
    "ThemeColorAnalyzer",
    "TwitterCardAnalyzer",
    "WebAppManifestAnalyzer",
]
