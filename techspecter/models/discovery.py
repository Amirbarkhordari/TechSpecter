"""Data models for JavaScript discovery results."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from pydantic import Field, HttpUrl

from techspecter.models.artifact import ArtifactDiscoveryObservation
from techspecter.models.base import TechSpecterModel
from techspecter.models.http import HttpResponseObservation
from techspecter.models.metadata import MetadataDiscoveryObservation

if TYPE_CHECKING:
    from techspecter.asset_discovery.models import AssetInventory
    from techspecter.javascript.index.javascript_index import JavaScriptIndex
    from techspecter.sensitive_intelligence.models import SensitiveIntelligenceReport


class Target(TechSpecterModel):
    """Validated and normalized scan target.

    Attributes:
        url: Normalized target URL.
        original_url: Original URL provided by the user.
    """

    url: HttpUrl
    original_url: str


class InlineScript(TechSpecterModel):
    """Inline JavaScript block discovered in an HTML document.

    Attributes:
        index: Zero-based index among inline scripts on the page.
        content: Raw script content.
        source_map_url: Detected ``sourceMappingURL`` reference, if any.
    """

    index: int = Field(ge=0)
    content: str
    source_map_url: str | None = None


class ScriptResource(TechSpecterModel):
    """External JavaScript resource discovered in an HTML document.

    Attributes:
        url: Absolute URL of the script resource.
        original_url: URL as discovered in the HTML before normalization.
    """

    url: HttpUrl
    original_url: str


class DownloadResult(TechSpecterModel):
    """Metadata for a downloaded JavaScript resource.

    Attributes:
        url: Absolute URL of the downloaded resource.
        filename: Derived filename from the URL path.
        status_code: HTTP response status code, if available.
        content_type: Response Content-Type header value.
        encoding: Detected or declared character encoding.
        content_length: Response body length in bytes.
        download_success: Whether the download completed successfully.
        download_duration_ms: Download duration in milliseconds.
        error_message: Error description when download failed.
        source_map_url: Detected ``sourceMappingURL`` reference, if any.
        content: Downloaded JavaScript body text when available.
    """

    url: HttpUrl
    filename: str
    status_code: int | None = None
    content_type: str | None = None
    encoding: str | None = None
    content_length: int | None = None
    download_success: bool = False
    download_duration_ms: float | None = None
    error_message: str | None = None
    source_map_url: str | None = None
    content: str | None = None


class DiscoveryResult(TechSpecterModel):
    """Complete result of a JavaScript discovery scan.

    Attributes:
        target: Validated target information.
        external_scripts: Discovered external script resources.
        inline_scripts: Discovered inline script blocks.
        downloads: Download results for external scripts.
        elapsed_ms: Total pipeline execution time in milliseconds.
        started_at: UTC timestamp when the scan started.
        completed_at: UTC timestamp when the scan completed.
    """

    target: Target
    external_scripts: list[ScriptResource] = Field(default_factory=list)
    inline_scripts: list[InlineScript] = Field(default_factory=list)
    downloads: list[DownloadResult] = Field(default_factory=list)
    http_response: HttpResponseObservation | None = None
    metadata_observation: MetadataDiscoveryObservation | None = None
    artifact_observation: ArtifactDiscoveryObservation | None = None
    javascript_index: JavaScriptIndex | None = None
    asset_inventory: AssetInventory | None = None
    sensitive_intelligence: SensitiveIntelligenceReport | None = None
    elapsed_ms: float = 0.0
    started_at: datetime | None = None
    completed_at: datetime | None = None

    @property
    def discovered_count(self) -> int:
        """Return the total number of discovered script resources."""
        return len(self.external_scripts) + len(self.inline_scripts)

    @property
    def downloaded_count(self) -> int:
        """Return the number of successfully downloaded external scripts."""
        return sum(1 for item in self.downloads if item.download_success)

    @property
    def failed_count(self) -> int:
        """Return the number of failed external script downloads."""
        return sum(1 for item in self.downloads if not item.download_success)
