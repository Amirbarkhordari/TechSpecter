"""Asset discovery and inventory models."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import Field

from techspecter.models.base import TechSpecterModel


class AssetCategory(StrEnum):
    """High-level asset category."""

    JAVASCRIPT = "javascript"
    CSS = "css"
    JSON = "json"
    MAP = "map"
    MANIFEST = "manifest"
    WORKER = "worker"
    SERVICE_WORKER = "service_worker"
    WASM = "wasm"
    FONT = "font"
    XML = "xml"
    TEXT = "text"
    IMAGE = "image"
    UNKNOWN = "unknown"


class AssetDownloadStatus(StrEnum):
    """Outcome of an asset download attempt."""

    DOWNLOADED = "downloaded"
    SKIPPED = "skipped"
    FAILED = "failed"
    TIMEOUT = "timeout"
    FORBIDDEN = "forbidden"
    RATE_LIMITED = "rate_limited"
    NOT_ATTEMPTED = "not_attempted"


class AssetDiscoverySource(StrEnum):
    """How an asset reference was discovered."""

    HTML = "html"
    CSS = "css"
    JAVASCRIPT = "javascript"
    MANIFEST = "manifest"
    HTTP_HEADER = "http_header"
    WELL_KNOWN = "well_known"
    SERVICE_WORKER = "service_worker"
    ROBOTS = "robots"
    SITEMAP = "sitemap"
    SOURCE_MAP = "source_map"
    IMPORT_MAP = "import_map"


class AssetRelationship(TechSpecterModel):
    """Evidence describing how an asset was discovered."""

    source: AssetDiscoverySource
    referenced_by: str
    detail: str | None = None


class AssetRecord(TechSpecterModel):
    """A single discovered asset with metadata."""

    asset_id: str
    url: str
    original_url: str | None = None
    relative_path: str | None = None
    filename: str
    extension: str | None = None
    category: AssetCategory = AssetCategory.UNKNOWN
    content_type: str | None = None
    mime_type: str | None = None
    http_status: int | None = None
    encoding: str | None = None
    file_size: int | None = None
    sha256: str | None = None
    discovery_sources: list[AssetDiscoverySource] = Field(default_factory=list)
    relationships: list[AssetRelationship] = Field(default_factory=list)
    download_success: bool = False
    download_duration_ms: float | None = None
    response_time_ms: float | None = None
    error_message: str | None = None
    download_status: AssetDownloadStatus | None = None
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AssetInventorySummary(TechSpecterModel):
    """Aggregated asset counts by category."""

    javascript: int = 0
    css: int = 0
    json_count: int = 0
    map_count: int = 0
    manifest: int = 0
    worker: int = 0
    service_worker: int = 0
    wasm: int = 0
    font: int = 0
    xml: int = 0
    text: int = 0
    image: int = 0
    unknown: int = 0
    other: int = 0
    total_assets: int = 0

    def increment(self, category: AssetCategory) -> None:
        """Increment the counter for a category."""
        mapping = {
            AssetCategory.JAVASCRIPT: "javascript",
            AssetCategory.CSS: "css",
            AssetCategory.JSON: "json_count",
            AssetCategory.MAP: "map_count",
            AssetCategory.MANIFEST: "manifest",
            AssetCategory.WORKER: "worker",
            AssetCategory.SERVICE_WORKER: "service_worker",
            AssetCategory.WASM: "wasm",
            AssetCategory.FONT: "font",
            AssetCategory.XML: "xml",
            AssetCategory.TEXT: "text",
            AssetCategory.IMAGE: "image",
            AssetCategory.UNKNOWN: "unknown",
        }
        field_name = mapping.get(category, "other")
        current = getattr(self, field_name)
        setattr(self, field_name, current + 1)
        self.total_assets += 1


class AssetDownloadSummary(TechSpecterModel):
    """Aggregated asset download outcome counts."""

    downloaded: int = 0
    failed: int = 0
    skipped: int = 0
    timeout: int = 0
    forbidden: int = 0
    rate_limited: int = 0
    total_attempted: int = 0


class AssetInventory(TechSpecterModel):
    """Complete passive asset inventory for a target."""

    target_url: str
    assets: list[AssetRecord] = Field(default_factory=list)
    summary: AssetInventorySummary = Field(default_factory=AssetInventorySummary)
    download_summary: AssetDownloadSummary = Field(default_factory=AssetDownloadSummary)
    text_bodies: dict[str, str] = Field(default_factory=dict)
    elapsed_ms: float = 0.0
    started_at: datetime | None = None
    completed_at: datetime | None = None


class AssetReference(TechSpecterModel):
    """A referenced asset URL before download."""

    url: str
    original_url: str
    category_hint: AssetCategory | None = None
    source: AssetDiscoverySource
    referenced_by: str
    detail: str | None = None
