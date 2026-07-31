"""Technology intelligence and evidence models."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import Field

from techspecter.fingerprinting.models import Technology
from techspecter.models.base import TechSpecterModel


class IntelligenceEvidenceType(StrEnum):
    """Classification of technology detection evidence."""

    PATTERN_MATCH = "pattern_match"
    RUNTIME_CONSTANT = "runtime_constant"
    BANNER = "banner"
    METADATA = "metadata"
    PACKAGE_IDENTIFIER = "package_identifier"
    HTTP_HEADER = "http_header"
    SCRIPT_CONTENT = "script_content"
    BUNDLE_MARKER = "bundle_marker"
    FILENAME = "filename"
    SOURCE_MAP = "source_map"
    VERSION_CANDIDATE = "version_candidate"
    CUSTOM = "custom"


class DiscoveryMethod(StrEnum):
    """How the evidence-producing asset was discovered."""

    HTML = "html"
    JAVASCRIPT = "javascript"
    CSS = "css"
    NETWORK = "network"
    MANIFEST = "manifest"
    WELL_KNOWN = "well_known"
    INLINE = "inline"
    UNKNOWN = "unknown"


class RelationshipKind(StrEnum):
    """Kind of dependency between technologies."""

    FRAMEWORK_DEPENDENCY = "framework_dependency"
    UI_DEPENDENCY = "ui_dependency"
    ROUTING_DEPENDENCY = "routing_dependency"
    LANGUAGE_DEPENDENCY = "language_dependency"
    BUILD_TOOL = "build_tool"
    RUNTIME = "runtime"


class TechnologyEvidenceRecord(TechSpecterModel):
    """Complete evidence record for a technology detection."""

    evidence_id: str
    technology_name: str
    category: str
    version: str | None = None
    confidence: float = Field(ge=0.0, le=100.0)
    detector_name: str
    evidence_type: IntelligenceEvidenceType
    matched_pattern: str | None = None
    matched_text: str | None = None
    source_file: str | None = None
    source_url: str | None = None
    source_asset_id: str | None = None
    byte_offset: int | None = Field(default=None, ge=0)
    line_number: int | None = Field(default=None, ge=1)
    discovery_method: DiscoveryMethod = DiscoveryMethod.UNKNOWN
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class VersionAttributionRecord(TechSpecterModel):
    """Version detection outcome with provenance."""

    detected_version: str
    source_file: str | None = None
    source_url: str | None = None
    source_asset_id: str | None = None
    matched_pattern: str | None = None
    matched_text: str | None = None
    confidence: float = Field(ge=0.0, le=100.0)
    extractor_id: str | None = None
    alternative_candidates: list[str] = Field(default_factory=list)


class TechnologyRelationshipRecord(TechSpecterModel):
    """Dependency relationship between detected technologies."""

    source_technology_id: str
    source_technology_name: str
    target_technology_id: str
    target_technology_name: str
    relationship: RelationshipKind
    confidence: float = Field(default=100.0, ge=0.0, le=100.0)


class TechnologyDetectionMetadata(TechSpecterModel):
    """Aggregated detection metadata for one technology."""

    detection_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    detection_methods: list[str] = Field(default_factory=list)
    asset_count: int = 0
    evidence_count: int = 0
    version_source: str | None = None
    relationship_count: int = 0
    detectors: list[str] = Field(default_factory=list)


class TechnologyIntelligenceEntry(TechSpecterModel):
    """Intelligence record for a single detected technology."""

    technology: Technology
    version: str
    confidence: float = Field(ge=0.0, le=100.0)
    evidence: list[TechnologyEvidenceRecord] = Field(default_factory=list)
    version_attribution: VersionAttributionRecord | None = None
    relationships: list[TechnologyRelationshipRecord] = Field(default_factory=list)
    metadata: TechnologyDetectionMetadata = Field(default_factory=TechnologyDetectionMetadata)
    found_in_files: list[str] = Field(default_factory=list)
    found_in_asset_ids: list[str] = Field(default_factory=list)
    detectors: list[str] = Field(default_factory=list)


class TechnologyIntelligenceReport(TechSpecterModel):
    """Complete technology intelligence output for a scan target."""

    target_url: str
    technologies: list[TechnologyIntelligenceEntry] = Field(default_factory=list)
    relationships: list[TechnologyRelationshipRecord] = Field(default_factory=list)
    total_evidence: int = 0
    total_assets_referenced: int = 0
    elapsed_ms: float = 0.0
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
