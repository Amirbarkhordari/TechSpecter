"""Immutable evidence models for fingerprint collection."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import Field

from techspecter.models.base import TechSpecterModel


class EvidenceSource(StrEnum):
    """Origin subsystem that produced an evidence item."""

    NETWORK = "network"
    HTML = "html"
    JAVASCRIPT = "javascript"
    BUNDLE = "bundle"
    PACKAGE = "package"
    CSS = "css"
    PLUGIN = "plugin"
    UNKNOWN = "unknown"


class EvidenceType(StrEnum):
    """Classification of collected evidence."""

    HTTP_HEADER = "http_header"
    HTTP_METADATA = "http_metadata"
    HTML_ELEMENT = "html_element"
    HTML_MARKER = "html_marker"
    SCRIPT_REFERENCE = "script_reference"
    SCRIPT_CONTENT = "script_content"
    FILENAME = "filename"
    SOURCE_MAP = "source_map"
    BUNDLE_MARKER = "bundle_marker"
    PACKAGE_MARKER = "package_marker"
    METADATA = "metadata"
    CUSTOM = "custom"
    STRING_LITERAL = "string_literal"
    VERSION_CANDIDATE = "version_candidate"
    RUNTIME_PATTERN = "runtime_pattern"
    PACKAGE_REFERENCE = "package_reference"
    BANNER = "banner"
    MANIFEST = "manifest"
    BUNDLE_RUNTIME = "bundle_runtime"
    AST_EXTRACTION = "ast_extraction"
    SOURCE_MAP_METADATA = "source_map_metadata"
    IMPORT_EXPORT = "import_export"
    CSS_MARKER = "css_marker"


class Evidence(TechSpecterModel):
    """Single immutable evidence observation."""

    model_config = {**TechSpecterModel.model_config, "frozen": True}

    id: str = Field(default_factory=lambda: str(uuid4()))
    technology: str | None = None
    source: EvidenceSource
    evidence_type: EvidenceType
    file: str | None = None
    url: str | None = None
    matched_value: str | None = None
    matched_pattern: str | None = None
    line_number: int | None = Field(default=None, ge=1)
    category: str | None = None
    collector: str
    confidence_hint: float = Field(default=0.0, ge=0.0, le=100.0)
    metadata: dict[str, object] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    reason: str | None = None


class EvidenceSummary(TechSpecterModel):
    """Aggregated statistics for an evidence collection."""

    model_config = {**TechSpecterModel.model_config, "frozen": True}

    total_items: int = 0
    collectors: dict[str, int] = Field(default_factory=dict)
    sources: dict[str, int] = Field(default_factory=dict)
    evidence_types: dict[str, int] = Field(default_factory=dict)


class EvidenceCollection(TechSpecterModel):
    """Immutable aggregate of evidence produced by collectors."""

    model_config = {**TechSpecterModel.model_config, "frozen": True}

    target_url: str
    items: tuple[Evidence, ...] = Field(default_factory=tuple)
    summary: EvidenceSummary = Field(default_factory=EvidenceSummary)
    elapsed_ms: float = 0.0

    def with_items(self, items: list[Evidence]) -> EvidenceCollection:
        """Return a new collection with updated items and summary."""
        summary = summarize_evidence(items)
        return self.model_copy(update={"items": tuple(items), "summary": summary})


class EvidenceResult(TechSpecterModel):
    """Result returned by a single evidence collector."""

    model_config = {**TechSpecterModel.model_config, "frozen": True}

    collector: str
    items: tuple[Evidence, ...] = Field(default_factory=tuple)
    elapsed_ms: float = 0.0
    errors: tuple[str, ...] = Field(default_factory=tuple)


def summarize_evidence(items: list[Evidence]) -> EvidenceSummary:
    """Build summary statistics from evidence items."""
    collectors: dict[str, int] = {}
    sources: dict[str, int] = {}
    evidence_types: dict[str, int] = {}
    for item in items:
        collectors[item.collector] = collectors.get(item.collector, 0) + 1
        sources[item.source.value] = sources.get(item.source.value, 0) + 1
        type_key = item.evidence_type.value
        evidence_types[type_key] = evidence_types.get(type_key, 0) + 1
    return EvidenceSummary(
        total_items=len(items),
        collectors=collectors,
        sources=sources,
        evidence_types=evidence_types,
    )
