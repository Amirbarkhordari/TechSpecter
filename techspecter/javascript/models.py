"""Core models for JavaScript discovery and preprocessing."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, HttpUrl

from techspecter.models.base import TechSpecterModel


class DiscoverySource(StrEnum):
    """Passive discovery source for a JavaScript reference."""

    HTML_SCRIPT = "html_script"
    HTML_MODULE = "html_module"
    HTML_DEFERRED = "html_deferred"
    HTML_ASYNC = "html_async"
    LINK_MODULEPRELOAD = "link_modulepreload"
    LINK_PRELOAD = "link_preload"
    LINK_PREFETCH = "link_prefetch"
    IMPORT_MAP = "import_map"
    MANIFEST = "manifest"
    SERVICE_WORKER = "service_worker"
    SHARED_WORKER = "shared_worker"
    WORKER = "worker"
    SCRIPT_REFERENCE = "script_reference"
    DYNAMIC_IMPORT = "dynamic_import"
    WEBPACK_CHUNK = "webpack_chunk"
    BUNDLE_MANIFEST = "bundle_manifest"
    RECURSIVE = "recursive"


class ModuleType(StrEnum):
    """JavaScript module loading type."""

    CLASSIC = "classic"
    MODULE = "module"
    WORKER = "worker"
    SERVICE_WORKER = "service_worker"
    SHARED_WORKER = "shared_worker"
    UNKNOWN = "unknown"


class JavaScriptResourceKind(StrEnum):
    """Classification of a discovered JavaScript resource."""

    ENTRY_BUNDLE = "entry_bundle"
    RUNTIME_BUNDLE = "runtime_bundle"
    VENDOR_BUNDLE = "vendor_bundle"
    APPLICATION_BUNDLE = "application_bundle"
    FRAMEWORK_BUNDLE = "framework_bundle"
    LAZY_CHUNK = "lazy_chunk"
    DYNAMIC_CHUNK = "dynamic_chunk"
    WORKER = "worker"
    SERVICE_WORKER = "service_worker"
    SHARED_WORKER = "shared_worker"
    MODULE = "module"
    UNKNOWN = "unknown"


class BundlerType(StrEnum):
    """Detected JavaScript bundler or build tool."""

    WEBPACK = "webpack"
    TURBOPACK = "turbopack"
    VITE = "vite"
    ROLLUP = "rollup"
    PARCEL = "parcel"
    RSPACK = "rspack"
    ESBUILD = "esbuild"
    UNKNOWN = "unknown"


class BundleClassification(StrEnum):
    """High-level bundle role classification."""

    ENTRY = "entry"
    RUNTIME = "runtime"
    VENDOR = "vendor"
    APPLICATION = "application"
    FRAMEWORK = "framework"
    CHUNK = "chunk"
    WORKER = "worker"
    UNKNOWN = "unknown"


class DiscoveredReference(TechSpecterModel):
    """A passively discovered JavaScript URL reference."""

    url: HttpUrl
    original_reference: str
    source: DiscoverySource
    module_type: ModuleType = ModuleType.UNKNOWN
    parent_url: str | None = None


class JavaScriptResourceMetadata(TechSpecterModel):
    """Structured metadata extracted from a JavaScript resource."""

    filename: str
    content_hash: str
    module_type: ModuleType = ModuleType.UNKNOWN
    resource_kind: JavaScriptResourceKind = JavaScriptResourceKind.UNKNOWN
    bundle_classification: BundleClassification = BundleClassification.UNKNOWN
    bundler: BundlerType = BundlerType.UNKNOWN
    is_minified: bool = False
    is_entry_point: bool = False
    chunk_name: str | None = None
    source_map_url: str | None = None
    manifest_reference: str | None = None
    known_globals: list[str] = Field(default_factory=list)
    known_constants: list[str] = Field(default_factory=list)
    import_references: list[str] = Field(default_factory=list)
    export_references: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    discovery_sources: list[DiscoverySource] = Field(default_factory=list)
    content_length: int = 0
    normalized_length: int = 0
    truncated: bool = False


class AstSnapshot(TechSpecterModel):
    """Prepared AST/token parse snapshot for future analyzers."""

    parser_id: str
    parse_strategy: str
    import_count: int = 0
    export_count: int = 0
    identifier_count: int = 0
    string_literal_count: int = 0
    parse_errors: list[str] = Field(default_factory=list)


class IndexedJavaScriptResource(TechSpecterModel):
    """A fully processed JavaScript resource in the index."""

    resource_id: str
    url: str
    original_url: str
    inline: bool = False
    inline_index: int | None = None
    download_success: bool = True
    status_code: int | None = None
    content_type: str | None = None
    encoding: str | None = None
    error_message: str | None = None
    content: str | None = None
    normalized_content: str | None = None
    metadata: JavaScriptResourceMetadata
    ast: AstSnapshot | None = None
    duplicate_of: str | None = None
    download_duration_ms: float | None = None


class JavaScriptPipelineStatistics(TechSpecterModel):
    """Statistics from a JavaScript pipeline run."""

    discovered_urls: int = 0
    downloaded_resources: int = 0
    inline_resources: int = 0
    duplicate_skipped: int = 0
    recursive_rounds: int = 0
    cache_hits: int = 0
    failed_downloads: int = 0
    elapsed_ms: float = 0.0
