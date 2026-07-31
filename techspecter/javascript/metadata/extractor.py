"""JavaScript metadata extraction."""

from __future__ import annotations

import re

from techspecter.javascript.cache.resource_cache import JavaScriptResourceCache
from techspecter.javascript.classification.classifier import classify_resource, extract_chunk_name
from techspecter.javascript.models import (
    DiscoverySource,
    JavaScriptResourceMetadata,
    ModuleType,
)
from techspecter.javascript.normalization.pipeline import NormalizationResult
from techspecter.parser.sourcemap import detect_source_map_url

_GLOBAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("React", re.compile(r"\bReact\b|\bReactDOM\b")),
    ("Vue", re.compile(r"\bVue\b|\bcreateApp\b")),
    ("Angular", re.compile(r"\bng\b|\bɵɵ\b")),
    ("jQuery", re.compile(r"\bjQuery\b|\$\(")),
    ("webpack", re.compile(r"__webpack_require__")),
)
_MANIFEST_REF = re.compile(
    r"(buildManifest|app-build-manifest|vite\.manifest|__NUXT_MANIFEST__)",
    re.IGNORECASE,
)


class JavaScriptMetadataExtractor:
    """Extract structured metadata from normalized JavaScript resources."""

    def extract(
        self,
        *,
        url: str,
        filename: str,
        content: str,
        normalized: NormalizationResult,
        module_type: ModuleType = ModuleType.UNKNOWN,
        discovery_sources: list[DiscoverySource] | None = None,
        is_entry: bool = False,
        import_refs: list[str] | None = None,
        export_refs: list[str] | None = None,
        cache: JavaScriptResourceCache | None = None,
    ) -> JavaScriptResourceMetadata:
        """Extract metadata for an indexed resource."""
        content_hash = JavaScriptResourceCache.content_hash(content)
        cache_key = JavaScriptResourceCache.content_key(url=url, content=content)
        if cache is not None:
            cached = cache.metadata_cache.get(cache_key)
            if cached is not None:
                return cached

        sources = list(discovery_sources or [])
        kind, bundle_class, bundler = classify_resource(
            filename=filename,
            content=content,
            module_type=module_type,
            discovery_sources=sources,
            is_entry=is_entry,
        )
        source_map_url = detect_source_map_url(content, base_url=url)
        manifest_match = _MANIFEST_REF.search(content)
        known_globals = [name for name, pattern in _GLOBAL_PATTERNS if pattern.search(content)]
        imports = list(import_refs or [])
        exports = list(export_refs or [])
        dependencies = sorted(set(imports))

        metadata = JavaScriptResourceMetadata(
            filename=filename,
            content_hash=content_hash,
            module_type=module_type,
            resource_kind=kind,
            bundle_classification=bundle_class,
            bundler=bundler,
            is_minified=normalized.is_minified,
            is_entry_point=is_entry,
            chunk_name=extract_chunk_name(filename),
            source_map_url=source_map_url,
            manifest_reference=manifest_match.group(0) if manifest_match else None,
            known_globals=known_globals,
            import_references=imports,
            export_references=exports,
            dependencies=dependencies,
            discovery_sources=sources,
            content_length=normalized.original_length,
            normalized_length=normalized.normalized_length,
            truncated=normalized.truncated,
        )

        if cache is not None:
            cache.metadata_cache.set(cache_key, metadata)
            cache.hash_cache.set(content_hash, url)
        return metadata
