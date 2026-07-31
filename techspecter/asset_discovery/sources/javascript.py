"""Passive asset reference extraction from JavaScript content."""

from __future__ import annotations

import logging
import re

from techspecter.asset_discovery.models import AssetCategory, AssetDiscoverySource, AssetReference
from techspecter.parser.sourcemap import detect_source_map_url
from techspecter.utils.url import resolve_url

logger = logging.getLogger(__name__)

_ASSET_STRING = re.compile(
    r"""['"]([^'"]+\.(?:css|json|map|wasm|woff2?|ttf|otf|eot|png|jpe?g|gif|webp|svg|avif|ico|xml|txt|webmanifest)(?:\?[^{'\"\\s]*)?)['"]""",
    re.IGNORECASE,
)
_WORKER = re.compile(
    r"""new\s+(?:Shared)?Worker\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
_SERVICE_WORKER = re.compile(
    r"""navigator\.serviceWorker\.register\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
_SOURCEMAP_COMMENT = re.compile(
    r"//[#@]\s*sourceMappingURL=(\S+)",
    re.IGNORECASE,
)


def extract_javascript_references(
    content: str,
    *,
    base_url: str,
    parent_url: str,
) -> list[AssetReference]:
    """Extract non-JavaScript asset references from script content."""
    references: list[AssetReference] = []
    seen: set[str] = set()

    def add(
        raw: str,
        *,
        source: AssetDiscoverySource,
        category_hint: AssetCategory,
        detail: str,
    ) -> None:
        candidate = raw.strip()
        if not candidate or candidate.startswith(("data:", "blob:")):
            return
        try:
            absolute = resolve_url(base_url, candidate)
        except Exception as exc:
            logger.debug("Skipping invalid JS asset reference %r: %s", candidate, exc)
            return
        if absolute in seen:
            return
        seen.add(absolute)
        references.append(
            AssetReference(
                url=absolute,
                original_url=candidate,
                category_hint=category_hint,
                source=source,
                referenced_by=parent_url,
                detail=detail,
            ),
        )

    for match in _ASSET_STRING.finditer(content):
        raw = match.group(1)
        add(
            raw,
            source=AssetDiscoverySource.JAVASCRIPT,
            category_hint=_category_from_path(raw),
            detail="js-string-literal",
        )

    for match in _WORKER.finditer(content):
        add(
            match.group(1),
            source=AssetDiscoverySource.JAVASCRIPT,
            category_hint=AssetCategory.WORKER,
            detail="worker-constructor",
        )

    for match in _SERVICE_WORKER.finditer(content):
        add(
            match.group(1),
            source=AssetDiscoverySource.SERVICE_WORKER,
            category_hint=AssetCategory.SERVICE_WORKER,
            detail="service-worker-register",
        )

    source_map = detect_source_map_url(content)
    if source_map:
        add(
            source_map,
            source=AssetDiscoverySource.SOURCE_MAP,
            category_hint=AssetCategory.MAP,
            detail="sourceMappingURL",
        )

    for match in _SOURCEMAP_COMMENT.finditer(content):
        add(
            match.group(1),
            source=AssetDiscoverySource.SOURCE_MAP,
            category_hint=AssetCategory.MAP,
            detail="sourceMappingURL-comment",
        )

    logger.debug(
        "Extracted %d JS-derived asset references from %s",
        len(references),
        parent_url,
    )
    return references


def _category_from_path(path: str) -> AssetCategory:
    """Infer category from a referenced path string."""
    lowered = path.lower()
    if lowered.endswith(".css"):
        return AssetCategory.CSS
    if lowered.endswith(".json") or lowered.endswith(".webmanifest"):
        return AssetCategory.JSON if lowered.endswith(".json") else AssetCategory.MANIFEST
    if lowered.endswith(".map"):
        return AssetCategory.MAP
    if lowered.endswith(".wasm"):
        return AssetCategory.WASM
    if lowered.endswith((".woff", ".woff2", ".ttf", ".otf", ".eot")):
        return AssetCategory.FONT
    if lowered.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".avif")):
        return AssetCategory.IMAGE
    if lowered.endswith(".xml"):
        return AssetCategory.XML
    if lowered.endswith(".txt"):
        return AssetCategory.TEXT
    return AssetCategory.UNKNOWN
