"""Passive asset reference extraction from CSS."""

from __future__ import annotations

import logging
import re

from techspecter.asset_discovery.models import AssetCategory, AssetDiscoverySource, AssetReference
from techspecter.utils.url import resolve_url

logger = logging.getLogger(__name__)

_URL_PATTERN = re.compile(
    r"""url\s*\(\s*['"]?([^'"\)\s]+)['"]?\s*\)""",
    re.IGNORECASE,
)
_IMPORT_PATTERN = re.compile(
    r"""@import\s+(?:url\s*\(\s*['"]?([^'"\)\s]+)['"]?\s*\)|['"]([^'"]+)['"])""",
    re.IGNORECASE,
)


def extract_css_references(content: str, *, base_url: str) -> list[AssetReference]:
    """Extract asset URLs referenced by CSS content."""
    references: list[AssetReference] = []
    seen: set[str] = set()

    def add(raw: str, *, detail: str) -> None:
        candidate = raw.strip().strip("'\"")
        if not candidate or candidate.startswith(("data:", "#")):
            return
        try:
            absolute = resolve_url(base_url, candidate)
        except Exception as exc:
            logger.debug("Skipping invalid CSS asset reference %r: %s", candidate, exc)
            return
        if absolute in seen:
            return
        seen.add(absolute)
        category = _category_from_css_url(candidate)
        references.append(
            AssetReference(
                url=absolute,
                original_url=candidate,
                category_hint=category,
                source=AssetDiscoverySource.CSS,
                referenced_by=base_url,
                detail=detail,
            ),
        )

    for match in _URL_PATTERN.finditer(content):
        add(match.group(1), detail="css-url()")

    for match in _IMPORT_PATTERN.finditer(content):
        raw = match.group(1) or match.group(2)
        if raw:
            add(raw, detail="css-@import")

    logger.debug("Extracted %d CSS asset references from %s", len(references), base_url)
    return references


def _category_from_css_url(path: str) -> AssetCategory:
    """Infer category from a CSS url() reference."""
    lowered = path.lower()
    if lowered.endswith(".css"):
        return AssetCategory.CSS
    if lowered.endswith((".woff", ".woff2", ".ttf", ".otf", ".eot")):
        return AssetCategory.FONT
    if lowered.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".avif")):
        return AssetCategory.IMAGE
    return AssetCategory.UNKNOWN
