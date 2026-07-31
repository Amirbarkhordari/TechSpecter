"""Passive asset reference extraction from web manifests."""

from __future__ import annotations

import json
import logging

from techspecter.asset_discovery.models import AssetCategory, AssetDiscoverySource, AssetReference
from techspecter.utils.url import resolve_url

logger = logging.getLogger(__name__)


def extract_manifest_references(
    content: str, *, base_url: str, manifest_url: str
) -> list[AssetReference]:
    """Extract asset URLs from a web manifest JSON document."""
    references: list[AssetReference] = []
    seen: set[str] = set()

    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        logger.debug("Failed to parse manifest JSON from %s: %s", manifest_url, exc)
        return references

    if not isinstance(payload, dict):
        return references

    def add(raw: str, *, detail: str, category: AssetCategory) -> None:
        candidate = raw.strip()
        if not candidate:
            return
        try:
            absolute = resolve_url(base_url, candidate)
        except Exception as exc:
            logger.debug("Skipping invalid manifest reference %r: %s", candidate, exc)
            return
        if absolute in seen:
            return
        seen.add(absolute)
        references.append(
            AssetReference(
                url=absolute,
                original_url=candidate,
                category_hint=category,
                source=AssetDiscoverySource.MANIFEST,
                referenced_by=manifest_url,
                detail=detail,
            ),
        )

    icons = payload.get("icons")
    if isinstance(icons, list):
        for icon in icons:
            if isinstance(icon, dict) and isinstance(icon.get("src"), str):
                add(icon["src"], detail="manifest.icons", category=AssetCategory.IMAGE)

    for key in ("start_url", "scope"):
        value = payload.get(key)
        if isinstance(value, str):
            add(value, detail=f"manifest.{key}", category=AssetCategory.UNKNOWN)

    shortcuts = payload.get("shortcuts")
    if isinstance(shortcuts, list):
        for shortcut in shortcuts:
            if isinstance(shortcut, dict) and isinstance(shortcut.get("url"), str):
                add(shortcut["url"], detail="manifest.shortcuts", category=AssetCategory.UNKNOWN)

    logger.debug("Extracted %d manifest references from %s", len(references), manifest_url)
    return references
