"""Asset category classification."""

from __future__ import annotations

import mimetypes
from pathlib import PurePosixPath

from techspecter.asset_discovery.models import AssetCategory

_EXTENSION_MAP: dict[str, AssetCategory] = {
    ".js": AssetCategory.JAVASCRIPT,
    ".mjs": AssetCategory.JAVASCRIPT,
    ".cjs": AssetCategory.JAVASCRIPT,
    ".css": AssetCategory.CSS,
    ".json": AssetCategory.JSON,
    ".map": AssetCategory.MAP,
    ".webmanifest": AssetCategory.MANIFEST,
    ".wasm": AssetCategory.WASM,
    ".woff": AssetCategory.FONT,
    ".woff2": AssetCategory.FONT,
    ".ttf": AssetCategory.FONT,
    ".otf": AssetCategory.FONT,
    ".eot": AssetCategory.FONT,
    ".xml": AssetCategory.XML,
    ".txt": AssetCategory.TEXT,
    ".png": AssetCategory.IMAGE,
    ".jpg": AssetCategory.IMAGE,
    ".jpeg": AssetCategory.IMAGE,
    ".gif": AssetCategory.IMAGE,
    ".webp": AssetCategory.IMAGE,
    ".svg": AssetCategory.IMAGE,
    ".ico": AssetCategory.IMAGE,
    ".avif": AssetCategory.IMAGE,
}

_MANIFEST_NAMES = frozenset(
    {
        "manifest.json",
        "site.webmanifest",
        "browserconfig.xml",
    },
)

_WORKER_SUFFIXES = (".worker.js", ".worker.mjs", ".sharedworker.js")


class AssetClassifier:
    """Classify assets by extension, filename, MIME type, and URL hints."""

    def classify(
        self,
        *,
        url: str,
        filename: str,
        content_type: str | None = None,
        source_hint: AssetCategory | None = None,
    ) -> AssetCategory:
        """Return the best category for an asset."""
        if source_hint is not None and source_hint != AssetCategory.UNKNOWN:
            return source_hint

        lowered_name = filename.lower()
        if lowered_name in _MANIFEST_NAMES or "manifest" in lowered_name:
            return AssetCategory.MANIFEST
        if lowered_name == "robots.txt":
            return AssetCategory.TEXT
        if lowered_name == "sitemap.xml":
            return AssetCategory.XML

        for suffix in _WORKER_SUFFIXES:
            if lowered_name.endswith(suffix):
                return AssetCategory.WORKER

        extension = PurePosixPath(lowered_name).suffix.lower()
        if extension in _EXTENSION_MAP:
            category = _EXTENSION_MAP[extension]
            if extension == ".map":
                return AssetCategory.MAP
            return category

        if content_type:
            mime = content_type.split(";", 1)[0].strip().lower()
            mime_category = _category_from_mime(mime)
            if mime_category != AssetCategory.UNKNOWN:
                return mime_category

        path_lower = url.lower()
        if "serviceworker" in path_lower or "service-worker" in path_lower:
            return AssetCategory.SERVICE_WORKER
        if path_lower.endswith(".map") or ".map?" in path_lower:
            return AssetCategory.MAP

        return AssetCategory.UNKNOWN

    def extension_from_filename(self, filename: str) -> str | None:
        """Return lowercase extension including dot, or None."""
        suffix = PurePosixPath(filename).suffix.lower()
        return suffix or None


def _category_from_mime(mime: str) -> AssetCategory:
    """Map a MIME type to an asset category."""
    if mime in {"application/javascript", "text/javascript", "module"}:
        return AssetCategory.JAVASCRIPT
    if mime == "text/css":
        return AssetCategory.CSS
    if mime == "application/json":
        return AssetCategory.JSON
    if mime == "application/wasm":
        return AssetCategory.WASM
    if mime.startswith("image/"):
        return AssetCategory.IMAGE
    if mime.startswith("font/") or mime in {
        "application/font-woff",
        "application/font-woff2",
        "application/vnd.ms-fontobject",
    }:
        return AssetCategory.FONT
    if mime in {"text/xml", "application/xml"}:
        return AssetCategory.XML
    if mime.startswith("text/"):
        return AssetCategory.TEXT
    guessed, _ = mimetypes.guess_type(f"file.{mime.split('/')[-1]}")
    if guessed:
        return AssetCategory.UNKNOWN
    return AssetCategory.UNKNOWN
