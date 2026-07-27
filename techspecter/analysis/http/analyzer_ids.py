"""HTTP analyzer identifiers and grouping helpers."""

from __future__ import annotations

HTTP_ANALYZER_IDS: tuple[str, ...] = (
    "http-header-analyzer",
    "security-header-analyzer",
    "cookie-analyzer",
    "csp-analyzer",
    "cors-analyzer",
    "cache-control-analyzer",
    "content-type-analyzer",
    "server-fingerprint-analyzer",
    "redirect-analyzer",
    "http-response-metadata-analyzer",
)

HTTP_ANALYZER_PLUGIN_IDS: tuple[str, ...] = (
    "http-header-analyzer-plugin",
    "security-header-analyzer-plugin",
    "cookie-analyzer-plugin",
    "csp-analyzer-plugin",
    "cors-analyzer-plugin",
    "cache-control-analyzer-plugin",
    "content-type-analyzer-plugin",
    "server-fingerprint-analyzer-plugin",
    "redirect-analyzer-plugin",
    "http-response-metadata-analyzer-plugin",
)

CLI_FLAG_ANALYZER_MAP: dict[str, tuple[str, ...]] = {
    "headers": ("http-header-analyzer",),
    "cookies": ("cookie-analyzer",),
    "security_headers": (
        "security-header-analyzer",
        "csp-analyzer",
    ),
    "redirects": ("redirect-analyzer",),
}


def is_http_analyzer(analyzer_id: str) -> bool:
    """Return whether an analyzer ID belongs to the HTTP analyzer set."""
    return analyzer_id in HTTP_ANALYZER_IDS
