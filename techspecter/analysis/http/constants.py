"""HTTP analyzer constants."""

from __future__ import annotations

COMMON_RESPONSE_HEADERS: tuple[str, ...] = (
    "server",
    "date",
    "content-type",
    "content-length",
    "transfer-encoding",
    "cache-control",
    "etag",
    "expires",
    "pragma",
    "vary",
    "connection",
    "location",
    "x-powered-by",
    "via",
    "age",
    "accept-ranges",
    "allow",
    "link",
    "content-encoding",
)

SECURITY_HEADERS: tuple[str, ...] = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "expect-ct",
    "nel",
    "report-to",
    "clear-site-data",
    "origin-agent-cluster",
)

CORS_HEADERS: tuple[str, ...] = (
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "access-control-max-age",
)

CACHE_HEADERS: tuple[str, ...] = (
    "cache-control",
    "expires",
    "etag",
    "pragma",
    "age",
    "vary",
)
