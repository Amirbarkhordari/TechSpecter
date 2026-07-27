"""Shared fixtures for HTTP passive analysis tests."""

from __future__ import annotations

from techspecter.models.discovery import DiscoveryResult, Target
from techspecter.models.http import HttpCookieObservation, HttpRedirectHop, HttpResponseObservation


def sample_http_observation(**overrides: object) -> HttpResponseObservation:
    """Return a representative HTTP response observation."""
    data = {
        "url": "https://example.com",
        "final_url": "https://example.com/",
        "status_code": 200,
        "headers": {
            "server": "nginx",
            "content-type": "text/html; charset=utf-8",
            "content-length": "1234",
            "cache-control": "no-cache",
            "set-cookie": "session=abc; Path=/; HttpOnly; Secure",
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "access-control-allow-origin": "https://example.com",
        },
        "raw_headers": {
            "Server": "nginx",
            "Content-Type": "text/html; charset=utf-8",
        },
        "cookies": [
            HttpCookieObservation(
                name="session",
                value="abc",
                path="/",
                secure=True,
                httponly=True,
                raw="session=abc; Path=/; HttpOnly; Secure",
            )
        ],
        "redirects": [
            HttpRedirectHop(
                url="https://example.com",
                status_code=301,
                location="https://example.com/",
            )
        ],
        "content_type": "text/html; charset=utf-8",
        "content_length": 1234,
        "body_size": 1234,
        "elapsed_ms": 42.0,
    }
    data.update(overrides)
    return HttpResponseObservation(**data)  # type: ignore[arg-type]


def sample_discovery_with_http(**overrides: object) -> DiscoveryResult:
    """Return a discovery result containing HTTP observation data."""
    data = {
        "target": Target(original_url="https://example.com", url="https://example.com/"),
        "http_response": sample_http_observation(),
        "elapsed_ms": 100.0,
    }
    data.update(overrides)
    return DiscoveryResult(**data)  # type: ignore[arg-type]
