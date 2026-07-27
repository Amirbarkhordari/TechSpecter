"""Tests for HTTP helper utilities."""

from __future__ import annotations

from techspecter.analysis.http.helpers import build_http_observation, parse_set_cookie_header


def test_parse_set_cookie_header_extracts_attributes() -> None:
    """Set-Cookie parser should extract security attributes."""
    cookie = parse_set_cookie_header(
        "__Host-session=abc; Path=/; Secure; HttpOnly; SameSite=Strict; Partitioned"
    )
    assert cookie.name == "__Host-session"
    assert cookie.host_prefix == "__Host-"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "Strict"
    assert cookie.partitioned is True


def test_build_http_observation_normalizes_headers() -> None:
    """HTTP observation builder should normalize header names."""
    observation = build_http_observation(
        url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        headers={"Server": "nginx", "Content-Type": "text/html"},
        raw_headers={"Server": "nginx", "Content-Type": "text/html"},
        set_cookies=["session=1; Path=/"],
        redirects=[("https://example.com", 301, "https://example.com/")],
        content_type="text/html",
        encoding="utf-8",
        body_size=100,
        elapsed_ms=12.5,
    )
    assert observation.headers["server"] == "nginx"
    assert observation.headers["content-type"] == "text/html"
    assert len(observation.cookies) == 1
    assert observation.redirects[0].status_code == 301
