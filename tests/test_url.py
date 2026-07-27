"""Tests for URL validation and resolution utilities."""

from __future__ import annotations

import pytest

from techspecter.exceptions import ValidationError
from techspecter.utils.url import filename_from_url, normalize_url, resolve_url, validate_url


def test_validate_url_adds_https_scheme() -> None:
    """Verify bare hostnames receive an HTTPS scheme."""
    assert validate_url("example.com") == "https://example.com/"


def test_validate_url_normalizes_existing_https_url() -> None:
    """Verify fully qualified HTTPS URLs are normalized."""
    assert validate_url("https://Example.com/app/") == "https://example.com/app"


def test_validate_url_rejects_empty_string() -> None:
    """Verify empty URLs raise ValidationError."""
    with pytest.raises(ValidationError, match="must not be empty"):
        validate_url("   ")


def test_validate_url_rejects_unsupported_scheme() -> None:
    """Verify non-HTTP schemes are rejected."""
    with pytest.raises(ValidationError, match="Unsupported URL scheme"):
        validate_url("ftp://example.com")


def test_resolve_url_handles_relative_paths() -> None:
    """Verify relative script paths resolve against a base URL."""
    assert resolve_url("https://example.com/app/page", "/js/main.js") == (
        "https://example.com/js/main.js"
    )


def test_resolve_url_handles_parent_relative_paths() -> None:
    """Verify parent-relative paths resolve correctly."""
    assert resolve_url("https://example.com/app/page", "../js/main.js") == (
        "https://example.com/js/main.js"
    )


def test_resolve_url_handles_protocol_relative_urls() -> None:
    """Verify protocol-relative URLs inherit the base scheme."""
    assert resolve_url("https://example.com", "//cdn.example.com/lib.js") == (
        "https://cdn.example.com/lib.js"
    )


def test_normalize_url_lowercases_host_and_scheme() -> None:
    """Verify URL normalization lowercases scheme and host."""
    assert normalize_url("HTTPS://Example.COM/Path") == "https://example.com/Path"


def test_filename_from_url_extracts_basename() -> None:
    """Verify filename extraction uses the URL path basename."""
    assert filename_from_url("https://example.com/assets/app.js?v=1") == "app.js"


def test_filename_from_url_uses_default_for_empty_path() -> None:
    """Verify a default filename is returned for empty paths."""
    assert filename_from_url("https://example.com") == "script.js"
