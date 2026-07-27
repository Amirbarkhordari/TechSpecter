"""URL validation, normalization, and resolution utilities."""

from __future__ import annotations

from typing import Final
from urllib.parse import urljoin, urlparse, urlunparse

from techspecter.exceptions import InvalidTargetUrlError

_ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})


def validate_url(url: str) -> str:
    """Validate and normalize a target URL.

    Args:
        url: Raw URL string provided by the user.

    Returns:
        Normalized absolute URL with scheme and netloc.

    Raises:
        InvalidTargetUrlError: If the URL is empty, malformed, or uses a disallowed scheme.
    """
    stripped = url.strip()
    if not stripped:
        msg = "URL must not be empty."
        raise InvalidTargetUrlError(msg)

    candidate = stripped if "://" in stripped else f"https://{stripped}"
    parsed = urlparse(candidate)

    if parsed.scheme not in _ALLOWED_SCHEMES:
        msg = f"Unsupported URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are allowed."
        raise InvalidTargetUrlError(msg)

    if not parsed.netloc:
        msg = f"Invalid URL '{url}': missing host."
        raise InvalidTargetUrlError(msg)

    return normalize_url(urlunparse(parsed))


def normalize_url(url: str) -> str:
    """Normalize a URL for consistent comparison and storage.

    Args:
        url: Absolute or relative URL string.

    Returns:
        Normalized URL string without trailing slash on the path root.
    """
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    normalized = urlunparse(
        (
            scheme,
            netloc,
            path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )
    return normalized


def resolve_url(base_url: str, reference: str) -> str:
    """Resolve a script reference to an absolute URL.

    Args:
        base_url: Base URL of the HTML document.
        reference: Script URL as found in HTML (absolute, relative, or protocol-relative).

    Returns:
        Normalized absolute URL.

    Raises:
        InvalidTargetUrlError: If the resolved URL is invalid or uses a disallowed scheme.
    """
    stripped = reference.strip()
    if not stripped:
        msg = "Script URL reference must not be empty."
        raise InvalidTargetUrlError(msg)

    if stripped.startswith("//"):
        base_scheme = urlparse(base_url).scheme or "https"
        stripped = f"{base_scheme}:{stripped}"

    absolute = urljoin(base_url, stripped)
    parsed = urlparse(absolute)

    if parsed.scheme not in _ALLOWED_SCHEMES:
        msg = f"Unsupported script URL scheme '{parsed.scheme}' for reference '{reference}'."
        raise InvalidTargetUrlError(msg)

    if not parsed.netloc:
        msg = f"Unable to resolve script URL '{reference}' against base '{base_url}'."
        raise InvalidTargetUrlError(msg)

    return normalize_url(absolute)


def filename_from_url(url: str) -> str:
    """Extract a filename from a URL path.

    Args:
        url: Absolute URL string.

    Returns:
        Filename derived from the URL path, or ``script.js`` when absent.
    """
    path = urlparse(url).path.rstrip("/")
    if not path:
        return "script.js"

    filename = path.rsplit("/", 1)[-1]
    return filename or "script.js"
