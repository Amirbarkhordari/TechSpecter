"""Shared helpers for passive HTTP analyzers."""

from __future__ import annotations

import re
from contextlib import suppress
from email.utils import parsedate_to_datetime

from techspecter.analysis.models.evidence import Evidence
from techspecter.analysis.models.finding import Finding, FindingCategory, Severity
from techspecter.models.discovery import DiscoveryResult
from techspecter.models.http import HttpCookieObservation, HttpResponseObservation

_COOKIE_ATTR = re.compile(r";\s*")
_PREFIX_HOST = "__Host-"
_PREFIX_SECURE = "__Secure-"


def normalize_header_name(name: str) -> str:
    """Normalize a header name to lowercase."""
    return name.strip().lower()


def get_http_observation(discovery: DiscoveryResult) -> HttpResponseObservation | None:
    """Return HTTP observation data from a discovery result."""
    return discovery.http_response


def build_http_finding(
    *,
    finding_id: str,
    analyzer_id: str,
    category: FindingCategory | str,
    title: str,
    description: str,
    severity: Severity = Severity.INFO,
    confidence: float = 100.0,
    recommendation: str | None = None,
    location: str | None = None,
    header: str | None = None,
    cookie: str | None = None,
    url: str | None = None,
    source: str = "passive-http-response",
    references: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> Finding:
    """Build a normalized HTTP finding."""
    evidence: list[Evidence] = []
    if header is not None:
        evidence.append(Evidence(header=header, url=url))
    if cookie is not None:
        evidence.append(Evidence(cookie=cookie, url=url))
    if url is not None and not evidence:
        evidence.append(Evidence(url=url))

    finding_metadata: dict[str, object] = {"source": source}
    if references:
        finding_metadata["references"] = references
    if metadata:
        finding_metadata.update(metadata)

    return Finding(
        id=finding_id,
        analyzer=analyzer_id,
        category=category,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        location=location,
        recommendation=recommendation,
        metadata=finding_metadata,
    )


def header_value(observation: HttpResponseObservation, header_name: str) -> str | None:
    """Return a header value using case-insensitive lookup."""
    return observation.headers.get(normalize_header_name(header_name))


def parse_set_cookie_header(raw_cookie: str) -> HttpCookieObservation:
    """Parse a Set-Cookie header into structured cookie metadata."""
    parts = _COOKIE_ATTR.split(raw_cookie.strip())
    name_value = parts[0]
    if "=" not in name_value:
        name, value = name_value, ""
    else:
        name, value = name_value.split("=", 1)

    attrs: dict[str, str] = {}
    for part in parts[1:]:
        if "=" in part:
            key, attr_value = part.split("=", 1)
            attrs[normalize_header_name(key)] = attr_value.strip()
        else:
            attrs[normalize_header_name(part)] = "true"

    host_prefix = _PREFIX_HOST if name.startswith(_PREFIX_HOST) else None
    secure_prefix = _PREFIX_SECURE if name.startswith(_PREFIX_SECURE) else None
    max_age: int | None = None
    if "max-age" in attrs:
        try:
            max_age = int(attrs["max-age"])
        except ValueError:
            max_age = None

    expires = attrs.get("expires")
    if expires:
        with suppress(TypeError, ValueError, OverflowError):
            parsedate_to_datetime(expires)

    return HttpCookieObservation(
        name=name.strip(),
        value=value.strip(),
        domain=attrs.get("domain"),
        path=attrs.get("path"),
        expires=expires,
        max_age=max_age,
        secure="secure" in attrs,
        httponly="httponly" in attrs,
        samesite=attrs.get("samesite"),
        priority=attrs.get("priority"),
        partitioned="partitioned" in attrs,
        host_prefix=host_prefix,
        secure_prefix=secure_prefix,
        raw=raw_cookie,
    )


def build_http_observation(
    *,
    url: str,
    final_url: str,
    status_code: int,
    headers: dict[str, str],
    raw_headers: dict[str, str],
    set_cookies: list[str],
    redirects: list[tuple[str, int, str | None]],
    content_type: str | None,
    encoding: str | None,
    body_size: int,
    elapsed_ms: float | None,
) -> HttpResponseObservation:
    """Build an HTTP response observation from downloader output."""
    normalized = {normalize_header_name(key): value for key, value in headers.items()}
    cookies = [parse_set_cookie_header(item) for item in set_cookies]
    redirect_hops = [
        {"url": hop_url, "status_code": hop_status, "location": hop_location}
        for hop_url, hop_status, hop_location in redirects
    ]
    from techspecter.models.http import HttpRedirectHop

    return HttpResponseObservation(
        url=url,
        final_url=final_url,
        status_code=status_code,
        headers=normalized,
        raw_headers=raw_headers,
        cookies=cookies,
        redirects=[HttpRedirectHop.model_validate(item) for item in redirect_hops],
        content_type=content_type or normalized.get("content-type"),
        content_length=_safe_int(normalized.get("content-length")),
        content_encoding=normalized.get("content-encoding"),
        transfer_encoding=normalized.get("transfer-encoding"),
        protocol="HTTP/1.1",
        elapsed_ms=elapsed_ms,
        body_size=body_size if body_size else _safe_int(normalized.get("content-length")) or 0,
    )


def _safe_int(value: str | None) -> int | None:
    """Parse an integer value safely."""
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None
