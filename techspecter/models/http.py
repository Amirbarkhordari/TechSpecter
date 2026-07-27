"""HTTP observation models for passive analysis."""

from __future__ import annotations

from pydantic import Field

from techspecter.models.base import TechSpecterModel


class HttpCookieObservation(TechSpecterModel):
    """Parsed cookie observation from a passive HTTP response."""

    name: str
    value: str
    domain: str | None = None
    path: str | None = None
    expires: str | None = None
    max_age: int | None = None
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None
    priority: str | None = None
    partitioned: bool = False
    host_prefix: str | None = None
    secure_prefix: str | None = None
    raw: str


class HttpRedirectHop(TechSpecterModel):
    """Single hop in a passive redirect chain."""

    url: str
    status_code: int
    location: str | None = None


class HttpResponseObservation(TechSpecterModel):
    """Passive HTTP response metadata captured during discovery."""

    url: str
    final_url: str
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    raw_headers: dict[str, str] = Field(default_factory=dict)
    cookies: list[HttpCookieObservation] = Field(default_factory=list)
    redirects: list[HttpRedirectHop] = Field(default_factory=list)
    content_type: str | None = None
    content_length: int | None = None
    content_encoding: str | None = None
    transfer_encoding: str | None = None
    protocol: str = "HTTP/1.1"
    elapsed_ms: float | None = None
    body_size: int = 0
