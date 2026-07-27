"""Evidence models for analysis findings."""

from __future__ import annotations

from pydantic import Field

from techspecter.models.base import TechSpecterModel


class Evidence(TechSpecterModel):
    """Structured evidence supporting an analysis finding."""

    url: str | None = None
    file: str | None = None
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    snippet: str | None = None
    header: str | None = None
    cookie: str | None = None
    html_element: str | None = None
    javascript_location: str | None = None
