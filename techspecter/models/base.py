"""Base Pydantic model for TechSpecter data structures."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class TechSpecterModel(BaseModel):
    """Base model with shared configuration for all TechSpecter schemas."""

    model_config = ConfigDict(
        strict=False,
        extra="forbid",
        validate_assignment=True,
        populate_by_name=True,
    )
