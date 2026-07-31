"""JavaScript pipeline configuration."""

from __future__ import annotations

from pydantic import Field

from techspecter.models.base import TechSpecterModel


class JavaScriptPipelineConfig(TechSpecterModel):
    """Configuration for the JavaScript discovery and preprocessing pipeline."""

    enabled: bool = True
    max_concurrency: int = Field(default=10, ge=1)
    max_resources: int = Field(default=200, ge=1)
    max_recursive_rounds: int = Field(default=20, ge=1)
    max_content_bytes: int = Field(default=5_242_880, ge=1)
    enable_recursive_discovery: bool = True
    enable_ast_preparation: bool = True
    enable_content_hash_dedup: bool = True
    cache_enabled: bool = True
