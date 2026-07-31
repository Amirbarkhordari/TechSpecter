"""Adapter from JavaScript index to legacy DiscoveryResult."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from techspecter.javascript.index.javascript_index import JavaScriptPipelineResult
from techspecter.models.discovery import (
    DiscoveryResult,
    DownloadResult,
    InlineScript,
    ScriptResource,
    Target,
)
from techspecter.models.http import HttpResponseObservation
from techspecter.models.metadata import MetadataDiscoveryObservation

if TYPE_CHECKING:
    from techspecter.asset_discovery.models import AssetInventory


def to_discovery_result(
    *,
    target: Target,
    pipeline_result: JavaScriptPipelineResult,
    http_response: HttpResponseObservation | None = None,
    metadata_observation: MetadataDiscoveryObservation | None = None,
    asset_inventory: AssetInventory | None = None,
    elapsed_ms: float = 0.0,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
) -> DiscoveryResult:
    """Convert JavaScript pipeline output to backward-compatible DiscoveryResult."""
    index = pipeline_result.index
    external_scripts: list[ScriptResource] = []
    inline_scripts: list[InlineScript] = []
    downloads: list[DownloadResult] = []

    for resource in index.all_resources():
        if resource.inline:
            inline_scripts.append(
                InlineScript(
                    index=resource.inline_index or 0,
                    content=resource.content or "",
                    source_map_url=resource.metadata.source_map_url,
                ),
            )
            continue

        external_scripts.append(
            ScriptResource(
                url=resource.url,  # type: ignore[arg-type]
                original_url=resource.original_url,
            ),
        )
        downloads.append(
            DownloadResult(
                url=resource.url,  # type: ignore[arg-type]
                filename=resource.metadata.filename,
                status_code=resource.status_code,
                content_type=resource.content_type,
                encoding=resource.encoding,
                content_length=resource.metadata.content_length,
                download_success=resource.download_success,
                download_duration_ms=resource.download_duration_ms,
                error_message=resource.error_message,
                source_map_url=resource.metadata.source_map_url,
                content=resource.content,
            ),
        )

    return DiscoveryResult(
        target=target,
        external_scripts=external_scripts,
        inline_scripts=inline_scripts,
        downloads=downloads,
        http_response=http_response,
        metadata_observation=metadata_observation,
        javascript_index=index,
        asset_inventory=asset_inventory,
        elapsed_ms=elapsed_ms,
        started_at=started_at,
        completed_at=completed_at,
    )
