"""Tests for the fingerprint detection pipeline."""

from __future__ import annotations

from techspecter.fingerprints.pipeline import FingerprintPipeline
from techspecter.models.discovery import (
    DiscoveryResult,
    DownloadResult,
    InlineScript,
    Target,
)


def test_fingerprint_pipeline_analyzes_downloads_and_inline_scripts() -> None:
    """Verify the pipeline analyzes both external and inline JavaScript."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com", original_url="https://example.com"),  # type: ignore[arg-type]
        downloads=[
            DownloadResult(
                url="https://example.com/react.js",  # type: ignore[arg-type]
                filename="react.js",
                download_success=True,
                content='React.version="18.2.0"; React.createElement("div");',
            )
        ],
        inline_scripts=[
            InlineScript(index=0, content="jQuery.fn.jquery = '3.7.1'; window.jQuery = jQuery;")
        ],
    )
    result = FingerprintPipeline().run(discovery)
    ids = {match.technology.id for match in result.matches}
    assert result.scripts_analyzed == 2
    assert "react" in ids
    assert "jquery" in ids
