"""Tests for discovery data models."""

from __future__ import annotations

from techspecter.models.discovery import (
    DiscoveryResult,
    DownloadResult,
    InlineScript,
    ScriptResource,
    Target,
)


def test_discovery_result_counts() -> None:
    """Verify discovery result helper properties compute expected counts."""
    result = DiscoveryResult(
        target=Target(url="https://example.com", original_url="example.com"),  # type: ignore[arg-type]
        external_scripts=[
            ScriptResource(url="https://example.com/a.js", original_url="/a.js"),  # type: ignore[arg-type]
        ],
        inline_scripts=[InlineScript(index=0, content="console.log(1);")],
        downloads=[
            DownloadResult(
                url="https://example.com/a.js",  # type: ignore[arg-type]
                filename="a.js",
                download_success=True,
            ),
            DownloadResult(
                url="https://example.com/b.js",  # type: ignore[arg-type]
                filename="b.js",
                download_success=False,
                error_message="timeout",
            ),
        ],
    )

    assert result.discovered_count == 2
    assert result.downloaded_count == 1
    assert result.failed_count == 1


def test_target_model_requires_valid_url() -> None:
    """Verify Target model stores normalized URL values."""
    target = Target(url="https://example.com", original_url="example.com")  # type: ignore[arg-type]
    assert str(target.url) == "https://example.com/"
    assert target.original_url == "example.com"
