"""Tests for sensitive artifact extraction."""

from __future__ import annotations

from techspecter.analysis.artifact.sensitive_extractor import SensitiveArtifactExtractor
from techspecter.models.discovery import DiscoveryResult, InlineScript, Target


def test_sensitive_extractor_detects_aws_and_github_tokens() -> None:
    """Sensitive extractor should detect AWS and GitHub token patterns."""
    discovery = DiscoveryResult(
        target=Target(original_url="https://example.com", url="https://example.com/"),
        inline_scripts=[
            InlineScript(
                index=0,
                content=(
                    "const key='AKIAIOSFODNN7EXAMPLE'; "
                    "const gh='ghp_1234567890abcdefghijklmnopqrstuvwxyz';"
                ),
            ),
        ],
    )
    references = SensitiveArtifactExtractor().extract(discovery)
    types = {item.artifact_type for item in references}
    assert "aws-access-key" in types
    assert "github-token" in types


def test_sensitive_extractor_detects_build_and_debug() -> None:
    """Sensitive extractor should detect build and debug indicators."""
    discovery = DiscoveryResult(
        target=Target(original_url="https://example.com", url="https://example.com/"),
        inline_scripts=[
            InlineScript(
                index=0,
                content="__webpack_require__; fetch('/debug'); NODE_ENV='development'",
            ),
        ],
    )
    references = SensitiveArtifactExtractor().extract(discovery)
    types = {item.artifact_type for item in references}
    assert "webpack-build" in types
    assert "debug-endpoint" in types
    assert "dev-mode" in types
