"""Tests for passive artifact extraction."""

from __future__ import annotations

from techspecter.analysis.artifact.extractor import ArtifactExtractor
from techspecter.models.discovery import DiscoveryResult, InlineScript, Target
from techspecter.models.http import HttpResponseObservation


def test_extractor_detects_graphql_and_jwt() -> None:
    """Extractor should detect GraphQL and JWT patterns in inline scripts."""
    discovery = DiscoveryResult(
        target=Target(original_url="https://example.com", url="https://example.com/"),
        inline_scripts=[
            InlineScript(
                index=0,
                content=(
                    "fetch('/graphql'); "
                    "const t='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                    "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';"
                ),
            ),
        ],
        http_response=HttpResponseObservation(
            url="https://example.com/",
            final_url="https://example.com/",
            status_code=200,
            headers={"server": "cloudflare"},
        ),
    )
    observation = ArtifactExtractor().extract(discovery)
    types = {item.artifact_type for item in observation.references}
    assert "graphql" in types
    assert "jwt" in types
    assert "cloudflare" in types


def test_extractor_detects_oauth_and_openapi() -> None:
    """Extractor should detect OAuth and OpenAPI references."""
    discovery = DiscoveryResult(
        target=Target(original_url="https://example.com", url="https://example.com/"),
        inline_scripts=[
            InlineScript(
                index=0,
                content="window.location='/oauth2/authorize'; swagger-ui bundle",
            ),
        ],
    )
    observation = ArtifactExtractor().extract(discovery)
    types = {item.artifact_type for item in observation.references}
    assert "oauth" in types
    assert "swagger-ui" in types
