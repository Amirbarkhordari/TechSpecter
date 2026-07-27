"""Shared fixtures for artifact analysis tests."""

from __future__ import annotations

from techspecter.models.artifact import ArtifactDiscoveryObservation, ArtifactReference
from techspecter.models.discovery import DiscoveryResult, InlineScript
from techspecter.models.http import HttpResponseObservation
from tests.metadata_fixtures import sample_discovery_with_metadata


def sample_artifact_references() -> list[ArtifactReference]:
    """Return representative artifact references."""
    return [
        ArtifactReference(
            artifact_type="graphql",
            category="api",
            value="/graphql",
            source="inline-script",
            location="inline-script:0",
            snippet="fetch('/graphql')",
        ),
        ArtifactReference(
            artifact_type="openapi",
            category="api",
            value="swagger-ui",
            source="external-script-url",
            location="https://example.com/swagger-ui",
        ),
        ArtifactReference(
            artifact_type="oauth",
            category="identity",
            value="oauth2/authorize",
            source="html-link",
            location="https://example.com/",
        ),
        ArtifactReference(
            artifact_type="oidc",
            category="identity",
            value=".well-known/openid-configuration",
            source="well-known:security.txt",
            location="https://example.com/.well-known/openid-configuration",
        ),
        ArtifactReference(
            artifact_type="jwt",
            category="token",
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            source="inline-script",
            location="inline-script:1",
            metadata={"redacted": True},
        ),
        ArtifactReference(
            artifact_type="api-key",
            category="token",
            value="api-key [redacted]",
            source="inline-script",
            location="inline-script:2",
            metadata={"redacted": True},
        ),
        ArtifactReference(
            artifact_type="aws",
            category="cloud",
            value="s3.amazonaws.com",
            source="external-script-url",
            location="https://bucket.s3.amazonaws.com/app.js",
        ),
        ArtifactReference(
            artifact_type="azure",
            category="cloud",
            value="blob.core.windows.net",
            source="html-link",
            location="https://example.com/",
        ),
        ArtifactReference(
            artifact_type="gcp",
            category="cloud",
            value="googleapis.com",
            source="external-script-url",
            location="https://storage.googleapis.com/app.js",
        ),
        ArtifactReference(
            artifact_type="firebase",
            category="cloud",
            value="firebaseConfig",
            source="inline-script",
            location="inline-script:3",
        ),
        ArtifactReference(
            artifact_type="cloudflare",
            category="cloud",
            value="cloudflare",
            source="http-headers",
            location="https://example.com/",
        ),
        ArtifactReference(
            artifact_type="google-analytics",
            category="analytics",
            value="google-analytics.com",
            source="inline-script",
            location="inline-script:4",
        ),
        ArtifactReference(
            artifact_type="sentry",
            category="monitoring",
            value="sentry.io",
            source="inline-script",
            location="inline-script:5",
        ),
        ArtifactReference(
            artifact_type="stripe",
            category="third-party",
            value="stripe.com",
            source="inline-script",
            location="inline-script:6",
        ),
        ArtifactReference(
            artifact_type="technology-exposure",
            category="technology",
            value="webpack",
            source="external-script",
            location="https://example.com/app.js",
        ),
    ]


def sample_artifact_observation(**overrides: object) -> ArtifactDiscoveryObservation:
    """Return a full artifact discovery observation."""
    data = {
        "references": sample_artifact_references(),
        "sources_scanned": ["inline-script", "http-headers", "html-metadata"],
    }
    data.update(overrides)
    return ArtifactDiscoveryObservation(**data)  # type: ignore[arg-type]


def sample_discovery_with_artifacts(**overrides: object) -> DiscoveryResult:
    """Return a discovery result with artifact observation."""
    base = sample_discovery_with_metadata()
    data = {
        "target": base.target,
        "metadata_observation": base.metadata_observation,
        "http_response": HttpResponseObservation(
            url="https://example.com/",
            final_url="https://example.com/",
            status_code=200,
            headers={"server": "cloudflare", "x-powered-by": "Express"},
        ),
        "inline_scripts": [
            InlineScript(
                index=0,
                content=(
                    "fetch('/graphql'); "
                    "const token='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                    "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'; "
                    "api_key='sk_test_1234567890'; "
                    "firebaseConfig={}; "
                    "gtag('config','GA-123'); "
                    "Sentry.init({dsn:'https://abc@sentry.io/1'}); "
                    "Stripe('pk_live_abc');"
                ),
            ),
        ],
        "artifact_observation": sample_artifact_observation(),
        "elapsed_ms": 100.0,
    }
    data.update(overrides)
    return DiscoveryResult(**data)  # type: ignore[arg-type]
