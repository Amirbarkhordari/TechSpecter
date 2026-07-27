"""Extended fixtures for sensitive artifact analysis tests."""

from __future__ import annotations

from techspecter.models.artifact import ArtifactReference
from tests.artifact_fixtures import sample_artifact_observation, sample_discovery_with_artifacts


def sample_sensitive_references() -> list[ArtifactReference]:
    """Return representative sensitive artifact references."""
    return [
        ArtifactReference(
            artifact_type="aws-access-key",
            category="secret",
            value="aws-access-key [redacted]",
            source="inline-script",
            location="inline-script:0",
            metadata={"redacted": True, "classification": "Secrets", "risk_level": "HIGH"},
        ),
        ArtifactReference(
            artifact_type="github-token",
            category="secret",
            value="github-token [redacted]",
            source="inline-script",
            location="inline-script:0",
            metadata={"redacted": True, "classification": "Secrets", "risk_level": "HIGH"},
        ),
        ArtifactReference(
            artifact_type="config-file-ref",
            category="configuration",
            value="config.json",
            source="html-link",
            location="https://example.com/",
        ),
        ArtifactReference(
            artifact_type="webpack-build",
            category="build",
            value="__webpack_require__",
            source="external-script",
            location="https://example.com/app.js",
        ),
        ArtifactReference(
            artifact_type="debug-endpoint",
            category="debug",
            value="/debug",
            source="inline-script",
            location="inline-script:1",
        ),
        ArtifactReference(
            artifact_type="backup-filename",
            category="backup",
            value=".bak",
            source="external-script-url",
            location="https://example.com/app.js.bak",
        ),
        ArtifactReference(
            artifact_type="env-reference",
            category="environment",
            value="process.env.API_URL",
            source="inline-script",
            location="inline-script:2",
        ),
        ArtifactReference(
            artifact_type="source-artifact",
            category="source",
            value="sourceMappingURL=",
            source="external-script",
            location="https://example.com/app.js",
        ),
        ArtifactReference(
            artifact_type="client-config",
            category="client-config",
            value="window.__APP_CONFIG__",
            source="inline-script",
            location="inline-script:3",
        ),
        ArtifactReference(
            artifact_type="dev-server",
            category="development",
            value="localhost:3000",
            source="inline-script",
            location="inline-script:4",
        ),
        ArtifactReference(
            artifact_type="infra-metadata",
            category="infrastructure",
            value="kubernetes",
            source="html-comment",
            location="https://example.com/",
        ),
    ]


def sample_discovery_with_sensitive_artifacts(**overrides: object):
    """Return discovery with sensitive artifact references."""
    observation = sample_artifact_observation()
    merged = observation.model_copy(
        update={
            "references": observation.references + sample_sensitive_references(),
        },
    )
    data: dict[str, object] = {"artifact_observation": merged}
    data.update(overrides)
    return sample_discovery_with_artifacts(**data)
