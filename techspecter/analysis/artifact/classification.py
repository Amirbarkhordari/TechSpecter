"""Passive artifact classification engine."""

from __future__ import annotations

from enum import StrEnum

from techspecter.models.artifact import ArtifactReference


class ArtifactClassification(StrEnum):
    """Standard artifact classification buckets."""

    SECRETS = "Secrets"
    AUTHENTICATION = "Authentication"
    CONFIGURATION = "Configuration"
    INFRASTRUCTURE = "Infrastructure"
    CLOUD = "Cloud"
    API = "API"
    IDENTITY = "Identity"
    DEVELOPMENT = "Development"
    BUILD = "Build"
    DEBUG = "Debug"
    BACKUP = "Backup"
    THIRD_PARTY = "Third Party"
    ANALYTICS = "Analytics"
    MONITORING = "Monitoring"
    FRAMEWORK = "Framework"
    METADATA = "Metadata"


_TYPE_CLASSIFICATION: dict[str, ArtifactClassification] = {
    # Secrets
    "aws-access-key": ArtifactClassification.SECRETS,
    "google-api-key": ArtifactClassification.SECRETS,
    "firebase-key": ArtifactClassification.SECRETS,
    "stripe-secret-key": ArtifactClassification.SECRETS,
    "github-token": ArtifactClassification.SECRETS,
    "gitlab-token": ArtifactClassification.SECRETS,
    "slack-token": ArtifactClassification.SECRETS,
    "discord-token": ArtifactClassification.SECRETS,
    "twilio-key": ArtifactClassification.SECRETS,
    "sendgrid-key": ArtifactClassification.SECRETS,
    "azure-key": ArtifactClassification.SECRETS,
    "webhook-token": ArtifactClassification.SECRETS,
    "high-entropy-token": ArtifactClassification.SECRETS,
    "private-key-header": ArtifactClassification.SECRETS,
    "jwt-token": ArtifactClassification.AUTHENTICATION,
    "bearer-token-ref": ArtifactClassification.AUTHENTICATION,
    "basic-auth-token": ArtifactClassification.AUTHENTICATION,
    "public-ssh-key": ArtifactClassification.SECRETS,
    "pem-block": ArtifactClassification.SECRETS,
    "certificate-block": ArtifactClassification.SECRETS,
    # Configuration
    "config-file-ref": ArtifactClassification.CONFIGURATION,
    "env-reference": ArtifactClassification.CONFIGURATION,
    "runtime-config": ArtifactClassification.CONFIGURATION,
    "frontend-config": ArtifactClassification.CONFIGURATION,
    "public-config": ArtifactClassification.CONFIGURATION,
    "app-config": ArtifactClassification.CONFIGURATION,
    "framework-config": ArtifactClassification.CONFIGURATION,
    "deployment-config": ArtifactClassification.CONFIGURATION,
    "client-config": ArtifactClassification.CONFIGURATION,
    "dotenv-reference": ArtifactClassification.CONFIGURATION,
    # Build
    "webpack-build": ArtifactClassification.BUILD,
    "vite-build": ArtifactClassification.BUILD,
    "rollup-build": ArtifactClassification.BUILD,
    "parcel-build": ArtifactClassification.BUILD,
    "nextjs-build": ArtifactClassification.BUILD,
    "nuxt-build": ArtifactClassification.BUILD,
    "angular-build": ArtifactClassification.BUILD,
    "react-build": ArtifactClassification.BUILD,
    "vue-build": ArtifactClassification.BUILD,
    "svelte-build": ArtifactClassification.BUILD,
    "remix-build": ArtifactClassification.BUILD,
    "astro-build": ArtifactClassification.BUILD,
    "build-id": ArtifactClassification.BUILD,
    "chunk-naming": ArtifactClassification.BUILD,
    "bundle-metadata": ArtifactClassification.BUILD,
    "version-metadata": ArtifactClassification.BUILD,
    "asset-manifest": ArtifactClassification.BUILD,
    # Debug
    "debug-comment": ArtifactClassification.DEBUG,
    "dev-banner": ArtifactClassification.DEBUG,
    "debug-endpoint": ArtifactClassification.DEBUG,
    "stack-trace": ArtifactClassification.DEBUG,
    "framework-debug": ArtifactClassification.DEBUG,
    "dev-mode": ArtifactClassification.DEBUG,
    "build-env": ArtifactClassification.DEBUG,
    # Backup
    "backup-filename": ArtifactClassification.BACKUP,
    "temp-file": ArtifactClassification.BACKUP,
    "archive-ref": ArtifactClassification.BACKUP,
    "old-config-ref": ArtifactClassification.BACKUP,
    "legacy-asset": ArtifactClassification.BACKUP,
    "deployment-leftover": ArtifactClassification.BACKUP,
    # Development / source / infra
    "dev-server": ArtifactClassification.DEVELOPMENT,
    "hot-reload": ArtifactClassification.DEVELOPMENT,
    "source-artifact": ArtifactClassification.METADATA,
    "infra-metadata": ArtifactClassification.INFRASTRUCTURE,
}

_CATEGORY_CLASSIFICATION: dict[str, ArtifactClassification] = {
    "secret": ArtifactClassification.SECRETS,
    "configuration": ArtifactClassification.CONFIGURATION,
    "build": ArtifactClassification.BUILD,
    "debug": ArtifactClassification.DEBUG,
    "backup": ArtifactClassification.BACKUP,
    "environment": ArtifactClassification.CONFIGURATION,
    "source": ArtifactClassification.METADATA,
    "client-config": ArtifactClassification.CONFIGURATION,
    "development": ArtifactClassification.DEVELOPMENT,
    "infrastructure": ArtifactClassification.INFRASTRUCTURE,
    "api": ArtifactClassification.API,
    "identity": ArtifactClassification.IDENTITY,
    "cloud": ArtifactClassification.CLOUD,
    "third-party": ArtifactClassification.THIRD_PARTY,
    "analytics": ArtifactClassification.ANALYTICS,
    "monitoring": ArtifactClassification.MONITORING,
    "technology": ArtifactClassification.FRAMEWORK,
    "token": ArtifactClassification.AUTHENTICATION,
}


class ClassificationEngine:
    """Classify passive artifact references into standard buckets."""

    def classify(self, reference: ArtifactReference) -> ArtifactClassification:
        """Return the classification bucket for an artifact reference."""
        if reference.artifact_type in _TYPE_CLASSIFICATION:
            return _TYPE_CLASSIFICATION[reference.artifact_type]
        if reference.category in _CATEGORY_CLASSIFICATION:
            return _CATEGORY_CLASSIFICATION[reference.category]
        return ArtifactClassification.METADATA

    def classify_all(
        self,
        references: list[ArtifactReference],
    ) -> dict[ArtifactClassification, list[ArtifactReference]]:
        """Group references by classification bucket."""
        grouped: dict[ArtifactClassification, list[ArtifactReference]] = {}
        for reference in references:
            bucket = self.classify(reference)
            grouped.setdefault(bucket, []).append(reference)
        return grouped
