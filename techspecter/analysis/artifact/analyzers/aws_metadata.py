"""AWS metadata artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.typed_base import TypedArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class AwsMetadataAnalyzer(TypedArtifactAnalyzer):
    """Detect passive AWS cloud metadata indicators."""

    artifact_types = ("aws", "s3", "cloudfront")
    display_name = "AWS"
    finding_category = FindingCategory.INFRASTRUCTURE

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="aws-metadata-analyzer",
            name="AWS Metadata Analyzer",
            version="1.0.0",
            description="Detects passive AWS, S3, and CloudFront references.",
            category=FindingCategory.INFRASTRUCTURE.value,
        )
