"""JavaScript version detection engine."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from techspecter.fingerprinting.models import UNKNOWN_VERSION, DetectionResult, TechnologyMatch
from techspecter.models.discovery import DiscoveryResult
from techspecter.versioning.models import ExtractedVersion, TechnologyVersionResult
from techspecter.versioning.registry import VersionExtractorRegistry

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class JavaScriptResourceContent:
    """JavaScript content available for version extraction."""

    url: str
    filename: str
    content: str


@dataclass(slots=True)
class VersionDetectionEngine:
    """Detect library/framework versions from discovered JavaScript resources."""

    registry: VersionExtractorRegistry = field(default_factory=VersionExtractorRegistry)

    def enrich(
        self,
        detection: DetectionResult,
        discovery: DiscoveryResult,
    ) -> DetectionResult:
        """Apply version detection to fingerprint matches using discovery content."""
        resources = list(_collect_resources(discovery))
        if not resources:
            return detection

        enriched_matches: list[TechnologyMatch] = []
        resolved = 0

        for match in detection.matches:
            updated = self._resolve_match_version(match, resources)
            if updated.version != UNKNOWN_VERSION and match.version == UNKNOWN_VERSION:
                resolved += 1
            enriched_matches.append(updated)

        if resolved:
            logger.info(
                "Version detection resolved %d unknown versions for %s",
                resolved,
                detection.target_url,
            )

        return DetectionResult(
            target_url=detection.target_url,
            matches=enriched_matches,
            scripts_analyzed=detection.scripts_analyzed,
            elapsed_ms=detection.elapsed_ms,
        )

    def detect_for_technology(
        self,
        technology_id: str,
        resources: list[JavaScriptResourceContent],
    ) -> TechnologyVersionResult | None:
        """Detect the best version for one technology across resources."""
        extractor = self.registry.get(technology_id)
        if extractor is None:
            return None

        candidates: list[ExtractedVersion] = []
        for resource in resources:
            candidates.extend(
                extractor.extract(
                    resource.content,
                    url=resource.url,
                    filename=resource.filename,
                ),
            )

        if not candidates:
            return None

        candidates.sort(key=lambda item: (-item.confidence, item.version))
        best = candidates[0]
        rejected = sorted({item.version for item in candidates[1:] if item.version != best.version})

        return TechnologyVersionResult(
            technology_id=extractor.technology_id,
            version=best.version,
            confidence=best.confidence,
            confidence_level=best.confidence_level,
            method=best.method,
            reason=f"Selected via {best.method.value} ({best.confidence_level.value} confidence)",
            evidence=best.evidence,
            candidates_considered=len(candidates),
            rejected_candidates=rejected,
        )

    def _resolve_match_version(
        self,
        match: TechnologyMatch,
        resources: list[JavaScriptResourceContent],
    ) -> TechnologyMatch:
        """Resolve version for a single technology match."""
        existing_confidence = match.version_confidence or 0.0
        has_known_version = match.version not in (UNKNOWN_VERSION, "", None)

        if has_known_version and existing_confidence >= 90.0:
            return match

        result = self.detect_for_technology(match.technology.id, resources)
        if result is None:
            return match

        if has_known_version and existing_confidence >= result.confidence:
            return match

        evidence_sources = list(match.evidence_sources)
        if result.method.value not in evidence_sources:
            evidence_sources.append(result.method.value)

        return match.model_copy(
            update={
                "version": result.version,
                "version_source": result.method.value,
                "version_reason": result.reason,
                "version_confidence": result.confidence,
                "rejected_version_candidates": result.rejected_candidates,
                "evidence_sources": evidence_sources,
            },
        )


def _collect_resources(discovery: DiscoveryResult) -> list[JavaScriptResourceContent]:
    """Collect JavaScript content from discovery and index."""
    resources: list[JavaScriptResourceContent] = []
    seen_hashes: set[str] = set()

    if discovery.javascript_index is not None:
        for item in discovery.javascript_index.all_resources():
            if item.duplicate_of is not None:
                continue
            content = item.normalized_content or item.content
            if not content:
                continue
            content_hash = item.metadata.content_hash
            if content_hash in seen_hashes:
                continue
            seen_hashes.add(content_hash)
            resources.append(
                JavaScriptResourceContent(
                    url=item.url,
                    filename=item.metadata.filename,
                    content=content,
                ),
            )
        if resources:
            return resources

    for download in discovery.downloads:
        if not download.download_success or not download.content:
            continue
        resources.append(
            JavaScriptResourceContent(
                url=str(download.url),
                filename=download.filename,
                content=download.content,
            ),
        )

    for inline in discovery.inline_scripts:
        resources.append(
            JavaScriptResourceContent(
                url=f"inline://script/{inline.index}",
                filename=f"inline-{inline.index}.js",
                content=inline.content,
            ),
        )

    return resources
