"""JavaScript version detection engine."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from techspecter.fingerprinting.models import UNKNOWN_VERSION, DetectionResult, TechnologyMatch
from techspecter.models.discovery import DiscoveryResult
from techspecter.versioning.adapters import (
    resolve_extracted_versions,
    technology_version_result_from_resolution,
)
from techspecter.versioning.models import TechnologyVersionResult
from techspecter.versioning.registry import VersionExtractorRegistry
from techspecter.versioning.validator import is_valid_version

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class JavaScriptResourceContent:
    """JavaScript content available for version extraction."""

    url: str
    filename: str
    content: str


@dataclass(slots=True)
class VersionDetectionEngine:
    """Detect library/framework versions from discovered JavaScript resources.

    Extractors only produce version evidence. Final primary/alternate selection is
    always performed by the canonical ``resolve_primary_version`` path.
    """

    registry: VersionExtractorRegistry = field(default_factory=VersionExtractorRegistry)

    def enrich(
        self,
        detection: DetectionResult,
        discovery: DiscoveryResult,
    ) -> DetectionResult:
        """Apply version detection to fingerprint matches using discovery content."""
        resources = list(_collect_resources(discovery))
        logger.info(
            "Version detection starting for %s: %d technologies, %d javascript resources",
            detection.target_url,
            len(detection.matches),
            len(resources),
        )
        if not resources:
            logger.warning(
                "Version detection skipped for %s: no javascript content available",
                detection.target_url,
            )
            return DetectionResult(
                target_url=detection.target_url,
                matches=[_sanitize_match_version(match) for match in detection.matches],
                ignored_matches=detection.ignored_matches,
                scripts_analyzed=detection.scripts_analyzed,
                elapsed_ms=detection.elapsed_ms,
            )

        enriched_matches: list[TechnologyMatch] = []
        resolved = 0

        for match in detection.matches:
            logger.debug(
                "Version detection processing technology=%s current_version=%s",
                match.technology.id,
                match.version,
            )
            updated = self._resolve_match_version(match, resources)
            if updated.version != UNKNOWN_VERSION and match.version == UNKNOWN_VERSION:
                resolved += 1
                logger.info(
                    "Version detection resolved %s -> %s (confidence=%.1f source=%s)",
                    match.technology.id,
                    updated.version,
                    updated.version_confidence or 0.0,
                    updated.version_source,
                )
            elif updated.version == UNKNOWN_VERSION:
                logger.debug(
                    "Version detection left %s as Unknown (no extractor or no candidates)",
                    match.technology.id,
                )
            enriched_matches.append(updated)

        logger.info(
            "Version detection finished for %s: resolved %d/%d unknown versions",
            detection.target_url,
            resolved,
            sum(1 for item in detection.matches if item.version == UNKNOWN_VERSION),
        )

        return DetectionResult(
            target_url=detection.target_url,
            matches=enriched_matches,
            ignored_matches=detection.ignored_matches,
            scripts_analyzed=detection.scripts_analyzed,
            elapsed_ms=detection.elapsed_ms,
        )

    def detect_for_technology(
        self,
        technology_id: str,
        resources: list[JavaScriptResourceContent],
        *,
        technology_confidence: float | None = None,
        preferred_source_url: str | None = None,
        preferred_filename: str | None = None,
    ) -> TechnologyVersionResult | None:
        """Extract JS version evidence and resolve via the canonical resolver."""
        extractor = self.registry.get(technology_id)
        if extractor is None:
            logger.debug(
                "Version detection has no extractor registered for technology=%s",
                technology_id,
            )
            return None

        logger.debug(
            "Version detection selected extractor=%s for technology=%s",
            extractor.technology_id,
            technology_id,
        )

        extracted = []
        for resource in resources:
            found = extractor.extract(
                resource.content,
                url=resource.url,
                filename=resource.filename,
            )
            if found:
                logger.debug(
                    "Version detection extractor=%s found %d candidate(s) in %s",
                    extractor.technology_id,
                    len(found),
                    resource.filename,
                )
                for item in found:
                    extracted.append(
                        item.model_copy(
                            update={
                                "technology_id": technology_id,
                                "source_url": item.source_url or resource.url,
                                "filename": item.filename or resource.filename,
                            },
                        ),
                    )

        if not extracted:
            logger.debug(
                "Version detection extractor=%s found no candidates for technology=%s",
                extractor.technology_id,
                technology_id,
            )
            return None

        outcome = resolve_extracted_versions(
            extracted,
            technology_id=technology_id,
            technology_confidence=technology_confidence,
            preferred_source_urls=(preferred_source_url,) if preferred_source_url else (),
            preferred_filenames=(preferred_filename,) if preferred_filename else (),
        )
        result = technology_version_result_from_resolution(
            technology_id=extractor.technology_id,
            extracted=extracted,
            outcome=outcome,
        )
        if result is None:
            return None

        logger.debug(
            "Version detection canonically resolved technology=%s version=%s "
            "(conflict=%s alternates=%s candidates=%d)",
            technology_id,
            result.version,
            result.conflict_class,
            result.alternate_versions,
            result.candidates_considered,
        )
        return result

    def _resolve_match_version(
        self,
        match: TechnologyMatch,
        resources: list[JavaScriptResourceContent],
    ) -> TechnologyMatch:
        """Resolve version for a single technology match via canonical resolution."""
        match = _sanitize_match_version(match)
        existing_confidence = match.version_confidence or 0.0
        has_known_version = match.version not in (UNKNOWN_VERSION, "", None)

        if has_known_version and existing_confidence >= 90.0:
            logger.debug(
                "Version detection preserving existing version for %s: %s (confidence=%.1f)",
                match.technology.id,
                match.version,
                existing_confidence,
            )
            return match

        result = self.detect_for_technology(
            match.technology.id,
            resources_for_match(match, resources),
            technology_confidence=match.confidence,
            preferred_source_url=match.source_url,
            preferred_filename=match.filename or match.source_file,
        )
        if result is None:
            return match

        if result.version in (UNKNOWN_VERSION, "", None):
            if has_known_version:
                return match.model_copy(
                    update={
                        "alternate_versions": sorted(
                            {
                                *match.alternate_versions,
                                *result.alternate_versions,
                            },
                        ),
                        "rejected_version_candidates": sorted(
                            {
                                *match.rejected_version_candidates,
                                *result.rejected_candidates,
                            },
                        ),
                    },
                )
            return match.model_copy(
                update={
                    "version": UNKNOWN_VERSION,
                    "version_source": result.method.value,
                    "version_reason": result.reason,
                    "version_confidence": result.version_confidence or 0.0,
                    "alternate_versions": list(result.alternate_versions),
                    "rejected_version_candidates": list(result.rejected_candidates),
                },
            )

        if has_known_version and existing_confidence >= result.confidence:
            logger.debug(
                "Version detection kept existing version for %s over candidate %s",
                match.technology.id,
                result.version,
            )
            return match.model_copy(
                update={
                    "alternate_versions": sorted(
                        {
                            *match.alternate_versions,
                            *result.alternate_versions,
                            result.version,
                        }
                        - {match.version},
                    ),
                },
            )

        evidence_sources = list(match.evidence_sources)
        if result.method.value not in evidence_sources:
            evidence_sources.append(result.method.value)

        return match.model_copy(
            update={
                "version": result.version,
                "version_source": result.method.value,
                "version_reason": result.reason,
                "version_confidence": result.confidence,
                "rejected_version_candidates": list(result.rejected_candidates),
                "alternate_versions": list(result.alternate_versions),
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
            logger.debug(
                "Version detection collected %d resources from javascript_index",
                len(resources),
            )
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

    logger.debug(
        "Version detection collected %d resources from legacy discovery downloads/inline scripts",
        len(resources),
    )
    return resources


def collect_javascript_resources(
    discovery: DiscoveryResult,
) -> list[JavaScriptResourceContent]:
    """Collect JavaScript resources from a discovery result."""
    return _collect_resources(discovery)


def resources_for_match(
    match: TechnologyMatch,
    resources: list[JavaScriptResourceContent],
) -> list[JavaScriptResourceContent]:
    """Limit version extraction to assets that contributed to the technology match."""
    scope_urls: set[str] = set()
    scope_filenames: set[str] = set()

    if match.source_url:
        scope_urls.add(match.source_url.strip())
    if match.filename:
        scope_filenames.add(match.filename.strip())
    if match.source_file:
        scope_filenames.add(match.source_file.strip())

    for resource in match.matched_resources:
        value = resource.strip()
        if not value:
            continue
        if "://" in value or value.startswith("/"):
            scope_urls.add(value)
        else:
            scope_filenames.add(value.rsplit("/", 1)[-1])

    for item in match.evidence:
        if item.source_file:
            scope_filenames.add(item.source_file.strip())

    if not scope_urls and not scope_filenames:
        # Matches without asset provenance still need a chance to resolve versions
        # from available JS content. Ownership/affinity gates prevent incidental
        # cross-asset mentions from becoming false strong conflicts.
        return list(resources)

    scoped: list[JavaScriptResourceContent] = []
    seen: set[tuple[str, str]] = set()
    for resource in resources:
        key = (resource.url, resource.filename)
        if key in seen:
            continue
        if resource.url in scope_urls or resource.filename in scope_filenames:
            seen.add(key)
            scoped.append(resource)
    return scoped


def _sanitize_match_version(match: TechnologyMatch) -> TechnologyMatch:
    """Drop invalid placeholder versions while preserving technology detection."""
    if match.version in (UNKNOWN_VERSION, "", None):
        return match
    if is_valid_version(match.version):
        return match
    rejected = sorted({match.version, *match.rejected_version_candidates})
    logger.debug(
        "Version detection rejected invalid version for %s: %s",
        match.technology.id,
        match.version,
    )
    return match.model_copy(
        update={
            "version": UNKNOWN_VERSION,
            "version_source": None,
            "version_reason": "Rejected invalid or placeholder version candidate",
            "version_confidence": None,
            "rejected_version_candidates": rejected,
        },
    )
