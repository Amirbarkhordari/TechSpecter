"""Technology evidence construction from detection outputs."""

from __future__ import annotations

import logging
from uuid import uuid4

from techspecter.fingerprinting.evidence.models import Evidence, EvidenceCollection
from techspecter.fingerprinting.models import PatternEvidence, TechnologyMatch
from techspecter.technology_intelligence.attribution import AssetAttributor
from techspecter.technology_intelligence.models import (
    DiscoveryMethod,
    IntelligenceEvidenceType,
    TechnologyEvidenceRecord,
    VersionAttributionRecord,
)
from techspecter.versioning.models import TechnologyVersionResult, VersionEvidence

logger = logging.getLogger(__name__)

_DETECTOR_NAME = "techspecter-fingerprint"
_EVIDENCE_DETECTOR = "techspecter-evidence"
_PROVIDER_PREFIXES = frozenset({"techspecter", "wappalyzer", "retirejs"})
_CATEGORY_PREFIXES = frozenset(
    {
        "runtime",
        "javascript",
        "html",
        "headers",
        "wappalyzer",
        "retirejs",
        "resource",
        "source",
        "filename",
        "other",
    },
)


def build_evidence_from_match(
    match: TechnologyMatch,
    *,
    attributor: AssetAttributor,
    detected_at: object | None = None,
) -> list[TechnologyEvidenceRecord]:
    """Build evidence records from a technology match and pattern evidence."""
    records: list[TechnologyEvidenceRecord] = []
    source_url = match.source_url
    source_file = attributor.source_file(source_url, match.filename)
    asset_id = attributor.asset_id(source_url)
    discovery = _map_discovery_method(attributor.discovery_method(source_url))

    for pattern in match.evidence:
        records.append(
            _pattern_evidence(
                match=match,
                pattern=pattern,
                source_url=source_url,
                source_file=source_file,
                asset_id=asset_id,
                discovery_method=discovery,
                detected_at=detected_at,
            ),
        )

    for resource_url in match.matched_resources:
        if resource_url == source_url:
            continue
        resource_file = attributor.source_file(resource_url)
        resource_asset = attributor.asset_id(resource_url)
        resource_discovery = _map_discovery_method(attributor.discovery_method(resource_url))
        for pattern in match.evidence:
            records.append(
                _pattern_evidence(
                    match=match,
                    pattern=pattern,
                    source_url=resource_url,
                    source_file=resource_file,
                    asset_id=resource_asset,
                    discovery_method=resource_discovery,
                    detected_at=detected_at,
                ),
            )

    if not records and (source_url or match.filename):
        if match.matched_patterns:
            fallback_pattern = match.matched_patterns[0]
            synthetic = PatternEvidence(
                matcher="string",
                pattern=fallback_pattern,
                weight=match.confidence,
                detail=match.detection_reason,
            )
            matched_pattern = _strip_evidence_prefixes(fallback_pattern)
            matched_text = _resolve_matched_text(synthetic)
        else:
            matched_pattern = None
            matched_text = match.detection_reason
        records.append(
            TechnologyEvidenceRecord(
                evidence_id=str(uuid4()),
                technology_name=match.technology.name,
                category=match.technology.category,
                version=match.version if match.version != "Unknown" else None,
                confidence=match.confidence,
                detector_name=_DETECTOR_NAME,
                evidence_type=IntelligenceEvidenceType.PATTERN_MATCH,
                matched_pattern=matched_pattern,
                matched_text=matched_text,
                source_file=source_file,
                source_url=source_url,
                source_asset_id=asset_id,
                discovery_method=discovery,
            ),
        )

    logger.debug(
        "Built %d evidence records from match for %s",
        len(records),
        match.technology.id,
    )
    return records


def build_evidence_from_collection(
    match: TechnologyMatch,
    collection: EvidenceCollection,
    *,
    attributor: AssetAttributor,
) -> list[TechnologyEvidenceRecord]:
    """Build evidence from fingerprint evidence collection items."""
    if not match.supporting_evidence_ids:
        return []

    id_set = set(match.supporting_evidence_ids)
    records: list[TechnologyEvidenceRecord] = []
    for item in collection.items:
        if item.id not in id_set:
            continue
        records.append(_fingerprint_evidence_item(item, match=match, attributor=attributor))

    logger.debug(
        "Built %d collection evidence records for %s",
        len(records),
        match.technology.id,
    )
    return records


def build_version_attribution(
    match: TechnologyMatch,
    version_result: TechnologyVersionResult | None,
    *,
    attributor: AssetAttributor,
) -> VersionAttributionRecord | None:
    """Build version attribution from version detection result."""
    if version_result is None:
        if match.version in ("Unknown", "", None):
            return None
        raw_pattern = match.matched_patterns[0] if match.matched_patterns else None
        return VersionAttributionRecord(
            detected_version=match.version,
            source_file=attributor.source_file(match.source_url, match.filename),
            source_url=match.source_url,
            source_asset_id=attributor.asset_id(match.source_url),
            matched_pattern=_strip_evidence_prefixes(raw_pattern) if raw_pattern else None,
            matched_text=match.version_reason,
            confidence=match.version_confidence or match.confidence,
            extractor_id=match.version_source,
            alternative_candidates=list(match.rejected_version_candidates),
        )

    primary = version_result.evidence[0] if version_result.evidence else None
    source_url = primary.source_url if primary else match.source_url
    source_file = attributor.source_file(
        source_url,
        primary.filename if primary else match.filename,
    )
    raw_pattern = (
        primary.pattern
        if primary
        else (match.matched_patterns[0] if match.matched_patterns else None)
    )
    return VersionAttributionRecord(
        detected_version=version_result.version,
        source_file=source_file,
        source_url=source_url,
        source_asset_id=attributor.asset_id(source_url),
        matched_pattern=_strip_evidence_prefixes(raw_pattern) if raw_pattern else None,
        matched_text=primary.matched_value if primary else None,
        confidence=version_result.confidence,
        extractor_id=version_result.method.value,
        alternative_candidates=list(version_result.rejected_candidates),
    )


def version_evidence_records(
    match: TechnologyMatch,
    version_result: TechnologyVersionResult,
    *,
    attributor: AssetAttributor,
) -> list[TechnologyEvidenceRecord]:
    """Convert version extraction evidence into technology evidence records."""
    records: list[TechnologyEvidenceRecord] = []
    for item in version_result.evidence:
        records.append(_version_evidence_item(item, match=match, attributor=attributor))
    return records


def _pattern_evidence(
    *,
    match: TechnologyMatch,
    pattern: PatternEvidence,
    source_url: str | None,
    source_file: str | None,
    asset_id: str | None,
    discovery_method: DiscoveryMethod,
    detected_at: object | None,
) -> TechnologyEvidenceRecord:
    kwargs: dict[str, object] = {}
    if detected_at is not None:
        kwargs["detected_at"] = detected_at
    return TechnologyEvidenceRecord(
        evidence_id=str(uuid4()),
        technology_name=match.technology.name,
        category=match.technology.category,
        version=match.version if match.version != "Unknown" else None,
        confidence=min(match.confidence, pattern.weight),
        detector_name=_DETECTOR_NAME,
        evidence_type=_map_matcher_type(pattern.matcher),
        matched_pattern=pattern.pattern,
        matched_text=_resolve_matched_text(pattern),
        source_file=source_file,
        source_url=source_url,
        source_asset_id=asset_id,
        discovery_method=discovery_method,
        **kwargs,  # type: ignore[arg-type]
    )


def _fingerprint_evidence_item(
    item: Evidence,
    *,
    match: TechnologyMatch,
    attributor: AssetAttributor,
) -> TechnologyEvidenceRecord:
    return TechnologyEvidenceRecord(
        evidence_id=item.id,
        technology_name=match.technology.name,
        category=match.technology.category,
        version=match.version if match.version != "Unknown" else None,
        confidence=max(item.confidence_hint, match.confidence * 0.5),
        detector_name=item.collector or _EVIDENCE_DETECTOR,
        evidence_type=_map_fingerprint_evidence_type(item.evidence_type.value),
        matched_pattern=item.matched_pattern,
        matched_text=item.matched_value,
        source_file=attributor.source_file(item.url, item.file),
        source_url=item.url,
        source_asset_id=attributor.asset_id(item.url),
        line_number=item.line_number,
        discovery_method=_map_discovery_method(attributor.discovery_method(item.url)),
        detected_at=item.timestamp,
    )


def _version_evidence_item(
    item: VersionEvidence,
    *,
    match: TechnologyMatch,
    attributor: AssetAttributor,
) -> TechnologyEvidenceRecord:
    return TechnologyEvidenceRecord(
        evidence_id=str(uuid4()),
        technology_name=match.technology.name,
        category=match.technology.category,
        version=item.matched_value,
        confidence=match.version_confidence or match.confidence,
        detector_name=f"version-{match.technology.id}",
        evidence_type=_map_version_evidence_type(item.evidence_type.value),
        matched_pattern=item.pattern,
        matched_text=item.matched_value,
        source_file=attributor.source_file(item.source_url, item.filename),
        source_url=item.source_url,
        source_asset_id=attributor.asset_id(item.source_url),
        discovery_method=_map_discovery_method(attributor.discovery_method(item.source_url)),
    )


def _map_matcher_type(matcher: str) -> IntelligenceEvidenceType:
    mapping = {
        "string": IntelligenceEvidenceType.PATTERN_MATCH,
        "regex": IntelligenceEvidenceType.PATTERN_MATCH,
        "filename": IntelligenceEvidenceType.FILENAME,
        "sourcemap": IntelligenceEvidenceType.SOURCE_MAP,
        "global": IntelligenceEvidenceType.RUNTIME_CONSTANT,
    }
    return mapping.get(matcher, IntelligenceEvidenceType.PATTERN_MATCH)


def _map_fingerprint_evidence_type(value: str) -> IntelligenceEvidenceType:
    mapping = {
        "http_header": IntelligenceEvidenceType.HTTP_HEADER,
        "script_content": IntelligenceEvidenceType.SCRIPT_CONTENT,
        "bundle_marker": IntelligenceEvidenceType.BUNDLE_MARKER,
        "filename": IntelligenceEvidenceType.FILENAME,
        "source_map": IntelligenceEvidenceType.SOURCE_MAP,
        "version_candidate": IntelligenceEvidenceType.VERSION_CANDIDATE,
        "runtime_pattern": IntelligenceEvidenceType.RUNTIME_CONSTANT,
        "banner": IntelligenceEvidenceType.BANNER,
        "metadata": IntelligenceEvidenceType.METADATA,
        "package_identifier": IntelligenceEvidenceType.PACKAGE_IDENTIFIER,
    }
    return mapping.get(value, IntelligenceEvidenceType.CUSTOM)


def _map_version_evidence_type(value: str) -> IntelligenceEvidenceType:
    mapping = {
        "banner": IntelligenceEvidenceType.BANNER,
        "runtime_constant": IntelligenceEvidenceType.RUNTIME_CONSTANT,
        "metadata": IntelligenceEvidenceType.METADATA,
        "package_identifier": IntelligenceEvidenceType.PACKAGE_IDENTIFIER,
        "framework_object": IntelligenceEvidenceType.RUNTIME_CONSTANT,
        "build_metadata": IntelligenceEvidenceType.METADATA,
        "source_map": IntelligenceEvidenceType.SOURCE_MAP,
        "generic_literal": IntelligenceEvidenceType.VERSION_CANDIDATE,
    }
    return mapping.get(value, IntelligenceEvidenceType.VERSION_CANDIDATE)


def _map_discovery_method(value: str | None) -> DiscoveryMethod:
    if value is None:
        return DiscoveryMethod.UNKNOWN
    mapping = {
        "html": DiscoveryMethod.HTML,
        "javascript": DiscoveryMethod.JAVASCRIPT,
        "css": DiscoveryMethod.CSS,
        "http_header": DiscoveryMethod.NETWORK,
        "manifest": DiscoveryMethod.MANIFEST,
        "well_known": DiscoveryMethod.WELL_KNOWN,
        "inline": DiscoveryMethod.INLINE,
    }
    return mapping.get(value, DiscoveryMethod.UNKNOWN)


def _resolve_matched_text(pattern: PatternEvidence) -> str | None:
    """Return human-readable evidence text from a pattern record."""
    if pattern.matcher in {"global", "string", "regex", "sourcemap"}:
        if pattern.detail and not _looks_internal_label(pattern.detail):
            return pattern.detail
        return pattern.pattern

    if pattern.matcher == "filename":
        return pattern.pattern

    for candidate in (pattern.detail, pattern.pattern):
        if not candidate:
            continue
        cleaned = _strip_evidence_prefixes(candidate)
        if cleaned and not _looks_internal_label(cleaned):
            return cleaned
    return pattern.pattern or pattern.detail


def _strip_evidence_prefixes(value: str) -> str:
    """Remove provider and category prefixes from evidence strings."""
    current = value.strip()
    while ":" in current:
        prefix, rest = current.split(":", 1)
        lowered = prefix.lower()
        if lowered in _PROVIDER_PREFIXES or lowered in _CATEGORY_PREFIXES:
            current = rest.strip()
            continue
        break
    return current


def _looks_internal_label(value: str) -> bool:
    """Return True when a value is an internal label rather than matched content."""
    return (
        value.startswith("techspecter:")
        or value.startswith("wappalyzer:")
        or value.startswith("resource:")
        or value.startswith("source:")
    )
