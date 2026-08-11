"""Technology intelligence engine."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from techspecter.fingerprinting.evidence.models import EvidenceCollection
from techspecter.fingerprinting.models import DetectionResult
from techspecter.models.discovery import DiscoveryResult
from techspecter.technology_intelligence.attribution import AssetAttributor
from techspecter.technology_intelligence.correlation import EvidenceCorrelationEngine
from techspecter.technology_intelligence.evidence import (
    build_evidence_from_collection,
    build_evidence_from_match,
    build_version_attribution,
    version_evidence_records,
)
from techspecter.technology_intelligence.models import TechnologyIntelligenceReport
from techspecter.versioning.engine import (
    VersionDetectionEngine,
    collect_javascript_resources,
    resources_for_match,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class TechnologyIntelligenceEngine:
    """Build technology intelligence from discovery and detection outputs."""

    correlation_engine: EvidenceCorrelationEngine = field(
        default_factory=EvidenceCorrelationEngine,
    )
    version_engine: VersionDetectionEngine = field(default_factory=VersionDetectionEngine)

    def build(
        self,
        discovery: DiscoveryResult,
        detection: DetectionResult,
        *,
        evidence_collection: EvidenceCollection | None = None,
    ) -> TechnologyIntelligenceReport:
        """Produce a technology intelligence report."""
        started = time.perf_counter()
        target_url = detection.target_url or str(discovery.target.url)
        attributor = AssetAttributor(inventory=discovery.asset_inventory)
        resources = list(collect_javascript_resources(discovery))
        detected_at = datetime.now(tz=UTC)

        entries = []
        for match in detection.matches:
            evidence = build_evidence_from_match(
                match,
                attributor=attributor,
                detected_at=detected_at,
            )
            if evidence_collection is not None:
                evidence.extend(
                    build_evidence_from_collection(
                        match,
                        evidence_collection,
                        attributor=attributor,
                    ),
                )

            version_result = self.version_engine.detect_for_technology(
                match.technology.id,
                resources_for_match(match, resources),
                technology_confidence=match.confidence,
                preferred_source_url=match.source_url,
                preferred_filename=match.filename or match.source_file,
            )
            if version_result is not None:
                evidence.extend(
                    version_evidence_records(
                        match,
                        version_result,
                        attributor=attributor,
                    ),
                )

            # TechnologyMatch.version is the canonical authority when already resolved.
            # JS extraction may fill gaps only; it must not independently override a
            # confirmed match version.
            if match.version not in ("Unknown", "", None):
                version_attr = build_version_attribution(
                    match,
                    None,
                    attributor=attributor,
                )
                resolved_version = match.version
            else:
                version_attr = build_version_attribution(
                    match,
                    version_result,
                    attributor=attributor,
                )
                resolved_version = (
                    version_attr.detected_version
                    if version_attr is not None
                    else match.version
                )

            entry = self.correlation_engine.correlate(
                match,
                evidence,
                version=resolved_version,
                version_attribution=version_attr,
                detectors=match.providers or ["techspecter"],
            )
            entries.append(entry)

        merged = self.correlation_engine.merge_entries(entries)
        relationships = self.correlation_engine.resolve_relationships(merged)
        merged = self.correlation_engine.attach_relationships(merged, relationships)

        total_evidence = sum(len(entry.evidence) for entry in merged)
        asset_ids = {asset_id for entry in merged for asset_id in entry.found_in_asset_ids}
        elapsed_ms = (time.perf_counter() - started) * 1000

        report = TechnologyIntelligenceReport(
            target_url=target_url,
            technologies=sorted(merged, key=lambda item: (-item.confidence, item.technology.name)),
            relationships=relationships,
            total_evidence=total_evidence,
            total_assets_referenced=len(asset_ids),
            elapsed_ms=elapsed_ms,
        )

        logger.info(
            "Technology intelligence built for %s: %d technologies, "
            "%d evidence, %d relationships (%.0f ms)",
            target_url,
            len(report.technologies),
            report.total_evidence,
            len(relationships),
            elapsed_ms,
        )
        return report
