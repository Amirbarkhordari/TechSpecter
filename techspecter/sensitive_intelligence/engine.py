"""Sensitive intelligence engine."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from techspecter.models.discovery import DiscoveryResult
from techspecter.sensitive_intelligence.models import (
    FindingType,
    SensitiveFindingRecord,
    SensitiveIntelligenceReport,
    SensitiveIntelligenceSummary,
    SeverityLevel,
)
from techspecter.sensitive_intelligence.registry import DetectorRegistry
from techspecter.sensitive_intelligence.sources import collect_text_assets
from techspecter.sensitive_intelligence.tracker import FindingTracker

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SensitiveIntelligenceEngine:
    """Analyze downloaded textual assets for sensitive data and secrets."""

    registry: DetectorRegistry = field(default_factory=DetectorRegistry)

    def build(self, discovery: DiscoveryResult) -> SensitiveIntelligenceReport:
        """Run all detectors against discovered textual assets."""
        started = time.perf_counter()
        target_url = str(discovery.target.url)
        assets = collect_text_assets(discovery)
        tracker = FindingTracker()

        logger.info(
            "Sensitive intelligence starting for %s: %d textual assets",
            target_url,
            len(assets),
        )

        for asset in assets:
            for detector in self.registry.all():
                for match in detector.detect(asset.content):
                    tracker.add_match(match, detector=detector, source=asset)

        findings = sorted(
            tracker.all(),
            key=lambda item: (-_severity_rank(item.severity), -item.confidence, item.subtype),
        )
        summary = _build_summary(findings, assets_analyzed=len(assets))
        elapsed_ms = (time.perf_counter() - started) * 1000

        report = SensitiveIntelligenceReport(
            target_url=target_url,
            findings=findings,
            summary=summary,
            elapsed_ms=elapsed_ms,
            generated_at=datetime.now(tz=UTC),
        )
        logger.info(
            "Sensitive intelligence complete for %s: %d findings from %d assets (%.0f ms)",
            target_url,
            summary.total_findings,
            len(assets),
            elapsed_ms,
        )
        return report


def _build_summary(
    findings: list[SensitiveFindingRecord],
    *,
    assets_analyzed: int,
) -> SensitiveIntelligenceSummary:
    summary = SensitiveIntelligenceSummary(assets_analyzed=assets_analyzed)
    for item in findings:
        summary.total_findings += 1
        if item.severity == SeverityLevel.HIGH:
            summary.high_severity += 1
        elif item.severity == SeverityLevel.MEDIUM:
            summary.medium_severity += 1
        else:
            summary.low_severity += 1

        if item.finding_type == FindingType.EMAIL:
            summary.emails += 1
        elif item.finding_type == FindingType.PHONE:
            summary.phones += 1
        elif item.finding_type == FindingType.SECRET:
            summary.secrets += 1
        elif item.finding_type == FindingType.CREDENTIAL:
            summary.credentials += 1
        elif item.finding_type == FindingType.URL:
            summary.urls += 1
        elif item.finding_type in {FindingType.DOMAIN, FindingType.HOSTNAME}:
            summary.domains += 1
        elif item.finding_type == FindingType.IP:
            summary.ips += 1
        elif item.finding_type == FindingType.UUID:
            summary.uuids += 1
        elif item.finding_type == FindingType.COMMENT:
            summary.comments += 1
        else:
            summary.other += 1
    return summary


def _severity_rank(severity: SeverityLevel) -> int:
    return {SeverityLevel.HIGH: 3, SeverityLevel.MEDIUM: 2, SeverityLevel.LOW: 1}[severity]
