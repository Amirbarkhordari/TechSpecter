"""Sensitive intelligence engine."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from techspecter.models.discovery import DiscoveryResult
from techspecter.sensitive_intelligence.candidates.models import ValidationState
from techspecter.sensitive_intelligence.candidates.validator import SensitiveCandidateValidator
from techspecter.sensitive_intelligence.correlator import correlate_credential_pairs
from techspecter.sensitive_intelligence.detectors.base import BaseSensitiveDetector, DetectorMatch
from techspecter.sensitive_intelligence.javascript_intel import extract_javascript_config_snippets
from techspecter.sensitive_intelligence.models import (
    FindingCategory,
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
    validator: SensitiveCandidateValidator = field(default_factory=SensitiveCandidateValidator)

    def build(self, discovery: DiscoveryResult) -> SensitiveIntelligenceReport:
        """Run detectors, validate candidates, and confirm findings."""
        started = time.perf_counter()
        target_url = str(discovery.target.url)
        assets = collect_text_assets(discovery)
        tracker = FindingTracker()
        correlator = _CredentialCorrelatorDetector()
        candidate_stats = {"confirmed": 0, "rejected": 0, "candidate_only": 0}

        logger.info(
            "Sensitive intelligence starting for %s: %d textual assets",
            target_url,
            len(assets),
        )

        for asset in assets:
            scan_targets = [asset.content, *extract_javascript_config_snippets(asset.content)]
            for content in scan_targets:
                for detector in self.registry.all():
                    for match in detector.detect(content):
                        candidate = self.validator.validate_match(
                            match,
                            detector_id=detector.detector_id,
                            source=asset,
                        )
                        _record_candidate_stat(candidate_stats, candidate.validation_state)
                        tracker.add_confirmed_candidate(candidate)
                for match in correlator.detect(content):
                    candidate = self.validator.validate_match(
                        match,
                        detector_id=correlator.detector_id,
                        source=asset,
                    )
                    _record_candidate_stat(candidate_stats, candidate.validation_state)
                    tracker.add_confirmed_candidate(candidate)

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
            "Sensitive intelligence complete for %s: %d findings from %d assets "
            "(%.0f ms; confirmed=%d rejected=%d candidate_only=%d)",
            target_url,
            summary.total_findings,
            len(assets),
            elapsed_ms,
            candidate_stats["confirmed"],
            candidate_stats["rejected"],
            candidate_stats["candidate_only"],
        )
        return report


class _CredentialCorrelatorDetector(BaseSensitiveDetector):
    detector_id = "credential-correlator"
    finding_type = FindingType.CREDENTIAL

    def detect(self, content: str) -> list[DetectorMatch]:
        return correlate_credential_pairs(content)


def _record_candidate_stat(stats: dict[str, int], state: ValidationState) -> None:
    if state == ValidationState.CONFIRMED:
        stats["confirmed"] += 1
    elif state == ValidationState.REJECTED:
        stats["rejected"] += 1
    else:
        stats["candidate_only"] += 1


def _build_summary(
    findings: list[SensitiveFindingRecord],
    *,
    assets_analyzed: int,
) -> SensitiveIntelligenceSummary:
    summary = SensitiveIntelligenceSummary(assets_analyzed=assets_analyzed)
    for item in findings:
        summary.total_findings += 1
        if item.severity == SeverityLevel.CRITICAL:
            summary.critical_severity += 1
        elif item.severity == SeverityLevel.HIGH:
            summary.high_severity += 1
        elif item.severity == SeverityLevel.MEDIUM:
            summary.medium_severity += 1
        elif item.severity == SeverityLevel.LOW:
            summary.low_severity += 1
        else:
            summary.informational_severity += 1

        if item.category == FindingCategory.SECRETS:
            summary.secrets += 1
        elif item.category == FindingCategory.CREDENTIALS:
            summary.credentials += 1
        elif item.category == FindingCategory.SENSITIVE_CONFIGURATION:
            summary.sensitive_configuration += 1
        elif item.category == FindingCategory.DEVELOPER_ARTIFACTS:
            summary.developer_artifacts += 1
        elif item.finding_type == FindingType.EMAIL:
            summary.emails += 1
        elif item.finding_type == FindingType.PHONE:
            summary.phones += 1
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
    return {
        SeverityLevel.CRITICAL: 5,
        SeverityLevel.HIGH: 4,
        SeverityLevel.MEDIUM: 3,
        SeverityLevel.LOW: 2,
        SeverityLevel.INFORMATIONAL: 1,
    }[severity]
