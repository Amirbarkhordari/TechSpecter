"""Pluggable detector registry."""

from __future__ import annotations

from dataclasses import dataclass, field

from techspecter.sensitive_intelligence.detectors.base import BaseSensitiveDetector
from techspecter.sensitive_intelligence.detectors.domains import DomainDetector
from techspecter.sensitive_intelligence.detectors.emails import EmailDetector
from techspecter.sensitive_intelligence.detectors.entropy_secrets import EntropySecretDetector
from techspecter.sensitive_intelligence.detectors.ips import IpDetector
from techspecter.sensitive_intelligence.detectors.phones import PhoneDetector
from techspecter.sensitive_intelligence.detectors.urls import UrlDetector
from techspecter.sensitive_intelligence.detectors.usernames import UsernameDetector
from techspecter.sensitive_intelligence.detectors.uuids import UuidDetector
from techspecter.sensitive_intelligence.models import FindingType
from techspecter.sensitive_intelligence.rules.engine import RuleEngine, RuleEngineDetector
from techspecter.sensitive_intelligence.rules.models import RuleCategory


def default_detectors() -> list[BaseSensitiveDetector]:
    """Return the built-in detector set."""
    engine = RuleEngine()
    return [
        RuleEngineDetector(
            detector_id="secrets-rule-engine",
            finding_type=FindingType.SECRET,
            category=RuleCategory.SECRETS,
            engine=engine,
        ),
        RuleEngineDetector(
            detector_id="credentials-rule-engine",
            finding_type=FindingType.CREDENTIAL,
            category=RuleCategory.CREDENTIALS,
            engine=engine,
        ),
        RuleEngineDetector(
            detector_id="sensitive-config-rule-engine",
            finding_type=FindingType.SENSITIVE_CONFIG,
            category=RuleCategory.SENSITIVE_CONFIGURATION,
            engine=engine,
        ),
        RuleEngineDetector(
            detector_id="developer-artifacts-rule-engine",
            finding_type=FindingType.COMMENT,
            category=RuleCategory.DEVELOPER_ARTIFACTS,
            engine=engine,
        ),
        EntropySecretDetector(),
        EmailDetector(),
        PhoneDetector(),
        UsernameDetector(),
        UrlDetector(),
        DomainDetector(),
        IpDetector(),
        UuidDetector(),
    ]


@dataclass(slots=True)
class DetectorRegistry:
    """Registry of passive sensitive data detectors."""

    detectors: list[BaseSensitiveDetector] = field(default_factory=default_detectors)

    def register(self, detector: BaseSensitiveDetector) -> None:
        """Register an additional detector without modifying the engine."""
        self.detectors.append(detector)

    def all(self) -> list[BaseSensitiveDetector]:
        """Return registered detectors."""
        return list(self.detectors)
