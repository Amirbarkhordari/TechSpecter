"""Pluggable detector registry."""

from __future__ import annotations

from dataclasses import dataclass, field

from techspecter.sensitive_intelligence.detectors.base import BaseSensitiveDetector
from techspecter.sensitive_intelligence.detectors.comments import CommentDetector
from techspecter.sensitive_intelligence.detectors.credentials import CredentialDetector
from techspecter.sensitive_intelligence.detectors.domains import DomainDetector
from techspecter.sensitive_intelligence.detectors.emails import EmailDetector
from techspecter.sensitive_intelligence.detectors.ips import IpDetector
from techspecter.sensitive_intelligence.detectors.phones import PhoneDetector
from techspecter.sensitive_intelligence.detectors.secrets import SecretDetector
from techspecter.sensitive_intelligence.detectors.urls import UrlDetector
from techspecter.sensitive_intelligence.detectors.usernames import UsernameDetector
from techspecter.sensitive_intelligence.detectors.uuids import UuidDetector


def default_detectors() -> list[BaseSensitiveDetector]:
    """Return the built-in detector set."""
    return [
        EmailDetector(),
        PhoneDetector(),
        UsernameDetector(),
        UrlDetector(),
        DomainDetector(),
        IpDetector(),
        UuidDetector(),
        SecretDetector(),
        CredentialDetector(),
        CommentDetector(),
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
