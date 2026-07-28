"""Multi-provider confidence calculation."""

from __future__ import annotations

from techspecter.providers.models import ProviderMatch

_AGREEMENT_CONFIDENCE: dict[int, float] = {
    1: 90.0,
    2: 97.0,
    3: 99.0,
}


class ProviderConfidenceEngine:
    """Recalculate confidence based on provider agreement and evidence quality."""

    def calculate(
        self,
        matches: list[ProviderMatch],
        *,
        provider_count: int,
    ) -> float:
        """Calculate unified confidence for merged detections."""
        if not matches:
            return 0.0

        provider_agreement = _AGREEMENT_CONFIDENCE.get(min(provider_count, 3), 99.0)
        base_confidence = max(match.confidence for match in matches)
        evidence_count = sum(len(match.evidence) for match in matches)
        evidence_bonus = min(5.0, evidence_count * 0.5)

        quality_bonus = 0.0
        if any(match.security_findings for match in matches):
            quality_bonus += 1.0
        if any(len(match.evidence) >= 3 for match in matches):
            quality_bonus += 2.0

        final = max(base_confidence, provider_agreement) + evidence_bonus + quality_bonus
        return round(min(100.0, final), 1)
