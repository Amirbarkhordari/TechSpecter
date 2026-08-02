"""Fingerprint matching engine."""

from __future__ import annotations

import logging

from techspecter.fingerprinting.context import MatchContext
from techspecter.fingerprinting.extractor import VersionExtractor
from techspecter.fingerprinting.match_attribution import (
    apply_match_attribution,
    build_pattern_evidence,
    build_version_evidence,
)
from techspecter.fingerprinting.match_quality import build_detection_reason
from techspecter.fingerprinting.matchers.base import MatcherRegistry, build_default_registry
from techspecter.fingerprinting.models import (
    UNKNOWN_VERSION,
    Fingerprint,
    FingerprintPattern,
    Technology,
    TechnologyMatch,
)
from techspecter.fingerprinting.scoring import ConfidenceScorer, MatchEvidence

logger = logging.getLogger(__name__)


class FingerprintEngine:
    """Execute fingerprint pattern matching against JavaScript resources."""

    def __init__(
        self,
        fingerprints: list[Fingerprint],
        *,
        matcher_registry: MatcherRegistry | None = None,
        version_extractor: VersionExtractor | None = None,
        confidence_scorer: ConfidenceScorer | None = None,
    ) -> None:
        """Initialize the fingerprint engine.

        Args:
            fingerprints: Loaded technology fingerprint definitions.
            matcher_registry: Optional custom matcher registry.
            version_extractor: Optional version extractor implementation.
            confidence_scorer: Optional confidence scorer implementation.
        """
        self._fingerprints = fingerprints
        self._matcher_registry = matcher_registry or build_default_registry()
        self._version_extractor = version_extractor or VersionExtractor()
        self._confidence_scorer = confidence_scorer or ConfidenceScorer()
        self._priority_map: dict[str, int] = {
            fp.id: fp.priority for fp in self._fingerprints
        }

    @property
    def fingerprints(self) -> list[Fingerprint]:
        """Return loaded fingerprint definitions."""
        return list(self._fingerprints)

    def detect(self, context: MatchContext) -> list[TechnologyMatch]:
        """Detect technologies present in a JavaScript resource.

        Args:
            context: JavaScript resource context.

        Returns:
            Technology matches sorted by confidence and priority.
        """
        matches: list[TechnologyMatch] = []
        for fingerprint in self._fingerprints:
            evidence = self._evaluate_fingerprint(fingerprint, context)
            if not evidence.matched_patterns:
                continue

            version, version_pattern = self._version_extractor.extract_with_pattern(
                fingerprint,
                context,
            )
            evidence = MatchEvidence(
                matched_patterns=evidence.matched_patterns,
                version_pattern=version_pattern,
            )
            confidence = self._confidence_scorer.score(fingerprint, evidence, version)
            if not self._confidence_scorer.passes_threshold(confidence):
                logger.debug(
                    "Skipping weak detection for '%s' (confidence %.1f)",
                    fingerprint.id,
                    confidence,
                )
                continue

            technology = Technology(
                id=fingerprint.id,
                name=fingerprint.name,
                category=fingerprint.category,
                website=fingerprint.website,
                description=fingerprint.description,
                tags=fingerprint.tags,
            )
            evidence_items = [
                build_pattern_evidence(pattern, context)
                for pattern in evidence.matched_patterns
            ]
            if version != UNKNOWN_VERSION and version_pattern is not None:
                evidence_items.append(
                    build_version_evidence(
                        matcher="version",
                        pattern=version_pattern.pattern,
                        matched_value=version,
                        context=context,
                        weight=version_pattern.weight,
                    ),
                )

            match = TechnologyMatch(
                technology=technology,
                version=version,
                confidence=confidence,
                matched_patterns=[
                    f"{pattern.matcher}:{pattern.pattern}" for pattern in evidence.matched_patterns
                ],
                source_url=context.url,
                filename=context.filename,
                source_file=context.filename,
                asset_id=context.asset_id,
                evidence=evidence_items,
            )
            match = apply_match_attribution(match)
            if not match.detection_reason:
                match.detection_reason = build_detection_reason(match)
            matches.append(match)
            logger.info(
                "Detected technology '%s' version '%s' (confidence %.1f)",
                fingerprint.name,
                version,
                confidence,
            )

        matches.sort(
            key=lambda item: (-item.confidence, -self._priority_for(item.technology.id)),
        )
        return matches

    def _evaluate_fingerprint(
        self,
        fingerprint: Fingerprint,
        context: MatchContext,
    ) -> MatchEvidence:
        """Evaluate all patterns for a fingerprint.

        Args:
            fingerprint: Technology fingerprint definition.
            context: JavaScript resource context.

        Returns:
            Match evidence containing matched patterns.
        """
        matched_patterns: list[FingerprintPattern] = []
        for pattern in fingerprint.patterns:
            matcher = self._matcher_registry.get(pattern.matcher)
            if matcher is None:
                logger.debug(
                    "Unsupported matcher '%s' in fingerprint '%s'",
                    pattern.matcher,
                    fingerprint.id,
                )
                continue
            if matcher.matches(pattern, context):
                matched_patterns.append(pattern)

        return MatchEvidence(
            matched_patterns=matched_patterns,
            version_pattern=None,
        )

    def _priority_for(self, technology_id: str) -> int:
        """Return the configured priority for a technology ID.

        Args:
            technology_id: Fingerprint identifier.

        Returns:
            Priority value, or zero when not found.
        """
        return self._priority_map.get(technology_id, 0)
