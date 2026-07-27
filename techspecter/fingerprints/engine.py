"""Fingerprint matching engine."""

from __future__ import annotations

import logging

from techspecter.fingerprints.confidence import ConfidenceScorer, MatchEvidence
from techspecter.fingerprints.context import MatchContext
from techspecter.fingerprints.matchers.base import MatcherRegistry, build_default_registry
from techspecter.fingerprints.models import (
    Fingerprint,
    Pattern,
    Technology,
    TechnologyMatch,
)
from techspecter.fingerprints.version import VersionExtractor

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
                context.content,
            )
            evidence = MatchEvidence(
                matched_patterns=evidence.matched_patterns,
                version_pattern=version_pattern,
            )
            confidence = self._confidence_scorer.score(fingerprint, evidence, version)

            technology = Technology(
                id=fingerprint.id,
                name=fingerprint.name,
                category=fingerprint.category,
                website=fingerprint.website,
                description=fingerprint.description,
                tags=fingerprint.tags,
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
            )
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
        matched_patterns: list[Pattern] = []
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
        for fingerprint in self._fingerprints:
            if fingerprint.id == technology_id:
                return fingerprint.priority
        return 0
