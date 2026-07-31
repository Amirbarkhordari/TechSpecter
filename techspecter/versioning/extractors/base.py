"""Pattern-based version extractor base."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from techspecter.versioning.confidence import score_method
from techspecter.versioning.extractor import TechnologyVersionExtractor
from techspecter.versioning.models import ExtractedVersion, VersionEvidence, VersionEvidenceType
from techspecter.versioning.validator import validate_and_normalize

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ExtractionPattern:
    """Regex pattern for passive version extraction."""

    pattern: re.Pattern[str]
    method: VersionEvidenceType
    description: str


class PatternVersionExtractor(TechnologyVersionExtractor):
    """Base extractor driven by ordered regex patterns."""

    patterns: tuple[ExtractionPattern, ...] = ()
    filename_patterns: tuple[ExtractionPattern, ...] = ()
    content_markers: frozenset[str] = frozenset()

    def extract(
        self,
        content: str,
        *,
        url: str,
        filename: str,
    ) -> list[ExtractedVersion]:
        """Extract versions using configured patterns."""
        if self.content_markers and not any(marker in content for marker in self.content_markers):
            logger.debug(
                "Version extractor %s skipped %s (%s): no content markers %s",
                self.technology_id,
                filename,
                url,
                sorted(self.content_markers),
            )
            return []

        results: list[ExtractedVersion] = []
        seen: set[str] = set()
        rejected: list[str] = []

        for target_name, target in (("content", content), ("filename", filename)):
            pattern_set = self.patterns if target_name == "content" else self.filename_patterns
            for item in pattern_set:
                matches = list(item.pattern.finditer(target))
                logger.debug(
                    "Version extractor %s attempting %s on %s (%s): pattern=%s matches=%d",
                    self.technology_id,
                    item.description,
                    filename,
                    url,
                    item.pattern.pattern,
                    len(matches),
                )
                for match in matches:
                    raw = match.group(1)
                    version = validate_and_normalize(raw)
                    if version is None:
                        rejected.append(raw)
                        logger.debug(
                            "Version extractor %s rejected raw candidate %r from %s (%s)",
                            self.technology_id,
                            raw,
                            filename,
                            item.description,
                        )
                        continue
                    if version in seen:
                        continue
                    seen.add(version)
                    confidence, level = score_method(item.method)
                    snippet_start = max(0, match.start() - 20)
                    snippet_end = min(len(target), match.end() + 20)
                    evidence = VersionEvidence(
                        evidence_type=item.method,
                        matched_value=version,
                        pattern=item.pattern.pattern,
                        source_url=url,
                        filename=filename,
                        snippet=target[snippet_start:snippet_end],
                    )
                    logger.debug(
                        "Version extractor %s accepted %s via %s (%s confidence=%.1f)",
                        self.technology_id,
                        version,
                        item.description,
                        level.value,
                        confidence,
                    )
                    results.append(
                        ExtractedVersion(
                            version=version,
                            confidence=confidence,
                            confidence_level=level,
                            method=item.method,
                            evidence=[evidence],
                            extractor_id=self.technology_id,
                            source_url=url,
                            filename=filename,
                        ),
                    )
        if rejected:
            logger.debug(
                "Version extractor %s rejected candidates for %s: %s",
                self.technology_id,
                filename,
                rejected[:10],
            )
        return results
