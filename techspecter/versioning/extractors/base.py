"""Pattern-based version extractor base."""

from __future__ import annotations

import re
from dataclasses import dataclass

from techspecter.versioning.confidence import score_method
from techspecter.versioning.extractor import TechnologyVersionExtractor
from techspecter.versioning.models import ExtractedVersion, VersionEvidence, VersionEvidenceType
from techspecter.versioning.validator import validate_and_normalize


@dataclass(frozen=True, slots=True)
class ExtractionPattern:
    """Regex pattern for passive version extraction."""

    pattern: re.Pattern[str]
    method: VersionEvidenceType
    description: str


class PatternVersionExtractor(TechnologyVersionExtractor):
    """Base extractor driven by ordered regex patterns."""

    patterns: tuple[ExtractionPattern, ...] = ()

    def extract(
        self,
        content: str,
        *,
        url: str,
        filename: str,
    ) -> list[ExtractedVersion]:
        """Extract versions using configured patterns."""
        results: list[ExtractedVersion] = []
        seen: set[str] = set()

        for item in self.patterns:
            for match in item.pattern.finditer(content):
                raw = match.group(1)
                version = validate_and_normalize(raw)
                if version is None or version in seen:
                    continue
                seen.add(version)
                confidence, level = score_method(item.method)
                snippet_start = max(0, match.start() - 20)
                snippet_end = min(len(content), match.end() + 20)
                evidence = VersionEvidence(
                    evidence_type=item.method,
                    matched_value=version,
                    pattern=item.pattern.pattern,
                    source_url=url,
                    filename=filename,
                    snippet=content[snippet_start:snippet_end],
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
        return results
