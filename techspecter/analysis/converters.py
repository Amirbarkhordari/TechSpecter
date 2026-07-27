"""Converters between fingerprint detection and generic findings."""

from __future__ import annotations

from techspecter.analysis.models.evidence import Evidence
from techspecter.analysis.models.finding import Finding, FindingCategory, Severity
from techspecter.fingerprinting.models import DetectionResult, TechnologyMatch


def technology_match_to_finding(match: TechnologyMatch, *, analyzer_id: str) -> Finding:
    """Convert a technology match into a generic finding."""
    source_file = match.filename or match.source_url
    evidence = [
        Evidence(
            url=match.source_url,
            file=source_file,
            snippet=item.pattern,
            javascript_location=item.detail or source_file,
        )
        for item in match.evidence
    ]
    if not evidence and match.matched_patterns:
        for entry in match.matched_patterns:
            matcher_type, _, pattern = entry.partition(":")
            evidence.append(
                Evidence(
                    url=match.source_url,
                    file=source_file,
                    snippet=pattern or entry,
                    javascript_location=f"{matcher_type}:{pattern or entry}",
                )
            )

    return Finding(
        id=f"technology:{match.technology.id}",
        analyzer=analyzer_id,
        category=FindingCategory.TECHNOLOGY,
        title=match.technology.name,
        description=match.technology.description or f"Detected {match.technology.name}",
        severity=Severity.INFO,
        confidence=match.confidence,
        evidence=evidence,
        location=source_file,
        metadata={
            "technology_id": match.technology.id,
            "technology_category": match.technology.category,
            "version": match.version,
            "website": match.technology.website,
            "tags": match.technology.tags,
        },
    )


def detection_result_to_findings(
    detection: DetectionResult,
    *,
    analyzer_id: str,
) -> list[Finding]:
    """Convert a detection result into technology findings."""
    return [
        technology_match_to_finding(match, analyzer_id=analyzer_id) for match in detection.matches
    ]


def _is_technology_category(category: FindingCategory | str) -> bool:
    """Return whether a finding category represents technology detection."""
    if isinstance(category, FindingCategory):
        return category == FindingCategory.TECHNOLOGY
    return category == FindingCategory.TECHNOLOGY.value


def findings_to_detection_result(
    findings: list[Finding],
    *,
    target_url: str,
    scripts_analyzed: int = 0,
    elapsed_ms: float = 0.0,
) -> DetectionResult:
    """Rebuild a detection result from technology findings for backward compatibility."""
    from techspecter.fingerprinting.models import PatternEvidence, Technology, TechnologyMatch

    matches: list[TechnologyMatch] = []
    for finding in findings:
        if not _is_technology_category(finding.category):
            continue
        technology_id = str(
            finding.metadata.get("technology_id", finding.id.removeprefix("technology:"))
        )
        matches.append(
            TechnologyMatch(
                technology=Technology(
                    id=technology_id,
                    name=finding.title,
                    category=str(finding.metadata.get("technology_category", "unknown")),
                    website=finding.metadata.get("website"),
                    description=finding.description,
                    tags=list(finding.metadata.get("tags", [])),
                ),
                version=str(finding.metadata.get("version", "Unknown")),
                confidence=finding.confidence,
                source_url=next((item.url for item in finding.evidence if item.url), None),
                filename=next(
                    (item.file for item in finding.evidence if item.file), finding.location
                ),
                evidence=[
                    PatternEvidence(
                        matcher="unknown",
                        pattern=item.snippet or "",
                        weight=finding.confidence,
                        detail=item.javascript_location,
                    )
                    for item in finding.evidence
                    if item.snippet
                ],
            )
        )

    return DetectionResult(
        target_url=target_url,
        matches=matches,
        scripts_analyzed=scripts_analyzed,
        elapsed_ms=elapsed_ms,
    )
