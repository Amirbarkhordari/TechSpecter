"""Metadata extraction from JavaScript resources."""

from __future__ import annotations

from techspecter.fingerprinting.evidence.models import EvidenceType
from techspecter.fingerprinting.javascript.extractors.patterns import (
    BUILD_HASH,
    COMMIT_HASH,
    GENERATED_BY,
    GITHUB_URL,
)
from techspecter.fingerprinting.javascript.models import ExtractionFinding, JavaScriptResource

_MAX_METADATA = 100


def extract_metadata_findings(resource: JavaScriptResource) -> tuple[ExtractionFinding, ...]:
    """Extract repository, build, and CI metadata evidence."""
    content = resource.content
    findings: list[ExtractionFinding] = []
    seen: set[str] = set()

    for pattern, reason, meta in (
        (GITHUB_URL, "GitHub URL observed in JavaScript", {"kind": "github_url"}),
        (GENERATED_BY, "Generator metadata observed in JavaScript", {"kind": "generator"}),
        (BUILD_HASH, "Build hash observed in JavaScript", {"kind": "build_hash"}),
    ):
        for match in pattern.finditer(content):
            value = match.group(1) if match.lastindex else match.group(0)
            if value in seen:
                continue
            seen.add(value)
            findings.append(
                ExtractionFinding(
                    category="metadata",
                    evidence_type=EvidenceType.METADATA.value,
                    matched_value=value,
                    matched_pattern=pattern.pattern,
                    reason=reason,
                    metadata=dict(meta),
                ),
            )
            if len(findings) >= _MAX_METADATA:
                return tuple(findings)

    for match in COMMIT_HASH.finditer(content[:50_000]):
        value = match.group(0)
        if len(value) < 12 or value in seen:
            continue
        context = content[max(0, match.start() - 20) : match.end() + 20].lower()
        if not any(token in context for token in ("commit", "sha", "revision", "git")):
            continue
        seen.add(value)
        findings.append(
            ExtractionFinding(
                category="metadata",
                evidence_type=EvidenceType.METADATA.value,
                matched_value=value,
                matched_pattern=COMMIT_HASH.pattern,
                reason="Commit hash candidate observed near git metadata",
                metadata={"kind": "commit_hash"},
            ),
        )

    return tuple(findings)
