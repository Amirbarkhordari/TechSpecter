"""Provider output normalization."""

from __future__ import annotations

import logging
from typing import Any

from techspecter.benchmark.utils import normalize_category, normalize_technology_id
from techspecter.fingerprinting.models import (
    UNKNOWN_VERSION,
    DetectionResult,
    SecurityFinding,
    TechnologyMatch,
)
from techspecter.providers.models import ProviderDetectionResult, ProviderMatch

logger = logging.getLogger(__name__)

_JAVASCRIPT_LIBRARY = "javascript-libraries"


class ProviderNormalizer:
    """Normalize provider-specific outputs into ProviderMatch records."""

    def from_techspecter(self, detection: DetectionResult) -> ProviderDetectionResult:
        """Normalize TechSpecter DetectionResult."""
        matches = [self._from_technology_match(match) for match in detection.matches]
        return ProviderDetectionResult(
            provider="techspecter",
            target_url=detection.target_url,
            matches=matches,
            elapsed_ms=detection.elapsed_ms,
        )

    def from_wappalyzer(
        self,
        payload: dict[str, Any] | list[Any],
        *,
        target_url: str,
        elapsed_ms: float = 0.0,
    ) -> ProviderDetectionResult:
        """Normalize Wappalyzer JSON into provider matches."""
        from techspecter.benchmark.normalizer import ResultNormalizer

        normalized = ResultNormalizer().normalize_wappalyzer(payload, target_url=target_url)
        matches = [
            ProviderMatch(
                technology_id=tech.id,
                name=tech.name,
                category=tech.category,
                version=tech.version,
                confidence=tech.confidence or 75.0,
                evidence=list(tech.evidence),
                provider="wappalyzer",
                detection_method="wappalyzer-cli",
                metadata=dict(tech.raw_metadata),
            )
            for tech in normalized.technologies
        ]
        return ProviderDetectionResult(
            provider="wappalyzer",
            target_url=target_url,
            matches=matches,
            elapsed_ms=elapsed_ms,
        )

    def from_retirejs(
        self,
        payload: list[dict[str, Any]],
        *,
        target_url: str,
        elapsed_ms: float = 0.0,
    ) -> ProviderDetectionResult:
        """Normalize Retire.js JSON output."""
        matches: list[ProviderMatch] = []
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            source_file = str(entry.get("file", ""))
            results = entry.get("results", [])
            if not isinstance(results, list):
                continue
            for result in results:
                if not isinstance(result, dict):
                    continue
                match = self._from_retire_result(result, source_file=source_file)
                if match is not None:
                    matches.append(match)
        return ProviderDetectionResult(
            provider="retirejs",
            target_url=target_url,
            matches=matches,
            elapsed_ms=elapsed_ms,
        )

    def _from_technology_match(self, match: TechnologyMatch) -> ProviderMatch:
        """Map TechSpecter TechnologyMatch to ProviderMatch."""
        tech = match.technology
        evidence: list[str] = []
        if match.detection_reason:
            evidence.append(match.detection_reason)
        evidence.extend(match.matched_patterns[:10])
        evidence.extend(f"source:{item}" for item in match.evidence_sources[:5])
        evidence.extend(f"resource:{item}" for item in match.matched_resources[:5])

        return ProviderMatch(
            technology_id=normalize_technology_id(tech.id),
            name=tech.name,
            category=normalize_category(tech.category),
            version=match.version or UNKNOWN_VERSION,
            confidence=match.confidence,
            evidence=evidence,
            provider="techspecter",
            detection_method="fingerprint-engine",
            metadata={
                "version_source": match.version_source,
                "version_confidence": match.version_confidence,
                "evidence_count": match.evidence_count,
            },
        )

    def _from_retire_result(
        self,
        result: dict[str, Any],
        *,
        source_file: str,
    ) -> ProviderMatch | None:
        """Map one Retire.js component result."""
        component = str(result.get("component") or result.get("name") or "").strip()
        if not component:
            return None
        version = str(result.get("version") or UNKNOWN_VERSION).strip() or UNKNOWN_VERSION
        tech_id = normalize_technology_id(component)
        security_findings = self._parse_vulnerabilities(result, component, version, source_file)
        evidence = [f"retire.js:{source_file}"] if source_file else ["retire.js"]
        if security_findings:
            evidence.append("vulnerability-intelligence")

        return ProviderMatch(
            technology_id=tech_id,
            name=component,
            category=_JAVASCRIPT_LIBRARY,
            version=version,
            confidence=85.0 if security_findings else 75.0,
            evidence=evidence,
            provider="retirejs",
            detection_method="retire.js-scan",
            metadata={"source_file": source_file},
            security_findings=security_findings,
        )

    def _parse_vulnerabilities(
        self,
        result: dict[str, Any],
        component: str,
        version: str,
        source_file: str,
    ) -> list[SecurityFinding]:
        """Extract passive vulnerability intelligence from Retire.js."""
        findings: list[SecurityFinding] = []
        vulnerabilities = result.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return findings
        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue
            cve_ids: list[str] = []
            references: list[str] = []
            identifiers = item.get("identifiers")
            identifier_items = identifiers if isinstance(identifiers, list) else []
            for identifier in identifier_items:
                if isinstance(identifier, dict):
                    ref_type = str(identifier.get("type", "")).upper()
                    value = str(identifier.get("value", ""))
                    if ref_type == "CVE" and value:
                        cve_ids.append(value)
                    elif value:
                        references.append(value)
            info = item.get("info")
            info_links: list[object] = info if isinstance(info, list) else []
            for link in info_links:
                if isinstance(link, str):
                    references.append(link)
            findings.append(
                SecurityFinding(
                    library=component,
                    installed_version=version,
                    severity=str(item.get("severity") or "unknown"),
                    cve_ids=cve_ids,
                    references=references,
                    description=str(item.get("summary") or item.get("title") or "") or None,
                    source_file=source_file or None,
                ),
            )
        return findings
