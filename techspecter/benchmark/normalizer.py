"""Normalize TechSpecter and Wappalyzer outputs into a common structure."""

from __future__ import annotations

import logging
from typing import Any

from techspecter.benchmark.models import (
    UNKNOWN_VERSION,
    DetectionSource,
    NormalizedScanResult,
    NormalizedTechnology,
)
from techspecter.benchmark.utils import normalize_category, normalize_technology_id
from techspecter.fingerprinting.models import DetectionResult, TechnologyMatch

logger = logging.getLogger(__name__)


class ResultNormalizer:
    """Convert engine-specific outputs into normalized benchmark records."""

    def normalize_techspecter(
        self,
        detection: DetectionResult,
        *,
        elapsed_ms: float | None = None,
    ) -> NormalizedScanResult:
        """Normalize a TechSpecter detection result."""
        technologies = [self._from_techspecter_match(match) for match in detection.matches]
        return NormalizedScanResult(
            target_url=detection.target_url,
            source=DetectionSource.TECHSPECTER,
            technologies=self._dedupe_technologies(technologies),
            elapsed_ms=elapsed_ms if elapsed_ms is not None else detection.elapsed_ms,
            scripts_analyzed=detection.scripts_analyzed,
        )

    def normalize_wappalyzer(
        self,
        payload: dict[str, Any] | list[Any],
        *,
        target_url: str,
        elapsed_ms: float = 0.0,
    ) -> NormalizedScanResult:
        """Normalize Wappalyzer JSON output."""
        technologies = self._extract_wappalyzer_technologies(payload, target_url=target_url)
        return NormalizedScanResult(
            target_url=target_url,
            source=DetectionSource.WAPPALYZER,
            technologies=self._dedupe_technologies(technologies),
            elapsed_ms=elapsed_ms,
        )

    def _from_techspecter_match(self, match: TechnologyMatch) -> NormalizedTechnology:
        """Map a TechSpecter match to a normalized technology."""
        tech = match.technology
        evidence: list[str] = []
        if match.detection_reason:
            evidence.append(match.detection_reason)
        evidence.extend(match.matched_patterns[:10])
        if match.matched_resources:
            evidence.extend(f"resource:{item}" for item in match.matched_resources[:5])
        if match.evidence_sources:
            evidence.extend(f"source:{item}" for item in match.evidence_sources)

        return NormalizedTechnology(
            id=normalize_technology_id(tech.id),
            name=tech.name,
            category=normalize_category(tech.category),
            version=match.version if match.version else UNKNOWN_VERSION,
            confidence=match.confidence,
            evidence=evidence,
            source=DetectionSource.TECHSPECTER,
            raw_metadata={
                "version_source": match.version_source,
                "version_confidence": match.version_confidence,
                "evidence_count": match.evidence_count,
            },
        )

    def _extract_wappalyzer_technologies(
        self,
        payload: dict[str, Any] | list[Any],
        *,
        target_url: str,
    ) -> list[NormalizedTechnology]:
        """Extract technologies from common Wappalyzer JSON formats."""
        records: list[NormalizedTechnology] = []

        if isinstance(payload, list):
            for entry in payload:
                if not isinstance(entry, dict):
                    continue
                url = str(entry.get("url", target_url))
                if not self._url_matches(url, target_url):
                    continue
                records.extend(
                    self._parse_wappalyzer_technology_list(entry.get("technologies", [])),
                )
            if records:
                return records
            for entry in payload:
                if isinstance(entry, dict) and "slug" in entry:
                    parsed = self._parse_wappalyzer_technology(entry)
                    if parsed is not None:
                        records.append(parsed)
            return records

        if not isinstance(payload, dict):
            logger.warning("Unsupported Wappalyzer payload type: %s", type(payload).__name__)
            return records

        if "technologies" in payload and isinstance(payload["technologies"], list):
            records.extend(self._parse_wappalyzer_technology_list(payload["technologies"]))
            if records:
                return records

        urls = payload.get("urls")
        if isinstance(urls, dict):
            for url, data in urls.items():
                if not self._url_matches(str(url), target_url):
                    continue
                if isinstance(data, dict):
                    records.extend(
                        self._parse_wappalyzer_technology_list(data.get("technologies", [])),
                    )
            if records:
                return records

        applications = payload.get("applications")
        if isinstance(applications, list):
            records.extend(self._parse_wappalyzer_technology_list(applications))

        return records

    def _parse_wappalyzer_technology_list(self, items: Any) -> list[NormalizedTechnology]:
        """Parse a list of Wappalyzer technology objects."""
        if not isinstance(items, list):
            return []
        records: list[NormalizedTechnology] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            parsed = self._parse_wappalyzer_technology(item)
            if parsed is not None:
                records.append(parsed)
        return records

    def _parse_wappalyzer_technology(self, item: dict[str, Any]) -> NormalizedTechnology | None:
        """Parse one Wappalyzer technology object."""
        slug = str(item.get("slug") or item.get("name") or "").strip()
        name = str(item.get("name") or slug).strip()
        if not slug and not name:
            return None

        tech_id = normalize_technology_id(slug or name)
        version_raw = item.get("version")
        version = str(version_raw).strip() if version_raw else UNKNOWN_VERSION
        if not version:
            version = UNKNOWN_VERSION

        category = "unknown"
        categories = item.get("categories")
        if isinstance(categories, list) and categories:
            first = categories[0]
            if isinstance(first, dict):
                category = normalize_category(str(first.get("name") or first.get("slug") or ""))
            else:
                category = normalize_category(str(first))

        confidence_raw = item.get("confidence")
        confidence = float(confidence_raw) if confidence_raw is not None else None

        evidence: list[str] = []
        for key in ("cpe", "website", "icon"):
            if item.get(key):
                evidence.append(f"{key}:{item[key]}")

        return NormalizedTechnology(
            id=tech_id,
            name=name,
            category=category,
            version=version,
            confidence=confidence,
            evidence=evidence,
            source=DetectionSource.WAPPALYZER,
            raw_metadata=dict(item),
        )

    def _dedupe_technologies(
        self,
        technologies: list[NormalizedTechnology],
    ) -> list[NormalizedTechnology]:
        """Keep one record per normalized technology ID (highest confidence)."""
        best: dict[str, NormalizedTechnology] = {}
        for tech in technologies:
            existing = best.get(tech.id)
            if existing is None:
                best[tech.id] = tech
                continue
            existing_conf = existing.confidence or 0.0
            current_conf = tech.confidence or 0.0
            if current_conf >= existing_conf:
                best[tech.id] = tech
        return sorted(best.values(), key=lambda item: item.name.lower())

    def _url_matches(self, candidate: str, target: str) -> bool:
        """Return whether two URLs refer to the same target."""
        return candidate.rstrip("/").lower() == target.rstrip("/").lower()
