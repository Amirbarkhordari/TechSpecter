"""Evidence aggregation across detection providers."""

from __future__ import annotations

from techspecter.fingerprinting.models import PatternEvidence
from techspecter.providers.models import ProviderEvidenceItem, ProviderMatch

_EVIDENCE_CATEGORY_WEIGHTS: dict[str, float] = {
    "runtime": 90.0,
    "javascript": 85.0,
    "html": 80.0,
    "headers": 75.0,
    "wappalyzer": 70.0,
    "retirejs": 70.0,
    "resource": 65.0,
    "source": 60.0,
    "other": 50.0,
}

_PROVIDER_CATEGORIES: dict[str, str] = {
    "techspecter": "runtime",
    "wappalyzer": "wappalyzer",
    "retirejs": "retirejs",
}


class ProviderEvidenceAggregator:
    """Merge evidence from all providers with source attribution."""

    def aggregate(self, matches: list[ProviderMatch]) -> tuple[list[str], list[PatternEvidence]]:
        """Return deduplicated string evidence and structured PatternEvidence."""
        items = self.collect_items(matches)
        strings: list[str] = []
        seen_strings: set[str] = set()
        structured: list[PatternEvidence] = []
        seen_structured: set[tuple[str, str, str]] = set()

        for item in items:
            label = self._format_item(item)
            if label not in seen_strings:
                seen_strings.add(label)
                strings.append(label)

            key = (item.source, item.category, item.detail)
            if key in seen_structured:
                continue
            seen_structured.add(key)
            structured.append(
                PatternEvidence(
                    matcher=item.category,
                    pattern=item.detail,
                    weight=_EVIDENCE_CATEGORY_WEIGHTS.get(item.category, 50.0),
                    detail=f"{item.source}:{item.detail}" if item.source else item.detail,
                ),
            )
        return strings, structured

    def collect_items(self, matches: list[ProviderMatch]) -> list[ProviderEvidenceItem]:
        """Collect structured evidence items from provider matches."""
        items: list[ProviderEvidenceItem] = []
        for match in matches:
            if match.evidence_items:
                items.extend(match.evidence_items)
                continue
            items.extend(self._items_from_strings(match))
        return items

    def _items_from_strings(self, match: ProviderMatch) -> list[ProviderEvidenceItem]:
        """Build evidence items from legacy string evidence."""
        default_category = _PROVIDER_CATEGORIES.get(match.provider, "other")
        parsed: list[ProviderEvidenceItem] = []
        for raw in match.evidence:
            category, detail, location = self._parse_evidence_string(raw, default_category)
            parsed.append(
                ProviderEvidenceItem(
                    source=match.provider,
                    category=category,
                    detail=detail,
                    location=location,
                    detection_method=match.detection_method,
                ),
            )
        return parsed

    def _parse_evidence_string(
        self,
        raw: str,
        default_category: str,
    ) -> tuple[str, str, str | None]:
        """Parse prefixed evidence strings into category and detail."""
        if ":" in raw:
            prefix, detail = raw.split(":", 1)
            category = prefix.strip().lower()
            if category in _EVIDENCE_CATEGORY_WEIGHTS:
                return category, detail.strip(), None
            if category in {"resource", "source", "retire.js"}:
                mapped = "retirejs" if category == "retire.js" else category
                return mapped, detail.strip(), None
        return default_category, raw.strip(), None

    def _format_item(self, item: ProviderEvidenceItem) -> str:
        """Format an evidence item for report strings."""
        if item.location:
            return f"{item.category}:{item.detail} ({item.location})"
        return f"{item.category}:{item.detail}"
