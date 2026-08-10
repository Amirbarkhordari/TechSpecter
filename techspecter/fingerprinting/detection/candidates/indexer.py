"""Index evidence by structured discovery keys for candidate generation."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from techspecter.fingerprinting.evidence.models import Evidence, EvidenceCollection, EvidenceType

# Evidence types eligible for candidate-oriented indexing.
_INDEXABLE_TYPES = frozenset(
    {
        EvidenceType.PACKAGE_REFERENCE,
        EvidenceType.PACKAGE_MARKER,
        EvidenceType.RUNTIME_PATTERN,
        EvidenceType.IMPORT_EXPORT,
        EvidenceType.AST_EXTRACTION,
        EvidenceType.BUNDLE_MARKER,
        EvidenceType.BUNDLE_RUNTIME,
        EvidenceType.HTTP_HEADER,
        EvidenceType.HTTP_METADATA,
        EvidenceType.BANNER,
        EvidenceType.MANIFEST,
        EvidenceType.SOURCE_MAP_METADATA,
        EvidenceType.VERSION_CANDIDATE,
        EvidenceType.CSS_MARKER,
        EvidenceType.HTML_MARKER,
    },
)


@dataclass(slots=True)
class EvidenceIndex:
    """Structured indexes over an evidence collection."""

    by_type: dict[str, list[Evidence]] = field(default_factory=lambda: defaultdict(list))
    by_package: dict[str, list[Evidence]] = field(default_factory=lambda: defaultdict(list))
    by_runtime_family: dict[str, list[Evidence]] = field(
        default_factory=lambda: defaultdict(list),
    )
    by_bundle_marker: dict[str, list[Evidence]] = field(
        default_factory=lambda: defaultdict(list),
    )
    by_bundler: dict[str, list[Evidence]] = field(default_factory=lambda: defaultdict(list))
    by_http_header: dict[str, list[Evidence]] = field(
        default_factory=lambda: defaultdict(list),
    )
    by_import: dict[str, list[Evidence]] = field(default_factory=lambda: defaultdict(list))
    by_css_family: dict[str, list[Evidence]] = field(default_factory=lambda: defaultdict(list))
    by_html_family: dict[str, list[Evidence]] = field(default_factory=lambda: defaultdict(list))
    all_items: tuple[Evidence, ...] = ()

    def items_for_type(self, evidence_type: EvidenceType | str) -> list[Evidence]:
        """Return evidence items for a type."""
        key = evidence_type.value if isinstance(evidence_type, EvidenceType) else evidence_type
        return list(self.by_type.get(key, []))


class EvidenceIndexer:
    """Build discovery indexes without indexing arbitrary string literals."""

    def index(self, collection: EvidenceCollection) -> EvidenceIndex:
        """Index structured evidence for candidate generation."""
        result = EvidenceIndex(all_items=collection.items)
        for item in collection.items:
            if item.evidence_type not in _INDEXABLE_TYPES:
                continue
            type_key = item.evidence_type.value
            result.by_type[type_key].append(item)

            if item.evidence_type in {
                EvidenceType.PACKAGE_REFERENCE,
                EvidenceType.PACKAGE_MARKER,
            }:
                key = (item.matched_value or "").strip().lower()
                if key:
                    result.by_package[key].append(item)

            if item.evidence_type == EvidenceType.SOURCE_MAP_METADATA:
                value = (item.matched_value or "").replace("\\", "/")
                if "node_modules/" in value.lower():
                    result.by_package[value.lower()].append(item)

            if item.evidence_type == EvidenceType.VERSION_CANDIDATE:
                package = str(item.metadata.get("package", "")).strip().lower()
                if package:
                    result.by_package[package].append(item)

            if item.evidence_type == EvidenceType.RUNTIME_PATTERN:
                family = str(item.metadata.get("runtime_family", "")).strip().lower()
                if family:
                    result.by_runtime_family[family].append(item)
                marker = (item.matched_value or "").strip()
                if marker:
                    result.by_bundle_marker[marker].append(item)

            if item.evidence_type in {
                EvidenceType.BUNDLE_MARKER,
                EvidenceType.BUNDLE_RUNTIME,
            }:
                marker = (item.matched_value or "").strip()
                if marker:
                    result.by_bundle_marker[marker].append(item)
                bundler = str(item.metadata.get("bundler", "")).strip().lower()
                if bundler:
                    result.by_bundler[bundler].append(item)

            if item.evidence_type == EvidenceType.HTTP_HEADER:
                header = str(
                    item.metadata.get("header") or item.matched_pattern or "",
                ).strip().lower()
                if header:
                    result.by_http_header[header].append(item)

            if item.evidence_type in {
                EvidenceType.IMPORT_EXPORT,
                EvidenceType.AST_EXTRACTION,
            }:
                module = (item.matched_value or "").strip().lower()
                if module and item.metadata.get("kind") in {None, "import", "dynamic_import"}:
                    result.by_import[module].append(item)

            if item.evidence_type == EvidenceType.CSS_MARKER:
                family = str(item.metadata.get("css_family", "")).strip().lower()
                if family:
                    result.by_css_family[family].append(item)

            if item.evidence_type == EvidenceType.HTML_MARKER:
                family = str(item.metadata.get("html_family", "")).strip().lower()
                if family:
                    result.by_html_family[family].append(item)

        return result
