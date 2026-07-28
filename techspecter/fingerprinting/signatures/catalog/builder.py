"""Compact signature builder for catalog definitions."""

from __future__ import annotations

from typing import Any

from techspecter.fingerprinting.signatures.models import (
    SignatureIndicator,
    SignatureIndicators,
    SignatureRule,
    TechnologySignature,
    VersionExtractorSpec,
)


class SignatureBuilder:
    """Fluent builder for technology signatures."""

    def __init__(
        self,
        *,
        id: str,
        name: str,
        category: str,
        subcategory: str | None = None,
        vendor: str | None = None,
        website: str | None = None,
        priority: int = 80,
        minimum_score: float = 45.0,
        description: str | None = None,
    ) -> None:
        """Initialize builder."""
        self._data: dict[str, Any] = {
            "id": id,
            "name": name,
            "category": category,
            "subcategory": subcategory,
            "vendor": vendor,
            "website": website,
            "priority": priority,
            "minimum_score": minimum_score,
            "description": description,
            "aliases": [],
            "dependencies": [],
            "conflicts_with": [],
            "references": [],
            "supported_versions": [],
            "required_rules": [],
            "positive_rules": [],
            "optional_rules": [],
            "negative_rules": [],
            "version_extractors": [],
            "required_evidence": SignatureIndicators(),
            "optional_evidence": SignatureIndicators(),
            "negative_evidence": SignatureIndicators(),
        }

    def alias(self, *names: str) -> SignatureBuilder:
        """Add aliases."""
        aliases = list(self._data["aliases"])
        aliases.extend(names)
        self._data["aliases"] = aliases
        return self

    def depends(self, *tech_ids: str) -> SignatureBuilder:
        """Add dependencies."""
        deps = list(self._data["dependencies"])
        deps.extend(tech_ids)
        self._data["dependencies"] = deps
        return self

    def conflicts(self, *tech_ids: str) -> SignatureBuilder:
        """Add conflict technology IDs."""
        conflicts = list(self._data["conflicts_with"])
        conflicts.extend(tech_ids)
        self._data["conflicts_with"] = conflicts
        return self

    def refs(self, *urls: str) -> SignatureBuilder:
        """Add reference URLs."""
        refs = list(self._data["references"])
        refs.extend(urls)
        self._data["references"] = refs
        return self

    def required_rule(self, rule: dict[str, object] | SignatureRule) -> SignatureBuilder:
        """Add required rule."""
        rules = list(self._data["required_rules"])
        rules.append(rule)
        self._data["required_rules"] = rules
        return self

    def positive_rule(self, rule: dict[str, object] | SignatureRule) -> SignatureBuilder:
        """Add positive rule."""
        rules = list(self._data["positive_rules"])
        rules.append(rule)
        self._data["positive_rules"] = rules
        return self

    def negative_rule(self, rule: dict[str, object] | SignatureRule) -> SignatureBuilder:
        """Add negative rule."""
        rules = list(self._data["negative_rules"])
        rules.append(rule)
        self._data["negative_rules"] = rules
        return self

    def optional(
        self,
        *,
        runtime: tuple[SignatureIndicator, ...] = (),
        bundle: tuple[SignatureIndicator, ...] = (),
        html: tuple[SignatureIndicator, ...] = (),
        http: tuple[SignatureIndicator, ...] = (),
        header: tuple[SignatureIndicator, ...] = (),
        manifest: tuple[SignatureIndicator, ...] = (),
        sourcemap: tuple[SignatureIndicator, ...] = (),
        package: tuple[SignatureIndicator, ...] = (),
        metadata: tuple[SignatureIndicator, ...] = (),
        content: tuple[SignatureIndicator, ...] = (),
    ) -> SignatureBuilder:
        """Add optional evidence indicators."""
        current = self._data.get("optional_evidence", SignatureIndicators())
        assert isinstance(current, SignatureIndicators)
        self._data["optional_evidence"] = SignatureIndicators(
            runtime=(*current.runtime, *runtime),
            bundle=(*current.bundle, *bundle),
            html=(*current.html, *html),
            http=(*current.http, *http),
            header=(*current.header, *header),
            manifest=(*current.manifest, *manifest),
            sourcemap=(*current.sourcemap, *sourcemap),
            package=(*current.package, *package),
            metadata=(*current.metadata, *metadata),
            content=(*current.content, *content),
        )
        return self

    def required(
        self,
        *,
        runtime: tuple[SignatureIndicator, ...] = (),
        bundle: tuple[SignatureIndicator, ...] = (),
        html: tuple[SignatureIndicator, ...] = (),
        http: tuple[SignatureIndicator, ...] = (),
        header: tuple[SignatureIndicator, ...] = (),
        manifest: tuple[SignatureIndicator, ...] = (),
        sourcemap: tuple[SignatureIndicator, ...] = (),
        package: tuple[SignatureIndicator, ...] = (),
        metadata: tuple[SignatureIndicator, ...] = (),
        content: tuple[SignatureIndicator, ...] = (),
    ) -> SignatureBuilder:
        """Add required evidence indicators."""
        current = self._data.get("required_evidence", SignatureIndicators())
        assert isinstance(current, SignatureIndicators)
        self._data["required_evidence"] = SignatureIndicators(
            runtime=(*current.runtime, *runtime),
            bundle=(*current.bundle, *bundle),
            html=(*current.html, *html),
            http=(*current.http, *http),
            header=(*current.header, *header),
            manifest=(*current.manifest, *manifest),
            sourcemap=(*current.sourcemap, *sourcemap),
            package=(*current.package, *package),
            metadata=(*current.metadata, *metadata),
            content=(*current.content, *content),
        )
        return self

    def negative(
        self,
        *,
        runtime: tuple[SignatureIndicator, ...] = (),
        content: tuple[SignatureIndicator, ...] = (),
    ) -> SignatureBuilder:
        """Add negative evidence indicators."""
        current = self._data.get("negative_evidence", SignatureIndicators())
        assert isinstance(current, SignatureIndicators)
        self._data["negative_evidence"] = SignatureIndicators(
            runtime=(*current.runtime, *runtime),
            content=(*current.content, *content),
        )
        return self

    def versions(self, *extractors: VersionExtractorSpec) -> SignatureBuilder:
        """Add version extractors."""
        current = list(self._data["version_extractors"])
        current.extend(extractors)
        self._data["version_extractors"] = current
        return self

    def build(self) -> TechnologySignature:
        """Build immutable technology signature."""
        return TechnologySignature.model_validate(self._data)
