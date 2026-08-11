"""Generic post-validation regression tests for version attribution contracts."""

from __future__ import annotations

from techspecter.fingerprinting.detection.version.candidates import (
    VersionCandidate,
    candidate_supports_confirmation,
)
from techspecter.fingerprinting.models import UNKNOWN_VERSION, Technology, TechnologyMatch
from techspecter.technology_intelligence.attribution import AssetAttributor
from techspecter.technology_intelligence.evidence import build_version_attribution
from techspecter.versioning.adapters import (
    extracted_versions_to_candidates,
    resolve_extracted_versions,
)
from techspecter.versioning.models import (
    ExtractedVersion,
    VersionAttributionState,
    VersionConfidenceLevel,
    VersionConflictClass,
    VersionEvidence,
    VersionEvidenceType,
    VersionOwnershipClass,
)
from techspecter.versioning.resolution import resolve_primary_version


def _js(
    version: str,
    *,
    technology_id: str = "tech-a",
    method: VersionEvidenceType = VersionEvidenceType.RUNTIME_CONSTANT,
    url: str | None = None,
    filename: str | None = None,
    confidence: float | None = None,
) -> ExtractedVersion:
    conf, level = (
        (confidence, VersionConfidenceLevel.HIGH)
        if confidence is not None
        else (95.0, VersionConfidenceLevel.HIGH)
    )
    if confidence is None:
        from techspecter.versioning.confidence import score_method

        conf, level = score_method(method)
    resolved_filename = filename or f"{technology_id}.js"
    resolved_url = url or f"https://example.com/{resolved_filename}"
    return ExtractedVersion(
        version=version,
        confidence=conf,
        confidence_level=level,
        method=method,
        evidence=[
            VersionEvidence(
                evidence_type=method,
                matched_value=version,
                pattern=r"version",
                source_url=resolved_url,
                filename=resolved_filename,
            ),
        ],
        extractor_id=f"{technology_id}-extractor",
        source_url=resolved_url,
        filename=resolved_filename,
        technology_id=technology_id,
        # Default ExtractedVersion ownership is OWNED@95; adapters must still
        # gate weak methods and incidental asset affinity generically.
        ownership_class=VersionOwnershipClass.OWNED,
        ownership_confidence=95.0,
        matched_value=version,
    )


def _candidate(
    version: str,
    *,
    technology_id: str = "tech-a",
    source: str = "package",
    ownership_confidence: float = 95.0,
    ownership_class: VersionOwnershipClass = VersionOwnershipClass.OWNED,
    priority: float | None = None,
    source_url: str = "https://example.com/a.js",
    evidence_type: str | None = None,
    method: str | None = None,
) -> VersionCandidate:
    from techspecter.fingerprinting.detection.version.priorities import priority_for_source

    return VersionCandidate(
        version=version,
        source=source,
        priority=priority if priority is not None else priority_for_source(source),
        technology_id=technology_id,
        evidence_id=f"{technology_id}-{version}-{source_url}",
        source_url=source_url,
        evidence_type=evidence_type,
        metadata={"method": method} if method else {},
        ownership_class=ownership_class,
        ownership_confidence=ownership_confidence,
        ownership_basis="test",
        version_confidence=priority if priority is not None else priority_for_source(source),
        technology_confidence=90.0,
        attribution_state=VersionAttributionState.CANDIDATE,
    )


def test_tech_a_strong_js_version_confirms() -> None:
    outcome = resolve_extracted_versions(
        [_js("1.4.2", technology_id="tech-a")],
        technology_id="tech-a",
    )
    assert outcome.primary_version == "1.4.2"
    assert outcome.attribution_state == VersionAttributionState.CONFIRMED


def test_tech_b_strong_js_version_confirms() -> None:
    outcome = resolve_extracted_versions(
        [_js("9.9.1", technology_id="tech-b")],
        technology_id="tech-b",
    )
    assert outcome.primary_version == "9.9.1"


def test_multiple_technologies_in_one_bundle_are_isolated() -> None:
    shared = "https://cdn.example.com/vendor.bundle.js"
    a = resolve_extracted_versions(
        [_js("1.0.0", technology_id="tech-a", url=shared, filename="vendor.bundle.js")],
        technology_id="tech-a",
    )
    b = resolve_extracted_versions(
        [_js("2.0.0", technology_id="tech-b", url=shared, filename="vendor.bundle.js")],
        technology_id="tech-b",
    )
    assert a.primary_version == "1.0.0"
    assert b.primary_version == "2.0.0"
    assert a.primary_version != b.primary_version


def test_version_evidence_does_not_cross_technology_boundaries() -> None:
    owned_a = _candidate("3.1.0", technology_id="tech-a", source_url="https://ex/a.js")
    owned_b = _candidate("3.1.0", technology_id="tech-b", source_url="https://ex/a.js")
    outcome_a = resolve_primary_version([owned_a])
    outcome_b = resolve_primary_version([owned_b])
    assert outcome_a.primary_version == "3.1.0"
    assert outcome_b.primary_version == "3.1.0"
    assert owned_a.technology_id != owned_b.technology_id


def test_same_source_repetition_does_not_inflate_confidence() -> None:
    repeated = [
        _js("4.2.0", url="https://example.com/one.js", filename="one.js") for _ in range(12)
    ]
    outcome = resolve_extracted_versions(repeated, technology_id="tech-a")
    assert outcome.primary_version == "4.2.0"
    assert outcome.independent_source_count == 1


def test_independent_sources_corroborate() -> None:
    outcome = resolve_extracted_versions(
        [
            _js("5.0.0", url="https://example.com/a.js", filename="a.js"),
            _js("5.0.0", url="https://example.com/b.js", filename="b.js"),
        ],
        technology_id="tech-a",
    )
    assert outcome.primary_version == "5.0.0"
    assert outcome.independent_source_count == 2


def test_conflicting_strong_versions_remain_ambiguous() -> None:
    outcome = resolve_extracted_versions(
        [
            _js("6.0.0", url="https://example.com/a.js", filename="a.js"),
            _js("6.1.0", url="https://example.com/b.js", filename="b.js"),
        ],
        technology_id="tech-a",
    )
    assert outcome.primary_version == UNKNOWN_VERSION
    assert set(outcome.alternate_versions) == {"6.0.0", "6.1.0"}


def test_weak_js_literals_do_not_veto_strong_runtime() -> None:
    """Weak methods stamped OWNED@95 must not create false strong conflicts."""
    outcome = resolve_extracted_versions(
        [
            _js(
                "3.6.0",
                method=VersionEvidenceType.RUNTIME_CONSTANT,
                url="https://example.com/lib.js",
                filename="lib.js",
            ),
            _js(
                "1.0.0",
                method=VersionEvidenceType.GENERIC_LITERAL,
                url="https://example.com/noise.js",
                filename="noise.js",
            ),
            _js(
                "2.0.0",
                method=VersionEvidenceType.REFERENCE,
                url="https://example.com/ref.js",
                filename="ref.js",
            ),
        ],
        technology_id="tech-a",
    )
    assert outcome.primary_version == "3.6.0"
    assert outcome.attribution_state == VersionAttributionState.CONFIRMED


def test_weak_evidence_remains_candidate_only() -> None:
    candidates = extracted_versions_to_candidates(
        [_js("7.0.0", method=VersionEvidenceType.GENERIC_LITERAL)],
        technology_id="tech-a",
    )
    assert candidates
    assert not candidate_supports_confirmation(candidates[0])
    outcome = resolve_extracted_versions(
        [_js("7.0.0", method=VersionEvidenceType.GENERIC_LITERAL)],
        technology_id="tech-a",
    )
    assert outcome.primary_version == UNKNOWN_VERSION
    assert outcome.conflict_class == VersionConflictClass.WEAK_ONLY


def test_invalid_versions_remain_rejected() -> None:
    outcome = resolve_extracted_versions(
        [
            ExtractedVersion(
                version="0.0.0",
                confidence=99.0,
                confidence_level=VersionConfidenceLevel.HIGH,
                method=VersionEvidenceType.RUNTIME_CONSTANT,
                evidence=[],
                extractor_id="x",
                source_url="https://example.com/bad.js",
                filename="bad.js",
            ),
            _js("8.1.0"),
        ],
        technology_id="tech-a",
    )
    assert outcome.primary_version == "8.1.0"
    assert "0.0.0" in outcome.rejected_versions


def test_package_and_js_versions_resolve_together() -> None:
    js = extracted_versions_to_candidates(
        [_js("2.5.0", method=VersionEvidenceType.RUNTIME_CONSTANT)],
        technology_id="tech-a",
    )
    package = _candidate(
        "2.5.0",
        source="package",
        source_url="https://example.com/pkg-meta",
        evidence_type="package_identifier",
    )
    outcome = resolve_primary_version((*js, package))
    assert outcome.primary_version == "2.5.0"
    assert outcome.independent_source_count >= 2


def test_js_and_sourcemap_versions_resolve_together() -> None:
    outcome = resolve_extracted_versions(
        [
            _js("3.2.1", method=VersionEvidenceType.RUNTIME_CONSTANT, url="https://ex/a.js"),
            _js(
                "3.2.1",
                method=VersionEvidenceType.SOURCE_MAP,
                url="https://ex/a.js.map",
                filename="a.js.map",
            ),
        ],
        technology_id="tech-a",
    )
    assert outcome.primary_version == "3.2.1"


def test_confidence_axes_remain_independent() -> None:
    outcome = resolve_extracted_versions(
        [_js("1.2.3")],
        technology_id="tech-a",
        technology_confidence=99.0,
    )
    assert outcome.primary_version == "1.2.3"
    assert outcome.ownership_confidence > 0
    assert outcome.version_confidence > 0
    # Technology confidence must not be copied into version confidence blindly.
    assert outcome.version_confidence != 99.0 or outcome.ownership_confidence != 99.0


def test_technology_intelligence_consumes_canonical_resolution() -> None:
    match = TechnologyMatch(
        technology=Technology(id="tech-a", name="Tech A", category="library"),
        version="1.2.3",
        confidence=95.0,
        version_confidence=90.0,
        version_reason="Canonical primary",
        alternate_versions=["1.2.0"],
    )
    attr = build_version_attribution(match, None, attributor=AssetAttributor())
    assert attr is not None
    assert attr.detected_version == "1.2.3"
    assert attr.alternative_candidates == ["1.2.0"]


def test_legacy_and_js_candidate_semantics_align_on_confirmability() -> None:
    js = extracted_versions_to_candidates(
        [_js("4.4.4", method=VersionEvidenceType.PACKAGE_IDENTIFIER)],
        technology_id="tech-a",
    )[0]
    evidence = _candidate(
        "4.4.4",
        source="package",
        evidence_type="package_identifier",
        method="package_identifier",
    )
    assert candidate_supports_confirmation(js)
    assert candidate_supports_confirmation(evidence)


def test_tech_c_package_version_confirms() -> None:
    outcome = resolve_extracted_versions(
        [_js("2.3.4", technology_id="tech-c", method=VersionEvidenceType.PACKAGE_IDENTIFIER)],
        technology_id="tech-c",
    )
    assert outcome.primary_version == "2.3.4"
    assert outcome.attribution_state == VersionAttributionState.CONFIRMED


def test_explicit_banner_on_affinity_asset_confirms() -> None:
    """Owned banner evidence on a technology-named asset remains primary."""
    outcome = resolve_extracted_versions(
        [
            _js(
                "3.6.0",
                technology_id="generic-library",
                method=VersionEvidenceType.BANNER,
                url="https://cdn.example.com/generic-library-3.6.0.min.js",
                filename="generic-library-3.6.0.min.js",
            ),
        ],
        technology_id="generic-library",
    )
    assert outcome.primary_version == "3.6.0"
    assert outcome.attribution_state == VersionAttributionState.CONFIRMED
    assert outcome.confidence > 0.0


def test_incidental_banner_cannot_veto_owned_banner() -> None:
    """Incidental banner mentions in unrelated assets must not create strong conflicts."""
    outcome = resolve_extracted_versions(
        [
            _js(
                "3.6.0",
                technology_id="generic-library",
                method=VersionEvidenceType.BANNER,
                url="https://cdn.example.com/generic-library-3.6.0.min.js",
                filename="generic-library-3.6.0.min.js",
            ),
            _js(
                "1.2.3",
                technology_id="generic-library",
                method=VersionEvidenceType.BANNER,
                url="https://cdn.example.com/app.bundle.js",
                filename="app.bundle.js",
            ),
        ],
        technology_id="generic-library",
    )
    assert outcome.primary_version == "3.6.0"
    assert outcome.attribution_state == VersionAttributionState.CONFIRMED
    assert outcome.conflict_class in {
        VersionConflictClass.WEAK_ALTERNATE,
        VersionConflictClass.NO_CONFLICT,
    }


def test_confirmed_version_not_lost_to_weaker_unrelated_candidate() -> None:
    outcome = resolve_extracted_versions(
        [
            _js(
                "3.6.0",
                technology_id="library-a",
                method=VersionEvidenceType.RUNTIME_CONSTANT,
                filename="library-a.js",
            ),
            _js(
                "9.9.9",
                technology_id="library-a",
                method=VersionEvidenceType.GENERIC_LITERAL,
                filename="noise.js",
                url="https://example.com/noise.js",
            ),
            _js(
                "0.1.0",
                technology_id="library-a",
                method=VersionEvidenceType.BANNER,
                filename="unrelated-app.js",
                url="https://example.com/unrelated-app.js",
            ),
        ],
        technology_id="library-a",
    )
    assert outcome.primary_version == "3.6.0"
    assert outcome.attribution_state == VersionAttributionState.CONFIRMED


def test_empty_match_scope_still_resolves_from_available_resources() -> None:
    from techspecter.versioning.engine import (
        JavaScriptResourceContent,
        VersionDetectionEngine,
        resources_for_match,
    )

    match = TechnologyMatch(
        technology=Technology(id="jquery", name="jQuery", category="javascript-libraries"),
        confidence=100.0,
    )
    resources = [
        JavaScriptResourceContent(
            url="https://cdn.example.com/jquery-3.6.0.min.js",
            filename="jquery-3.6.0.min.js",
            content="/*! jQuery v3.6.0 | (c) OpenJS Foundation */",
        ),
        JavaScriptResourceContent(
            url="https://cdn.example.com/app.js",
            filename="app.js",
            content="/* mentions jQuery v1.4.0 historically */\njQuery v1.4.0\n",
        ),
    ]
    scoped = resources_for_match(match, resources)
    assert len(scoped) == 2
    result = VersionDetectionEngine().detect_for_technology("jquery", scoped)
    assert result is not None
    assert result.version == "3.6.0"
    assert result.confidence > 0.0


def test_js_path_and_evidence_path_equivalent_semantics_for_owned_package() -> None:
    js = extracted_versions_to_candidates(
        [_js("8.8.8", method=VersionEvidenceType.PACKAGE_IDENTIFIER, technology_id="lib-x")],
        technology_id="lib-x",
    )
    evidence = (
        _candidate(
            "8.8.8",
            technology_id="lib-x",
            source="package",
            evidence_type="package_identifier",
            method="package_identifier",
        ),
    )
    js_outcome = resolve_primary_version(js)
    evidence_outcome = resolve_primary_version(evidence)
    assert js_outcome.primary_version == evidence_outcome.primary_version == "8.8.8"
    assert js_outcome.attribution_state == evidence_outcome.attribution_state


def test_match_provenance_breaks_equal_affinity_conflicts() -> None:
    """Primary TechnologyMatch source selects among equally strong owned assets."""
    owned_a = _js(
        "3.6.0",
        technology_id="examplelib",
        method=VersionEvidenceType.BANNER,
        url="https://cdn.example.com/examplelib-3.6.0.min.js",
        filename="examplelib-3.6.0.min.js",
    )
    owned_b = _js(
        "3.5.1",
        technology_id="examplelib",
        method=VersionEvidenceType.BANNER,
        url="https://cdn.example.com/examplelib-3.5.1.min.js",
        filename="examplelib-3.5.1.min.js",
    )
    without_pref = resolve_extracted_versions(
        [owned_a, owned_b],
        technology_id="examplelib",
    )
    assert without_pref.primary_version == UNKNOWN_VERSION
    assert set(without_pref.alternate_versions) == {"3.5.1", "3.6.0"}

    with_pref = resolve_extracted_versions(
        [owned_a, owned_b],
        technology_id="examplelib",
        preferred_source_urls=["https://cdn.example.com/examplelib-3.6.0.min.js"],
        preferred_filenames=["examplelib-3.6.0.min.js"],
    )
    assert with_pref.primary_version == "3.6.0"
    assert with_pref.attribution_state == VersionAttributionState.CONFIRMED
    assert with_pref.confidence > 0.0
    assert "3.5.1" in with_pref.alternate_versions


def test_engine_uses_match_provenance_for_conflicting_owned_assets() -> None:
    from techspecter.versioning.engine import JavaScriptResourceContent, VersionDetectionEngine

    resources = [
        JavaScriptResourceContent(
            url="https://code.example.com/examplelib-3.6.0.min.js",
            filename="examplelib-3.6.0.min.js",
            content="/*! ExampleLib v3.6.0 */\n",
        ),
        JavaScriptResourceContent(
            url="https://cdn.example.com/examplelib-3.5.1.min.dc5e7f18c8.js",
            filename="examplelib-3.5.1.min.dc5e7f18c8.js",
            content="/*! ExampleLib v3.5.1 */\n",
        ),
    ]
    # Register temporary extractor via direct resolve path using jquery-like pattern.
    from techspecter.versioning.extractors.base import ExtractionPattern, PatternVersionExtractor
    import re

    class _ExampleLib(PatternVersionExtractor):
        technology_id = "examplelib"
        content_markers = frozenset({"ExampleLib"})
        patterns = (
            ExtractionPattern(
                re.compile(r"ExampleLib\s+v?([\d.]+)"),
                VersionEvidenceType.BANNER,
                "banner",
            ),
        )

    engine = VersionDetectionEngine()
    engine.registry.register(_ExampleLib())
    result = engine.detect_for_technology(
        "examplelib",
        resources,
        preferred_source_url="https://code.example.com/examplelib-3.6.0.min.js",
        preferred_filename="examplelib-3.6.0.min.js",
    )
    assert result is not None
    assert result.version == "3.6.0"
    assert result.confidence > 0.0
    assert "3.5.1" in result.alternate_versions


def test_equal_owned_conflicts_without_provenance_remain_ambiguous() -> None:
    outcome = resolve_extracted_versions(
        [
            _js(
                "2.0.0",
                technology_id="lib-y",
                method=VersionEvidenceType.BANNER,
                filename="lib-y-2.0.0.min.js",
                url="https://cdn.example.com/lib-y-2.0.0.min.js",
            ),
            _js(
                "1.0.0",
                technology_id="lib-y",
                method=VersionEvidenceType.BANNER,
                filename="lib-y-1.0.0.min.js",
                url="https://cdn.example.com/lib-y-1.0.0.min.js",
            ),
        ],
        technology_id="lib-y",
    )
    assert outcome.primary_version == UNKNOWN_VERSION
    assert outcome.conflict_class in {
        VersionConflictClass.AMBIGUOUS,
        VersionConflictClass.STRONG_CONFLICT,
    }
