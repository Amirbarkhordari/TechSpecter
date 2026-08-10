"""Regression tests for invalid package-identity false positives."""

from __future__ import annotations

from datetime import UTC, datetime

from techspecter.fingerprinting.detection.candidates import CandidateDetectionPipeline
from techspecter.fingerprinting.detection.candidates.mappings import (
    is_valid_package_identity,
    resolve_package_identity,
)
from techspecter.fingerprinting.evidence.models import (
    Evidence,
    EvidenceCollection,
    EvidenceSource,
    EvidenceType,
    summarize_evidence,
)
from techspecter.fingerprinting.javascript.extractors.package import extract_package_findings
from techspecter.fingerprinting.javascript.models import (
    JavaScriptResource,
    ParsedImport,
    ParsedScript,
    ParseStrategy,
)


def test_prose_and_css_utilities_are_not_package_identities() -> None:
    invalid = [
        "we are looking for an android app",
        "inline-flex items-center justify-center",
        "bg-primary",
        "bg-destructive",
        "text",
        "chunks",
        "_next",
        "static",
        "media",
        "image",
        "a",
        "www.w3.org",
        "v3.38.1",
        "url(\"data:image",
        "github.com",
    ]
    for value in invalid:
        assert is_valid_package_identity(value) is False, value
        assert resolve_package_identity(value) is None, value


def test_valid_packages_still_resolve() -> None:
    assert is_valid_package_identity("react")
    assert is_valid_package_identity("@scope/package")
    assert is_valid_package_identity("some-new-library")
    assert resolve_package_identity("react")[0] == "react"
    assert resolve_package_identity("some-new-library")[0] == "package:some-new-library"


def test_invalid_package_references_do_not_confirm() -> None:
    items = [
        Evidence(
            source=EvidenceSource.JAVASCRIPT,
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            collector="test",
            file="app.js",
            url="https://example.com/app.js",
            matched_value=value,
            timestamp=datetime.now(UTC),
        )
        for value in ("bg-primary", "chunks", "inline-flex items-center", "static")
    ]
    collection = EvidenceCollection(
        target_url="https://example.com/",
        items=tuple(items),
        summary=summarize_evidence(items),
    )
    pipeline = CandidateDetectionPipeline()
    assert pipeline.generate_candidates(collection) == []
    assert pipeline.detect(collection).matches == []


def test_package_extractor_filters_invalid_imports() -> None:
    resource = JavaScriptResource(
        url="https://example.com/app.js",
        filename="app.js",
        content="import x from 'react'; const c = 'bg-primary';",
    )
    parsed = ParsedScript(
        resource=resource,
        imports=(
            ParsedImport(module="react", raw="import x from 'react'", line_number=1),
            ParsedImport(module="bg-primary", raw="import y from 'bg-primary'", line_number=1),
            ParsedImport(
                module="inline-flex items-center",
                raw="import z from 'inline-flex items-center'",
                line_number=1,
            ),
            ParsedImport(module="./utils", raw="import u from './utils'", line_number=1),
        ),
        parse_strategy=ParseStrategy.FULL,
    )
    findings = extract_package_findings(parsed, content=resource.content)
    refs = [
        item.matched_value
        for item in findings
        if item.evidence_type == EvidenceType.PACKAGE_REFERENCE.value
    ]
    assert "react" in refs
    assert "bg-primary" not in refs
    assert "inline-flex items-center" not in refs
    assert "./utils" not in refs
