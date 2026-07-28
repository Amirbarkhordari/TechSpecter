"""Tests for next-generation signature schema models."""

from __future__ import annotations

from techspecter.fingerprinting.signatures.models import (
    SignatureRule,
    TechnologySignature,
    VersionExtractorSpec,
)


def test_technology_signature_schema_fields() -> None:
    """TechnologySignature should expose rule groups and version extractor placeholders."""
    signature = TechnologySignature(
        id="example",
        name="Example",
        category="Framework",
        positive_rules=(SignatureRule(id="pos-1", matcher="string", pattern="ExampleGlobal"),),
        negative_rules=(SignatureRule(id="neg-1", matcher="string", pattern="NotExample"),),
        required_rules=(SignatureRule(id="req-1", matcher="regex", pattern="Example\\.init"),),
        optional_rules=(SignatureRule(id="opt-1", matcher="filename", pattern="example\\.js"),),
        references=("https://example.com/docs",),
        version_extractors=(
            VersionExtractorSpec(id="ver-1", pattern="Example/(\\d+)", enabled=False),
        ),
    )
    assert signature.id == "example"
    assert len(signature.positive_rules) == 1
    assert signature.version_extractors[0].enabled is False
    assert signature.minimum_score == 40.0
