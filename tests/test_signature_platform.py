"""Tests for Phase 4 signature intelligence platform."""

from __future__ import annotations

from techspecter.fingerprinting.signatures.benchmark import BenchmarkRunner, render_benchmark_report
from techspecter.fingerprinting.signatures.catalog import build_catalog
from techspecter.fingerprinting.signatures.compiler import compile_signature
from techspecter.fingerprinting.signatures.loader import TechnologySignatureLoader
from techspecter.fingerprinting.signatures.models import (
    SignatureIndicator,
    SignatureIndicators,
    TechnologySignature,
)
from techspecter.fingerprinting.signatures.validator import SignatureValidator


def test_catalog_covers_major_technologies() -> None:
    """Catalog should include broad modern technology coverage."""
    catalog = build_catalog()
    ids = {item.id for item in catalog}
    assert len(catalog) >= 80
    for tech_id in (
        "react",
        "nextjs",
        "vue",
        "angular",
        "sveltekit",
        "tailwindcss",
        "wordpress",
        "shopify",
        "stripe",
        "cloudflare",
        "google-analytics",
    ):
        assert tech_id in ids


def test_loader_compiles_indicators_into_rules() -> None:
    """Loader should compile typed indicators into detection rules."""
    react = next(
        item
        for item in TechnologySignatureLoader(include_catalog=True).load_all()
        if item.id == "react"
    )
    assert react.required_rules
    assert react.positive_rules
    assert any(rule.target == "runtime" for rule in react.positive_rules)


def test_signature_validator_accepts_quality_catalog_signatures() -> None:
    """Catalog signatures should pass platform validation."""
    validator = SignatureValidator()
    for signature in build_catalog()[:20]:
        compiled = compile_signature(signature)
        warnings = validator.validate(compiled)
        assert not any(item.startswith("CRITICAL:") for item in warnings)


def test_signature_schema_supports_indicator_groups() -> None:
    """Extended schema should support typed indicator groups."""
    signature = TechnologySignature(
        id="demo",
        name="Demo",
        category="test",
        required_rules=(),
        optional_evidence=SignatureIndicators(
            runtime=(SignatureIndicator(id="rt", pattern="demo-runtime"),),
            package=(SignatureIndicator(id="pkg", pattern="demo-pkg"),),
        ),
        required_evidence=SignatureIndicators(
            content=(SignatureIndicator(id="req", pattern="demo-required"),),
        ),
    )
    compiled = compile_signature(signature)
    assert len(compiled.positive_rules) >= 2
    assert len(compiled.required_rules) >= 1


def test_loader_categories_group_signatures() -> None:
    """Loader should expose category counts."""
    categories = TechnologySignatureLoader().categories()
    assert categories
    assert sum(categories.values()) >= 80


def test_regression_dataset_benchmark_runs() -> None:
    """Benchmark runner should execute regression dataset."""
    report = BenchmarkRunner().run()
    assert report.signature_count >= 80
    assert report.metrics.precision > 0
    assert len(report.samples) >= 10


def test_benchmark_report_renders_markdown() -> None:
    """Benchmark reporter should render markdown output."""
    report = BenchmarkRunner().run()
    text = render_benchmark_report(report)
    assert "# TechSpecter Signature Intelligence Benchmark" in text
    assert "Precision" in text
    assert "Wappalyzer" in text


def test_angular_negative_regression_sample() -> None:
    """Regression sample for zone.js-only should not detect Angular."""
    report = BenchmarkRunner().run()
    sample = next(item for item in report.samples if item.sample_id == "angular-zone-only-negative")
    assert "angular" not in sample.detected


def test_nextjs_regression_includes_react_dependency() -> None:
    """Next.js regression sample should detect React dependency."""
    report = BenchmarkRunner().run()
    sample = next(item for item in report.samples if item.sample_id == "nextjs-app")
    assert "nextjs" in sample.detected
    assert "react" in sample.detected
