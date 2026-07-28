"""Tests for Benchmark & Validation subsystem."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from techspecter.benchmark.comparator import ComparisonEngine
from techspecter.benchmark.gap_analysis import GapAnalyzer
from techspecter.benchmark.models import (
    DetectionSource,
    NormalizedScanResult,
    NormalizedTechnology,
)
from techspecter.benchmark.normalizer import ResultNormalizer
from techspecter.benchmark.reporter import render_console, render_json, render_markdown
from techspecter.benchmark.runner import BenchmarkRunner
from techspecter.benchmark.statistics import StatisticsCalculator
from techspecter.benchmark.utils import normalize_technology_id
from techspecter.benchmark.wappalyzer import WappalyzerExecutor
from techspecter.cli import app
from techspecter.fingerprinting.models import DetectionResult, Technology, TechnologyMatch

runner = CliRunner()


def _ts_detection(*tech_ids: str, target_url: str = "https://example.com") -> DetectionResult:
    """Build a minimal TechSpecter detection result."""
    matches = [
        TechnologyMatch(
            technology=Technology(id=tech_id, name=tech_id.title(), category="frameworks"),
            version="1.0.0" if tech_id == "react" else "Unknown",
            confidence=90.0,
            detection_reason="test evidence",
            matched_patterns=["runtime:test"],
            evidence_count=2,
        )
        for tech_id in tech_ids
    ]
    return DetectionResult(target_url=target_url, matches=matches, scripts_analyzed=3)


def _wap_payload(*slugs: str, target_url: str = "https://example.com") -> list[dict[str, object]]:
    """Build minimal Wappalyzer JSON payload."""
    return [
        {
            "url": target_url,
            "technologies": [
                {
                    "slug": slug,
                    "name": slug.title(),
                    "version": "1.0.0" if slug == "react" else "",
                    "confidence": 100,
                    "categories": [{"name": "JavaScript frameworks"}],
                }
                for slug in slugs
            ],
        },
    ]


def test_normalize_technology_id_aliases() -> None:
    """Technology IDs should normalize common aliases."""
    assert normalize_technology_id("Next.js") == "nextjs"
    assert normalize_technology_id("react") == "react"
    assert normalize_technology_id("Tailwind CSS") == "tailwindcss"


def test_normalizer_techspecter() -> None:
    """TechSpecter detection should normalize into benchmark structure."""
    detection = _ts_detection("react", "webpack")
    result = ResultNormalizer().normalize_techspecter(detection)
    assert result.source == DetectionSource.TECHSPECTER
    assert len(result.technologies) == 2
    assert result.technologies[0].evidence


def test_normalizer_wappalyzer_list_format() -> None:
    """Wappalyzer list JSON format should normalize correctly."""
    payload = _wap_payload("react", "nginx")
    result = ResultNormalizer().normalize_wappalyzer(
        payload,
        target_url="https://example.com",
    )
    assert result.source == DetectionSource.WAPPALYZER
    ids = {tech.id for tech in result.technologies}
    assert "react" in ids
    assert "nginx" in ids


def test_normalizer_wappalyzer_urls_format() -> None:
    """Wappalyzer urls-key JSON format should normalize correctly."""
    payload = {
        "urls": {
            "https://example.com": {
                "technologies": [
                    {
                        "slug": "vue",
                        "name": "Vue.js",
                        "version": "3.4.0",
                        "categories": [{"name": "JavaScript frameworks"}],
                    },
                ],
            },
        },
    }
    result = ResultNormalizer().normalize_wappalyzer(payload, target_url="https://example.com")
    assert any(tech.id == "vue" for tech in result.technologies)


def test_comparison_matched_and_missing() -> None:
    """Comparator should identify matched, missing, and extra technologies."""
    ts = NormalizedScanResult(
        target_url="https://example.com",
        source=DetectionSource.TECHSPECTER,
        technologies=[
            NormalizedTechnology(
                id="react",
                name="React",
                category="frameworks",
                version="1.0.0",
                confidence=90.0,
                source=DetectionSource.TECHSPECTER,
            ),
            NormalizedTechnology(
                id="webpack",
                name="Webpack",
                category="build-tools",
                version="Unknown",
                confidence=80.0,
                source=DetectionSource.TECHSPECTER,
            ),
        ],
    )
    wap = NormalizedScanResult(
        target_url="https://example.com",
        source=DetectionSource.WAPPALYZER,
        technologies=[
            NormalizedTechnology(
                id="react",
                name="React",
                category="frameworks",
                version="1.0.0",
                confidence=100.0,
                source=DetectionSource.WAPPALYZER,
            ),
            NormalizedTechnology(
                id="nginx",
                name="Nginx",
                category="web-servers",
                version="Unknown",
                confidence=100.0,
                source=DetectionSource.WAPPALYZER,
            ),
        ],
    )
    engine = ComparisonEngine()
    matched, ts_only, wap_only = engine.compare(ts, wap)
    assert len(matched) == 1
    assert matched[0].technology_id == "react"
    assert len(ts_only) == 1
    assert ts_only[0].technology_id == "webpack"
    assert len(wap_only) == 1
    assert wap_only[0].technology_id == "nginx"


def test_version_comparison_unknown_techspecter() -> None:
    """Version comparison should flag Unknown TechSpecter versions."""
    engine = ComparisonEngine()
    matched, _, _ = engine.compare(
        NormalizedScanResult(
            target_url="https://example.com",
            source=DetectionSource.TECHSPECTER,
            technologies=[
                NormalizedTechnology(
                    id="react",
                    name="React",
                    category="frameworks",
                    version="Unknown",
                    confidence=90.0,
                    source=DetectionSource.TECHSPECTER,
                ),
            ],
        ),
        NormalizedScanResult(
            target_url="https://example.com",
            source=DetectionSource.WAPPALYZER,
            technologies=[
                NormalizedTechnology(
                    id="react",
                    name="React",
                    category="frameworks",
                    version="19.1.0",
                    confidence=100.0,
                    source=DetectionSource.WAPPALYZER,
                ),
            ],
        ),
    )
    versions = engine.compare_versions(matched)
    assert len(versions) == 1
    assert versions[0].status == "unknown_techspecter"
    assert "version extractor" in (versions[0].suggested_improvement or "").lower()


def test_statistics_calculation() -> None:
    """Statistics should compute precision, recall, and version metrics."""
    engine = ComparisonEngine()
    ts = ResultNormalizer().normalize_techspecter(_ts_detection("react", "webpack"))
    wap = ResultNormalizer().normalize_wappalyzer(
        _wap_payload("react", "nginx"),
        target_url="https://example.com",
    )
    matched, ts_only, wap_only = engine.compare(ts, wap)
    versions = engine.compare_versions(matched)
    stats = StatisticsCalculator().calculate(
        matched=matched,
        techspecter_only=ts_only,
        wappalyzer_only=wap_only,
        version_comparisons=versions,
    )
    assert stats.matched_technologies == 1
    assert stats.extra_detections == 1
    assert stats.missing_detections == 1
    assert stats.technology_precision == 0.5
    assert stats.technology_recall == 0.5


def test_gap_analysis_recommendations() -> None:
    """Gap analyzer should produce actionable recommendations."""
    engine = ComparisonEngine()
    ts = ResultNormalizer().normalize_techspecter(_ts_detection("react"))
    wap = ResultNormalizer().normalize_wappalyzer(
        _wap_payload("react", "nginx"),
        target_url="https://example.com",
    )
    matched, ts_only, wap_only = engine.compare(ts, wap)
    versions = engine.compare_versions(matched)
    gaps = GapAnalyzer().analyze(
        wappalyzer_only=wap_only,
        techspecter_only=ts_only,
        version_comparisons=versions,
    )
    assert any(gap.gap_type == "missing_detection" for gap in gaps)
    assert any("nginx" in gap.technology_name.lower() for gap in gaps)


def test_runner_from_results() -> None:
    """Benchmark runner should compare precomputed results."""
    report = BenchmarkRunner().run_from_results(
        target_url="https://example.com",
        techspecter=_ts_detection("react", "webpack"),
        wappalyzer_payload=_wap_payload("react", "nginx"),
    )
    assert report.statistics.matched_technologies == 1
    assert len(report.gap_analysis) >= 1


def test_wappalyzer_json_import(tmp_path: Path) -> None:
    """Wappalyzer JSON import should load and parse reports."""
    payload = _wap_payload("react")
    path = tmp_path / "wappalyzer.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    loaded = WappalyzerExecutor().load_json(path)
    assert isinstance(loaded, list)


def test_render_markdown_and_json() -> None:
    """Reporter should render markdown and JSON output."""
    report = BenchmarkRunner().run_from_results(
        target_url="https://example.com",
        techspecter=_ts_detection("react"),
        wappalyzer_payload=_wap_payload("react"),
    )
    markdown = render_markdown(report)
    assert "# Benchmark Report" in markdown
    assert "React" in markdown

    payload = json.loads(render_json(report))
    assert payload["target_url"] == "https://example.com"
    assert "statistics" in payload


def test_render_console_output() -> None:
    """Console renderer should produce readable output."""
    from io import StringIO

    from rich.console import Console

    report = BenchmarkRunner().run_from_results(
        target_url="https://example.com",
        techspecter=_ts_detection("react"),
        wappalyzer_payload=_wap_payload("react"),
    )
    buffer = StringIO()
    render_console(report, console=Console(file=buffer))
    output = buffer.getvalue()
    assert "Benchmark Report" in output
    assert "React" in output


def test_cli_benchmark_help() -> None:
    """Benchmark command should appear in CLI help."""
    result = runner.invoke(app, ["benchmark", "--help"])
    assert result.exit_code == 0
    assert "Wappalyzer" in result.stdout
    assert "--wappalyzer-result" in result.stdout


def test_cli_benchmark_with_import(tmp_path: Path) -> None:
    """Benchmark CLI should accept imported Wappalyzer JSON."""
    payload = _wap_payload("react")
    path = tmp_path / "report.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    class _StubService:
        async def analyze_url(self, target_url: str) -> object:
            from techspecter.fingerprinting.models import FingerprintAnalysisResult

            return FingerprintAnalysisResult(
                target_url=target_url,
                detection=_ts_detection("react", target_url=target_url),
            )

    from techspecter.benchmark.runner import BenchmarkRunner

    original_run = BenchmarkRunner.run

    def _stub_run(
        self: BenchmarkRunner,
        target_url: str,
        *,
        wappalyzer_result: Path | str | None = None,
        wappalyzer_timeout_seconds: int = 120,
    ) -> object:
        self.fingerprint_service = _StubService()
        return original_run(
            self,
            target_url,
            wappalyzer_result=wappalyzer_result,
            wappalyzer_timeout_seconds=wappalyzer_timeout_seconds,
        )

    BenchmarkRunner.run = _stub_run  # type: ignore[method-assign]
    try:
        result = runner.invoke(
            app,
            ["benchmark", "https://example.com", "--wappalyzer-result", str(path), "--json"],
        )
    finally:
        BenchmarkRunner.run = original_run  # type: ignore[method-assign]

    assert result.exit_code == 0
    assert "matched_technologies" in result.stdout or "statistics" in result.stdout


def test_fingerprint_compare_flag_in_help() -> None:
    """Fingerprint command should expose --compare-wappalyzer flag."""
    result = runner.invoke(app, ["fingerprint", "--help"])
    assert result.exit_code == 0
    assert "--compare-wappalyzer" in result.stdout
