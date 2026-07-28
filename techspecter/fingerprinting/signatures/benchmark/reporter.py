"""Benchmark report generation."""

from __future__ import annotations

from techspecter.fingerprinting.signatures.benchmark.models import BenchmarkReport


def render_benchmark_report(report: BenchmarkReport) -> str:
    """Render human-readable benchmark report."""
    lines = [
        "# TechSpecter Signature Intelligence Benchmark",
        "",
        "## Metrics",
        f"- Precision: {report.metrics.precision:.2%}",
        f"- Recall: {report.metrics.recall:.2%}",
        f"- F1 Score: {report.metrics.f1_score:.2%}",
        f"- Version Accuracy: {report.metrics.version_accuracy:.2%}",
        f"- False Positives: {report.metrics.false_positives}",
        f"- False Negatives: {report.metrics.false_negatives}",
        f"- Signature Coverage: {report.signature_count}",
        f"- Explainability Score: {report.metrics.explainability_score:.2f}",
        "",
        "## Competitor Comparison (estimated baselines)",
    ]
    for item in report.comparisons:
        lines.append(
            f"- {item.name}: precision={item.precision:.0%}, recall={item.recall:.0%}, "
            f"coverage~{item.coverage} ({item.notes})",
        )
    lines.extend(["", "## Category Coverage"])
    for category, count in sorted(report.category_coverage.items()):
        lines.append(f"- {category}: {count}")
    lines.extend(["", "## Sample Results"])
    for sample in report.samples:
        lines.append(f"### {sample.sample_id}")
        lines.append(f"- Expected: {', '.join(sample.expected) or 'none'}")
        lines.append(f"- Detected: {', '.join(sample.detected) or 'none'}")
        if sample.false_positives:
            lines.append(f"- False Positives: {', '.join(sample.false_positives)}")
        if sample.false_negatives:
            lines.append(f"- False Negatives: {', '.join(sample.false_negatives)}")
    return "\n".join(lines)
