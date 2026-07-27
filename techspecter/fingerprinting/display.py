"""Fingerprint command rendering helpers (backward compatible)."""

from __future__ import annotations

from rich.console import Console

from techspecter.fingerprinting.models import FingerprintAnalysisResult
from techspecter.reporting.renderer import render_report
from techspecter.reporting.service import ReportService


def render_fingerprint_result(
    result: FingerprintAnalysisResult,
    *,
    console: Console,
    compact: bool = False,
    group_by_category: bool = False,
    verbose: bool = False,
) -> None:
    """Render fingerprint analysis output using the reporting renderer."""
    report = ReportService().generate_report(
        result.detection,
        scan_duration_ms=result.elapsed_ms,
    )
    render_report(
        report,
        console=console,
        compact=compact,
        group_by_category=group_by_category,
        verbose=verbose,
    )
