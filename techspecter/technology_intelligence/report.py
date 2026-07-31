"""Technology intelligence console reporting."""

from __future__ import annotations

import logging
import shutil

from rich.console import Console
from rich.table import Table

from techspecter.reporting.models import (
    ReportSection,
    ReportTechnologyEvidence,
    ReportTechnologyIntelligence,
    ReportTechnologyIntelligenceEntry,
)
from techspecter.technology_intelligence.models import (
    TechnologyEvidenceRecord,
    TechnologyIntelligenceEntry,
    TechnologyIntelligenceReport,
)

logger = logging.getLogger(__name__)


def render_technology_intelligence(
    report: TechnologyIntelligenceReport,
    *,
    console: Console,
) -> None:
    """Render technology intelligence summary and evidence to the terminal."""
    if not report.technologies:
        return

    console.print("\n" + "=" * 50)
    console.print("[bold]Technology Intelligence[/bold]")
    console.print("=" * 50 + "\n")

    table = _build_summary_table(report)
    console.print(table)
    console.print()

    for entry in report.technologies:
        _render_evidence_block(entry, console=console)


def _build_summary_table(report: TechnologyIntelligenceReport) -> Table:
    width = shutil.get_terminal_size(fallback=(120, 24)).columns
    table = Table(show_header=True, header_style="bold", expand=False, width=min(width, 120))
    table.add_column("Technology", overflow="fold")
    table.add_column("Version", overflow="fold")
    table.add_column("Category", overflow="fold")
    table.add_column("Confidence", justify="right")
    table.add_column("Files", justify="right")
    table.add_column("Evidence", justify="right")
    table.add_column("Relationship", justify="right")
    table.add_column("Detector", overflow="fold")

    for entry in report.technologies:
        rel_count = len(entry.relationships)
        table.add_row(
            entry.technology.name,
            entry.version,
            entry.technology.category,
            f"{entry.confidence:.0f}%",
            str(len(entry.found_in_files)),
            str(len(entry.evidence)),
            str(rel_count),
            ", ".join(entry.detectors) or "techspecter",
        )
    return table


def _render_evidence_block(entry: TechnologyIntelligenceEntry, *, console: Console) -> None:
    console.print("-" * 50)
    console.print(f"[bold]Technology:[/bold] {entry.technology.name}")
    console.print("[bold]Found In:[/bold]")
    if entry.found_in_files:
        for filename in entry.found_in_files:
            console.print(f"  {filename}")
    else:
        console.print("  [dim](unknown)[/dim]")

    primary = _primary_evidence(entry.evidence)
    if primary is not None:
        console.print("\n[bold]Evidence:[/bold]")
        console.print(
            f"  {primary.matched_pattern or primary.matched_text or primary.evidence_type.value}"
        )
        if primary.matched_pattern:
            console.print("\n[bold]Matched Pattern:[/bold]")
            console.print(f"  {primary.matched_pattern}")
        if primary.matched_text:
            console.print("\n[bold]Matched Text:[/bold]")
            console.print(f"  {primary.matched_text}")

    if entry.version_attribution is not None:
        attr = entry.version_attribution
        console.print("\n[bold]Version Source:[/bold]")
        console.print(f"  {attr.source_file or attr.source_url or 'unknown'}")
        if attr.matched_text:
            console.print(f"  {attr.matched_text}")

    console.print(f"\n[bold]Confidence:[/bold] {entry.confidence:.0f}%\n")


def _primary_evidence(
    evidence: list[TechnologyEvidenceRecord],
) -> TechnologyEvidenceRecord | None:
    if not evidence:
        return None
    return max(evidence, key=lambda item: item.confidence)


def build_report_technology_intelligence(
    report: TechnologyIntelligenceReport,
) -> ReportTechnologyIntelligence:
    """Convert technology intelligence to export-ready report model."""
    entries = [
        ReportTechnologyIntelligenceEntry(
            technology_id=entry.technology.id,
            name=entry.technology.name,
            category=entry.technology.category,
            version=entry.version,
            confidence=entry.confidence,
            files_found=len(entry.found_in_files),
            evidence_count=len(entry.evidence),
            relationship_count=len(entry.relationships),
            detectors=entry.detectors,
            found_in_files=entry.found_in_files,
            found_in_asset_ids=entry.found_in_asset_ids,
            version_source=entry.metadata.version_source,
            version_attribution=(
                entry.version_attribution.model_dump(mode="json")
                if entry.version_attribution
                else None
            ),
            evidence=[_map_evidence(item) for item in entry.evidence],
            relationships=[item.model_dump(mode="json") for item in entry.relationships],
        )
        for entry in report.technologies
    ]
    return ReportTechnologyIntelligence(
        target_url=report.target_url,
        total_technologies=len(entries),
        total_evidence=report.total_evidence,
        total_assets_referenced=report.total_assets_referenced,
        technologies=entries,
        relationships=[item.model_dump(mode="json") for item in report.relationships],
        elapsed_ms=report.elapsed_ms,
    )


def build_report_section(
    report: TechnologyIntelligenceReport,
) -> ReportSection:
    """Build a report section for technology intelligence."""
    export_model = build_report_technology_intelligence(report)
    return ReportSection(
        id="technology-intelligence",
        title="Technology Intelligence",
        summary=(
            f"{export_model.total_technologies} technologies, "
            f"{export_model.total_evidence} evidence items"
        ),
        metadata=export_model.model_dump(mode="json"),
    )


def _map_evidence(item: TechnologyEvidenceRecord) -> ReportTechnologyEvidence:
    return ReportTechnologyEvidence(
        evidence_id=item.evidence_id,
        evidence_type=item.evidence_type.value,
        matched_pattern=item.matched_pattern,
        matched_text=item.matched_text,
        source_file=item.source_file,
        source_url=item.source_url,
        source_asset_id=item.source_asset_id,
        line_number=item.line_number,
        byte_offset=item.byte_offset,
        confidence=item.confidence,
        detector_name=item.detector_name,
        discovery_method=item.discovery_method.value,
    )
