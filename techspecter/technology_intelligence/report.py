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

_SECTION_WIDTH = 50


def render_fingerprint_technology_intelligence(
    report: TechnologyIntelligenceReport,
    *,
    console: Console,
) -> None:
    """Render a concise technology intelligence summary for fingerprint CLI."""
    render_technology_intelligence(report, console=console, cli_mode=True)


def render_fingerprint_technology_evidence(
    report: TechnologyIntelligenceReport,
    *,
    console: Console,
) -> None:
    """Render concise technology evidence blocks for fingerprint CLI."""
    render_technology_evidence(report, console=console, cli_mode=True)


def render_technology_intelligence(
    report: TechnologyIntelligenceReport,
    *,
    console: Console,
    cli_mode: bool = False,
) -> None:
    """Render technology intelligence summary table."""
    if not report.technologies:
        return

    console.print("\n" + "=" * _SECTION_WIDTH)
    console.print("[bold]Technology Intelligence[/bold]")
    console.print("=" * _SECTION_WIDTH + "\n")

    table = _build_summary_table(report, cli_mode=cli_mode)
    console.print(table)
    console.print()


def render_technology_evidence(
    report: TechnologyIntelligenceReport,
    *,
    console: Console,
    cli_mode: bool = False,
) -> None:
    """Render detailed technology evidence blocks."""
    if not report.technologies:
        return

    console.print("=" * _SECTION_WIDTH)
    console.print("[bold]Technology Evidence[/bold]")
    console.print("=" * _SECTION_WIDTH + "\n")

    for entry in report.technologies:
        _render_evidence_block(entry, console=console, cli_mode=cli_mode)


def _build_summary_table(
    report: TechnologyIntelligenceReport,
    *,
    cli_mode: bool = False,
) -> Table:
    width = shutil.get_terminal_size(fallback=(120, 24)).columns
    table = Table(show_header=True, header_style="bold", expand=False, width=min(width, 120))
    table.add_column("Technology", overflow="fold")
    table.add_column("Version", overflow="fold")
    table.add_column("Category", overflow="fold")
    table.add_column("Confidence", justify="right")
    if not cli_mode:
        table.add_column("Files", justify="right")
        table.add_column("Evidence", justify="right")
        table.add_column("Relationship", justify="right")
        table.add_column("Detector", overflow="fold")

    for entry in report.technologies:
        if cli_mode:
            table.add_row(
                entry.technology.name,
                entry.version,
                entry.technology.category,
                f"{entry.confidence:.0f}%",
            )
            continue
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


def _render_evidence_block(
    entry: TechnologyIntelligenceEntry,
    *,
    console: Console,
    cli_mode: bool = False,
) -> None:
    console.print("-" * _SECTION_WIDTH)
    console.print(f"[bold]Technology:[/bold] {entry.technology.name}")
    _render_found_in(entry, console=console, cli_mode=cli_mode)

    primary = _primary_evidence(entry.evidence)
    if primary is not None:
        console.print("\n[bold]Evidence:[/bold]")
        matched_text = _display_matched_text(primary)
        if matched_text:
            console.print(f"  {matched_text}")

    if not cli_mode and entry.metadata.detection_methods:
        console.print("\n[bold]Discovery Methods:[/bold]")
        console.print(f"  {', '.join(entry.metadata.detection_methods)}")

    if not cli_mode and entry.relationships:
        console.print("\n[bold]Relationships:[/bold]")
        for rel in entry.relationships:
            console.print(
                f"  {rel.source_technology_name} -> {rel.target_technology_name} "
                f"({rel.relationship.value})",
            )

    if entry.version_attribution is not None:
        _render_version_attribution(entry, console=console, cli_mode=cli_mode)

    console.print(f"\n[bold]Confidence:[/bold] {entry.confidence:.0f}%\n")


def _render_found_in(
    entry: TechnologyIntelligenceEntry,
    *,
    console: Console,
    cli_mode: bool = False,
) -> None:
    console.print("[bold]Found In:[/bold]")
    locations = _collect_locations(entry)
    if cli_mode:
        locations = locations[:1]
    if not locations:
        console.print("  [dim](unknown)[/dim]")
        return
    for location in locations:
        console.print(f"  [bold]Source File:[/bold] {location['source_file']}")
        if location.get("relative_path"):
            console.print(f"  [bold]Relative Path:[/bold] {location['relative_path']}")
        if location.get("asset_id"):
            console.print(f"  [bold]Asset ID:[/bold] {location['asset_id']}")
        if not cli_mode and location.get("source_url"):
            console.print(f"  [bold]Source URL:[/bold] {location['source_url']}")
        if not cli_mode and location.get("discovery_method"):
            console.print(f"  [bold]Discovery:[/bold] {location['discovery_method']}")
        console.print()


def _render_version_attribution(
    entry: TechnologyIntelligenceEntry,
    *,
    console: Console,
    cli_mode: bool = False,
) -> None:
    attr = entry.version_attribution
    if attr is None:
        return
    console.print("\n[bold]Version Attribution:[/bold]")
    console.print(f"  [bold]Version:[/bold] {attr.detected_version}")
    if attr.source_file:
        console.print(f"  [bold]Source File:[/bold] {attr.source_file}")
    if not cli_mode and attr.source_url:
        console.print(f"  [bold]Source URL:[/bold] {attr.source_url}")
    if attr.source_asset_id:
        console.print(f"  [bold]Asset ID:[/bold] {attr.source_asset_id}")
    if attr.matched_pattern:
        console.print(f"  [bold]Matched Pattern:[/bold] {attr.matched_pattern}")
    if attr.matched_text:
        console.print(f"  [bold]Matched Value:[/bold] {attr.matched_text}")
    console.print(f"  [bold]Confidence:[/bold] {attr.confidence:.0f}%")


def _collect_locations(entry: TechnologyIntelligenceEntry) -> list[dict[str, str]]:
    """Build unique attribution locations from evidence and found-in metadata."""
    seen: set[tuple[str, str, str]] = set()
    locations: list[dict[str, str]] = []

    def add(
        *,
        source_file: str | None,
        relative_path: str | None = None,
        asset_id: str | None = None,
        source_url: str | None = None,
        discovery_method: str | None = None,
    ) -> None:
        file_label = source_file or source_url or asset_id
        if not file_label:
            return
        key = (file_label, asset_id or "", source_url or "")
        if key in seen:
            return
        seen.add(key)
        location: dict[str, str] = {"source_file": file_label}
        if relative_path:
            location["relative_path"] = relative_path
        if asset_id:
            location["asset_id"] = asset_id
        if source_url:
            location["source_url"] = source_url
        if discovery_method:
            location["discovery_method"] = discovery_method
        locations.append(location)

    for item in entry.evidence:
        add(
            source_file=item.source_file,
            asset_id=item.source_asset_id,
            source_url=item.source_url,
            discovery_method=item.discovery_method.value,
        )

    if not locations:
        for filename in entry.found_in_files:
            add(source_file=filename)
        for index, asset_id in enumerate(entry.found_in_asset_ids):
            linked_file = entry.found_in_files[index] if index < len(entry.found_in_files) else None
            add(source_file=linked_file, asset_id=asset_id)

    return locations


def _display_matched_text(item: TechnologyEvidenceRecord) -> str | None:
    """Prefer matched text over internal labels for display."""
    for candidate in (item.matched_text, item.matched_pattern):
        if candidate and not candidate.startswith("techspecter:"):
            return candidate
    return item.matched_text or item.matched_pattern


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
