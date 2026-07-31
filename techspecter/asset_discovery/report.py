"""Asset inventory console reporting."""

from __future__ import annotations

import logging
import shutil

from rich.console import Console
from rich.table import Table

from techspecter.asset_discovery.download_status import build_failure_breakdown
from techspecter.asset_discovery.models import AssetCategory, AssetInventory, AssetRecord
from techspecter.reporting.cli_format import format_metric_line
from techspecter.reporting.models import ReportAssetEntry, ReportAssetInventory, ReportSection

logger = logging.getLogger(__name__)

_SECTION_WIDTH = 50

_CATEGORY_LABELS: dict[AssetCategory, str] = {
    AssetCategory.JAVASCRIPT: "JavaScript",
    AssetCategory.CSS: "CSS",
    AssetCategory.JSON: "JSON",
    AssetCategory.MAP: "Source Maps",
    AssetCategory.MANIFEST: "Manifest",
    AssetCategory.WORKER: "Workers",
    AssetCategory.SERVICE_WORKER: "Service Workers",
    AssetCategory.WASM: "WASM",
    AssetCategory.FONT: "Fonts",
    AssetCategory.XML: "XML",
    AssetCategory.TEXT: "Text",
    AssetCategory.IMAGE: "Images",
    AssetCategory.UNKNOWN: "Other",
}

_SUMMARY_ROWS: tuple[tuple[str, str], ...] = (
    ("javascript", "JavaScript"),
    ("css", "CSS"),
    ("json_count", "JSON"),
    ("map_count", "Source Maps"),
    ("manifest", "Manifest"),
    ("worker", "Workers"),
    ("service_worker", "Service Workers"),
    ("font", "Fonts"),
    ("wasm", "WASM"),
    ("xml", "XML"),
    ("text", "Text"),
    ("image", "Images"),
)


def render_asset_inventory(
    inventory: AssetInventory,
    *,
    console: Console | None = None,
    show_assets: bool = False,
) -> None:
    """Render the asset inventory summary and optional table."""
    output = console or Console()
    _render_inventory_header(output)
    _render_category_summary(inventory, output=output)
    _render_download_summary(inventory, output=output)
    if show_assets:
        _render_asset_table(inventory, output=output, detailed=True)
    logger.info("Rendered asset inventory with %d assets", len(inventory.assets))


def render_fingerprint_asset_inventory(
    inventory: AssetInventory,
    *,
    console: Console | None = None,
    show_assets: bool = False,
) -> None:
    """Render a concise asset inventory for the fingerprint CLI."""
    output = console or Console()
    _render_inventory_header(output)
    _render_category_summary(inventory, output=output)
    _render_download_summary(inventory, output=output)
    if show_assets:
        _render_asset_table(inventory, output=output, detailed=False)
    logger.info("Rendered fingerprint asset inventory summary for %d assets", len(inventory.assets))


def _render_inventory_header(output: Console) -> None:
    output.print("\n" + "=" * _SECTION_WIDTH)
    output.print("[bold]Asset Inventory[/bold]")
    output.print("=" * _SECTION_WIDTH)


def _render_category_summary(inventory: AssetInventory, *, output: Console) -> None:
    summary = inventory.summary
    output.print("\n[bold]Summary[/bold]\n")
    for field_name, label in _SUMMARY_ROWS:
        count = getattr(summary, field_name)
        if count:
            output.print(format_metric_line(label, count, width=24))
    other = summary.unknown + summary.other
    if other:
        output.print(format_metric_line("Other", other, width=24))
    output.print("")
    output.print(format_metric_line("Total Assets", summary.total_assets, width=24))
    output.print("")


def _render_download_summary(inventory: AssetInventory, *, output: Console) -> None:
    download_summary = inventory.download_summary
    if download_summary.total_attempted == 0:
        return
    output.print("[bold]Download Summary[/bold]\n")
    output.print(format_metric_line("Downloaded", download_summary.downloaded, width=24))
    failed_total = (
        download_summary.failed
        + download_summary.timeout
        + download_summary.forbidden
        + download_summary.rate_limited
    )
    if failed_total:
        output.print(format_metric_line("Failed", failed_total, width=24))
    output.print(format_metric_line("Skipped", download_summary.skipped, width=24))
    output.print(format_metric_line("Rate Limited", download_summary.rate_limited, width=24))
    output.print("")

    breakdown = build_failure_breakdown(inventory.assets)
    if breakdown:
        output.print("[bold]Failed Downloads[/bold]\n")
        for reason, count in breakdown.items():
            output.print(format_metric_line(reason, count, width=24))
        output.print("")


def _render_asset_table(inventory: AssetInventory, *, output: Console, detailed: bool) -> None:
    if not inventory.assets:
        output.print("[dim]No assets discovered.[/dim]")
        return

    terminal_width = shutil.get_terminal_size(fallback=(120, 24)).columns
    table = Table(title="Asset Inventory", expand=True, min_width=min(terminal_width, 120))
    table.add_column("Category", no_wrap=True)
    table.add_column("File Name", overflow="fold", max_width=max(20, terminal_width // 5))
    table.add_column("Relative Path", overflow="fold", max_width=max(20, terminal_width // 4))
    table.add_column("Extension", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Size", no_wrap=True)
    if detailed:
        table.add_column("Content-Type", overflow="fold")
        table.add_column("Referenced By", overflow="fold")
        table.add_column("URL", overflow="fold")
    table.add_column("Asset ID", overflow="fold", max_width=max(12, terminal_width // 8))

    for asset in inventory.assets:
        row = [
            _category_label(asset.category),
            asset.filename,
            asset.relative_path or "-",
            asset.extension or "-",
            _format_status(asset),
            _format_size(asset.file_size),
        ]
        if detailed:
            row.extend(
                [
                    asset.content_type or "-",
                    _format_referenced_by(asset),
                    asset.url,
                ],
            )
        row.append(asset.asset_id)
        table.add_row(*row)

    output.print(table)
    output.print("")


def build_report_asset_inventory(inventory: AssetInventory) -> ReportAssetInventory:
    """Convert an asset inventory into report export models."""
    entries = [
        ReportAssetEntry(
            asset_id=asset.asset_id,
            url=asset.url,
            filename=asset.filename,
            extension=asset.extension,
            category=asset.category.value,
            content_type=asset.content_type,
            mime_type=asset.mime_type,
            http_status=asset.http_status,
            file_size=asset.file_size,
            sha256=asset.sha256,
            download_success=asset.download_success,
            referenced_by=_format_referenced_by(asset),
            discovery_sources=[source.value for source in asset.discovery_sources],
        )
        for asset in inventory.assets
    ]
    summary = inventory.summary
    return ReportAssetInventory(
        target_url=inventory.target_url,
        summary=summary.model_dump(),
        total_assets=summary.total_assets,
        assets=entries,
        elapsed_ms=inventory.elapsed_ms,
    )


def build_report_section(inventory: AssetInventory) -> ReportSection:
    """Build a report section for asset inventory export."""
    report_inventory = build_report_asset_inventory(inventory)
    return ReportSection(
        id="asset-inventory",
        title="Asset Inventory",
        summary=f"{report_inventory.total_assets} assets discovered",
        metadata={
            "asset_inventory": report_inventory.model_dump(mode="json"),
            "summary": report_inventory.summary,
        },
    )


def _category_label(category: AssetCategory) -> str:
    """Return display label for a category."""
    return _CATEGORY_LABELS.get(category, category.value.title())


def _format_size(size: int | None) -> str:
    """Format file size for display."""
    if size is None:
        return "-"
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def _format_status(asset: AssetRecord) -> str:
    """Format HTTP/download status."""
    if asset.download_status is not None:
        return asset.download_status.value.replace("_", " ").title()
    if asset.http_status is not None:
        return str(asset.http_status)
    if asset.download_success:
        return "OK"
    return asset.error_message or "Pending"


def _format_referenced_by(asset: AssetRecord) -> str:
    """Summarize relationship evidence."""
    if not asset.relationships:
        return "-"
    first = asset.relationships[0]
    detail = f" ({first.detail})" if first.detail else ""
    if len(asset.relationships) == 1:
        return f"{first.source.value}: {first.referenced_by}{detail}"
    return f"{first.source.value}: {first.referenced_by}{detail} +{len(asset.relationships) - 1}"
