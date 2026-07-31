"""Asset inventory console reporting."""

from __future__ import annotations

import logging
import shutil

from rich.console import Console
from rich.table import Table

from techspecter.asset_discovery.models import AssetCategory, AssetInventory, AssetRecord
from techspecter.reporting.models import ReportAssetEntry, ReportAssetInventory, ReportSection

logger = logging.getLogger(__name__)

_MAX_FINGERPRINT_ASSETS = 50

_CATEGORY_LABELS: dict[AssetCategory, str] = {
    AssetCategory.JAVASCRIPT: "JavaScript",
    AssetCategory.CSS: "CSS",
    AssetCategory.JSON: "JSON",
    AssetCategory.MAP: "Maps",
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


def render_asset_inventory(inventory: AssetInventory, *, console: Console | None = None) -> None:
    """Render the asset inventory summary and table to the console."""
    output = console or Console()
    summary = inventory.summary

    output.print("\n[bold]" + "=" * 50 + "[/bold]")
    output.print("[bold]Asset Inventory[/bold]")
    output.print("[bold]" + "=" * 50 + "[/bold]\n")
    output.print("[bold]Summary[/bold]\n")
    output.print(f"JavaScript : {summary.javascript}")
    output.print(f"CSS : {summary.css}")
    output.print(f"JSON : {summary.json_count}")
    output.print(f"Source Maps : {summary.map_count}")
    output.print(f"Manifest : {summary.manifest}")
    output.print(f"Workers : {summary.worker}")
    output.print(f"Service Workers : {summary.service_worker}")
    output.print(f"Fonts : {summary.font}")
    output.print(f"WASM : {summary.wasm}")
    output.print(f"XML : {summary.xml}")
    output.print(f"TXT : {summary.text}")
    output.print(f"Images : {summary.image}")
    other = summary.unknown + summary.other
    output.print(f"Other : {other}")
    output.print(f"\n[bold]Total Assets : {summary.total_assets}[/bold]\n")

    if not inventory.assets:
        output.print("[dim]No assets discovered.[/dim]")
        return

    terminal_width = shutil.get_terminal_size(fallback=(120, 24)).columns
    table = Table(title="Asset Inventory", expand=True, min_width=min(terminal_width, 120))
    table.add_column("Category", no_wrap=True)
    table.add_column("File Name", overflow="fold", max_width=max(20, terminal_width // 7))
    table.add_column("Relative Path", overflow="fold", max_width=max(20, terminal_width // 6))
    table.add_column("Extension", no_wrap=True)
    table.add_column("Content-Type", overflow="fold", max_width=max(16, terminal_width // 8))
    table.add_column("HTTP Status", no_wrap=True)
    table.add_column("Size", no_wrap=True)
    table.add_column("Referenced By", overflow="fold", max_width=max(16, terminal_width // 6))
    table.add_column("Asset ID", overflow="fold", max_width=max(12, terminal_width // 10))
    table.add_column("URL", overflow="fold")

    for asset in inventory.assets:
        table.add_row(
            _category_label(asset.category),
            asset.filename,
            asset.relative_path or "-",
            asset.extension or "-",
            asset.content_type or "-",
            _format_status(asset),
            _format_size(asset.file_size),
            _format_referenced_by(asset),
            asset.asset_id,
            asset.url,
        )

    output.print(table)
    logger.info("Rendered asset inventory with %d assets", len(inventory.assets))


def render_fingerprint_asset_inventory(
    inventory: AssetInventory,
    *,
    console: Console | None = None,
) -> None:
    """Render a concise asset inventory for the fingerprint CLI."""
    output = console or Console()
    summary = inventory.summary

    output.print("\n[bold]" + "=" * 50 + "[/bold]")
    output.print("[bold]Asset Inventory[/bold]")
    output.print("[bold]" + "=" * 50 + "[/bold]\n")
    output.print("[bold]Summary[/bold]\n")
    output.print(f"JavaScript : {summary.javascript}")
    output.print(f"CSS : {summary.css}")
    output.print(f"JSON : {summary.json_count}")
    output.print(f"Source Maps : {summary.map_count}")
    output.print(f"Manifest : {summary.manifest}")
    output.print(f"Workers : {summary.worker}")
    output.print(f"Service Workers : {summary.service_worker}")
    output.print(f"Fonts : {summary.font}")
    output.print(f"WASM : {summary.wasm}")
    output.print(f"XML : {summary.xml}")
    output.print(f"TXT : {summary.text}")
    output.print(f"Images : {summary.image}")
    other = summary.unknown + summary.other
    output.print(f"Other : {other}")
    output.print(f"\n[bold]Total Assets : {summary.total_assets}[/bold]\n")

    if not inventory.assets:
        _render_download_summary(inventory, output=output)
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
    table.add_column("Asset ID", overflow="fold", max_width=max(12, terminal_width // 8))

    displayed = inventory.assets[:_MAX_FINGERPRINT_ASSETS]
    for asset in displayed:
        table.add_row(
            _category_label(asset.category),
            asset.filename,
            asset.relative_path or "-",
            asset.extension or "-",
            _format_status(asset),
            _format_size(asset.file_size),
            asset.asset_id,
        )

    output.print(table)
    remaining = len(inventory.assets) - len(displayed)
    if remaining > 0:
        output.print(f"[dim]... and {remaining} more assets[/dim]")
    _render_download_summary(inventory, output=output)
    logger.info("Rendered fingerprint asset inventory with %d assets", len(displayed))


def _render_download_summary(inventory: AssetInventory, *, output: Console) -> None:
    """Render concise asset download outcome counts."""
    download_summary = inventory.download_summary
    if download_summary.total_attempted == 0:
        return
    output.print("[bold]Asset Download Summary[/bold]")
    output.print(f"  Downloaded: {download_summary.downloaded}")
    output.print(f"  Failed: {download_summary.failed}")
    output.print(f"  Skipped: {download_summary.skipped}")
    output.print(f"  Rate Limited: {download_summary.rate_limited}")
    if download_summary.timeout:
        output.print(f"  Timeout: {download_summary.timeout}")
    if download_summary.forbidden:
        output.print(f"  Forbidden: {download_summary.forbidden}")
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
