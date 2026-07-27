"""Command-line interface for TechSpecter."""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated, Any

import orjson
import typer
from rich.console import Console
from rich.table import Table

from techspecter import __version__
from techspecter.config import get_settings
from techspecter.crawler.discovery import DiscoveryPipeline
from techspecter.exceptions import TechSpecterError, ValidationError
from techspecter.models.discovery import DiscoveryResult
from techspecter.utils.logging import configure_logging

console = Console()
logger = logging.getLogger(__name__)

app = typer.Typer(
    name="techspecter",
    help="Web Technology Fingerprinting and JavaScript Intelligence framework.",
    no_args_is_help=True,
    add_completion=False,
)


def version_callback(value: bool) -> None:
    """Print the application version and exit.

    Args:
        value: When ``True``, print version information and raise ``typer.Exit``.
    """
    if value:
        console.print(f"TechSpecter {__version__}")
        raise typer.Exit()


@app.callback()
def cli_callback(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-V",
            help="Show the application version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
    debug: Annotated[
        bool,
        typer.Option("--debug", help="Enable debug logging."),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", help="Enable verbose (DEBUG) logging."),
    ] = False,
) -> None:
    """TechSpecter — professional web technology fingerprinting framework."""
    settings = get_settings()
    log_level = "DEBUG" if debug or verbose or settings.debug else settings.log_level
    configure_logging(level=log_level)
    logger.debug("TechSpecter CLI initialized (v%s)", __version__)


def _serialize_discovery_result(result: DiscoveryResult) -> dict[str, Any]:
    """Convert a discovery result to a JSON-serializable dictionary.

    Args:
        result: Discovery pipeline result.

    Returns:
        JSON-compatible dictionary representation.
    """
    return result.model_dump(mode="json")


def _render_discovery_result(result: DiscoveryResult) -> None:
    """Render a human-readable discovery summary.

    Args:
        result: Discovery pipeline result.
    """
    console.print(f"\n[bold]Target:[/bold] {result.target.url}")
    console.print(f"[bold]Elapsed:[/bold] {result.elapsed_ms:.0f} ms\n")

    console.print(
        f"[bold]Discovered:[/bold] {len(result.external_scripts)} external, "
        f"{len(result.inline_scripts)} inline"
    )
    console.print(
        f"[bold]Downloads:[/bold] {result.downloaded_count} succeeded, "
        f"{result.failed_count} failed\n"
    )

    if result.external_scripts:
        external_table = Table(title="External Scripts")
        external_table.add_column("URL", overflow="fold")
        external_table.add_column("Original", overflow="fold")
        for script in result.external_scripts:
            external_table.add_row(str(script.url), script.original_url)
        console.print(external_table)

    if result.downloads:
        download_table = Table(title="Download Results")
        download_table.add_column("Filename")
        download_table.add_column("Status")
        download_table.add_column("Size")
        download_table.add_column("Duration")
        download_table.add_column("Source Map")
        for item in result.downloads:
            status = str(item.status_code) if item.status_code is not None else "N/A"
            if not item.download_success:
                status = f"[red]{status}[/red]"
            size = str(item.content_length) if item.content_length is not None else "N/A"
            duration = (
                f"{item.download_duration_ms:.0f} ms"
                if item.download_duration_ms is not None
                else "N/A"
            )
            source_map = item.source_map_url or "-"
            download_table.add_row(item.filename, status, size, duration, source_map)
        console.print(download_table)

    if result.inline_scripts:
        console.print(f"\n[bold]Inline Scripts:[/bold] {len(result.inline_scripts)} found")


@app.command("discover")
def discover_command(
    url: Annotated[str, typer.Argument(help="Target website URL to scan.")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON."),
    ] = False,
) -> None:
    """Discover and download JavaScript resources from a target website."""
    try:
        pipeline = DiscoveryPipeline()
        result = asyncio.run(pipeline.run(url))
    except ValidationError as exc:
        console.print(f"[red]Validation error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except TechSpecterError as exc:
        console.print(f"[red]Discovery failed:[/red] {exc}")
        logger.exception("Discovery failed for %s", url)
        raise typer.Exit(code=1) from exc

    if json_output:
        payload = _serialize_discovery_result(result)
        console.print(orjson.dumps(payload, option=orjson.OPT_INDENT_2).decode("utf-8"))
        return

    _render_discovery_result(result)


def main() -> None:
    """Console script entry point for the ``techspecter`` command."""
    app()


if __name__ == "__main__":
    main()
