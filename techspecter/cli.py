"""Command-line interface for TechSpecter."""

from __future__ import annotations

import logging
from typing import Annotated

import typer
from rich.console import Console

from techspecter import __version__
from techspecter.config import get_settings
from techspecter.utils.logging import configure_logging

console = Console()
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
) -> None:
    """TechSpecter — professional web technology fingerprinting framework."""
    settings = get_settings()
    log_level = "DEBUG" if debug or settings.debug else settings.log_level
    configure_logging(level=log_level)
    logging.getLogger(__name__).debug("TechSpecter CLI initialized (v%s)", __version__)


def main() -> None:
    """Console script entry point for the ``techspecter`` command."""
    app()


if __name__ == "__main__":
    main()
