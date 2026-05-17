"""CLI entry point.

Currently exposes:
    aisuite version              — print version
    aisuite gui [--host …] [--port …]   — start the Guided Engagement web UI

Subcommands for `suite`/`sploit`/`enum`/`session-enum` (3-line shims to v1
scripts) will be wired up in a later Phase 1 task.
"""
import click


@click.group()
def main() -> None:
    """AISuite v2.0 — AI Red Team Engagement Toolkit."""


@main.command()
def version() -> None:
    """Show version."""
    from aisuite import __version__
    click.echo(f"aisuite {__version__}")


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Bind address. Use 0.0.0.0 to expose on the LAN.")
@click.option("--port", default=8000, show_default=True, type=int)
def gui(host: str, port: int) -> None:
    """Start the Guided Engagement web UI."""
    from aisuite.ui.app import serve
    click.echo(f"AISuite GUI → http://{host}:{port}")
    serve(host=host, port=port)


if __name__ == "__main__":
    main()
