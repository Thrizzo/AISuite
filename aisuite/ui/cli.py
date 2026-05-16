"""CLI entry point. Subcommands wired up in later Phase 1 / 2 tasks."""
import click


@click.group()
def main() -> None:
    """AISuite v2.0 - AI Red Team Engagement Toolkit."""


@main.command()
def version() -> None:
    """Show version."""
    from aisuite import __version__
    click.echo(f"aisuite {__version__}")


if __name__ == "__main__":
    main()
