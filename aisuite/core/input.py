"""Interactive input helpers. Lifted from ai_sploit.py.

preview_and_confirm return type fixed to str (the existing implementation
already returned 'y'/'e'/'n' strings but the annotation said bool).
"""
from __future__ import annotations

from aisuite.core.logger import BOLD, CYAN, DIM, RESET, error


def ask(prompt: str, default: str | None = None) -> str | None:
    """Simple input with optional default."""
    suffix = f" [{default}]" if default else ""
    val = input(f"  {BOLD}{prompt}{suffix}:{RESET} ").strip()
    return val if val else default


def choose(prompt: str, options: list[str]) -> int:
    """Show numbered menu and return chosen index (0-based)."""
    print(f"\n  {BOLD}{prompt}{RESET}")
    for i, opt in enumerate(options, 1):
        print(f"  {CYAN}[{i}]{RESET} {opt}")
    while True:
        val = input(f"\n  {BOLD}Choice:{RESET} ").strip()
        try:
            idx = int(val) - 1
            if 0 <= idx < len(options):
                return idx
        except ValueError:
            pass
        error("Invalid choice")


def preview_and_confirm(curl_cmd: str, payload_preview: str | None = None) -> str:
    """Show full curl + optional payload, return one of 'y', 'e', 'n'."""
    from aisuite.core.logger import divider
    divider("PREVIEW")
    print(f"\n  {DIM}# Full curl command that will be sent:{RESET}")
    print(f"\n  {CYAN}{curl_cmd}{RESET}\n")
    if payload_preview:
        print(f"  {DIM}# Payload content:{RESET}")
        for line in payload_preview.split("\n"):
            print(f"  {DIM}│{RESET} {line}")
        print()

    while True:
        choice = input(
            f"  {BOLD}[y]{RESET} Send  {BOLD}[e]{RESET} Edit  {BOLD}[n]{RESET} Cancel  > "
        ).strip().lower()
        if choice in ("y", "e", "n"):
            return choice
        error("Enter y / e / n")
