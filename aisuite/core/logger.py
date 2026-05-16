"""Terminal output helpers.

ANSI styling and prefix conventions lifted verbatim from ai_sploit.py so
the migrated shim produces byte-identical output. Banner frame is RED
(ai_sploit convention — the primary attack interface); the recon-vs-attack
distinction now lives in the `phase` parameter instead of frame color.
"""
import sys

# Box-drawing glyphs (─, ═, ✗, ►) are not encodable under cp1252, which is
# the default stdout codec on Windows Python until PYTHONUTF8=1. Reconfigure
# once at import so callers don't need to know.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure") and getattr(_stream, "encoding", "").lower() != "utf-8":
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"


def info(msg: str) -> None:
    print(f"  {CYAN}[*]{RESET} {msg}")


def success(msg: str) -> None:
    print(f"  {GREEN}[+]{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}[!]{RESET} {msg}")


def error(msg: str) -> None:
    print(f"  {RED}[✗]{RESET} {msg}")


def found(msg: str) -> None:
    print(f"  {GREEN}[►]{RESET} {BOLD}{msg}{RESET}")


def divider(title: str = "") -> None:
    if title:
        pad = (54 - len(title) - 4) // 2
        print(f"\n  {DIM}{'─' * pad}[ {RESET}{BOLD}{title}{RESET}{DIM} ]{'─' * pad}{RESET}")
    else:
        print(f"\n  {DIM}{'─' * 54}{RESET}")


def banner(title: str, phase: str = "") -> None:
    phase_str = f" {MAGENTA}[{phase}]{RESET}" if phase else ""
    print(f"\n{BOLD}{RED}{'═' * 54}{RESET}")
    print(f"{BOLD}{RED}  {title}{phase_str}{RESET}")
    print(f"{BOLD}{RED}{'═' * 54}{RESET}\n")
