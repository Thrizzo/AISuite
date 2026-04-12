#!/usr/bin/env python3
"""
ai_enum.py — AI Agent Enumerator
Parses nmap grepable output, hits /health on all Uvicorn services,
prints results to screen and optionally saves to file.

Usage:
    python3 ai_enum.py -f nmap_results.txt
    python3 ai_enum.py -f nmap_results.txt -o agents.json
"""

import argparse
import json
import re
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] requests not installed. Run: pip install requests --break-system-packages")
    sys.exit(1)

# ── ANSI colours ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}╔═══════════════════════════════════════════╗
║         AI Agent Enumerator v1.0          ║
║   OSAI — NVIDIA Kill Chain: RECON Phase   ║
╚═══════════════════════════════════════════╝{RESET}
"""

def parse_nmap_grepable(filepath: str) -> dict[str, list[int]]:
    """Extract host → [uvicorn ports] from nmap grepable output.
    Handles two-line-per-host format: Status line + Ports line."""
    targets: dict[str, list[int]] = {}

    try:
        with open(filepath) as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"{RED}[!] File not found: {filepath}{RESET}")
        sys.exit(1)

    for line in lines:
        # Only process lines that contain Ports data
        if "Ports:" not in line:
            continue

        # Extract host IP
        host_match = re.search(r"Host:\s+([\d.]+)", line)
        if not host_match:
            continue
        host = host_match.group(1)

        # Extract Uvicorn ports from this line
        ports_section = line.split("Ports:")[1] if "Ports:" in line else ""
        uvicorn_ports = [
            int(m.group(1))
            for m in re.finditer(r"(\d+)/open/tcp//http//Uvicorn", ports_section, re.IGNORECASE)
        ]

        if uvicorn_ports:
            targets[host] = uvicorn_ports

    return targets


def probe_agent(host: str, port: int, timeout: int = 5) -> dict:
    """Hit /health on a single host:port and return structured result."""
    url = f"http://{host}:{port}/health"
    result = {
        "host": host,
        "port": port,
        "url": url,
        "status": None,
        "agent": None,
        "healthy": False,
        "raw": None,
        "error": None,
    }

    try:
        resp = requests.get(url, timeout=timeout)
        data = resp.json()
        result.update({
            "status":  data.get("status"),
            "agent":   data.get("agent", "Unknown"),
            "healthy": data.get("status") == "healthy",
            "raw":     data,
        })
    except requests.exceptions.ConnectionError:
        result["error"] = "Connection refused"
    except requests.exceptions.Timeout:
        result["error"] = "Timeout"
    except ValueError:
        result["error"] = "Non-JSON response"
    except Exception as e:
        result["error"] = str(e)

    return result


def print_result(result: dict) -> None:
    """Pretty-print a single probe result."""
    host  = result["host"]
    port  = result["port"]
    agent = result["agent"]

    if result["healthy"]:
        status_str = f"{GREEN}● HEALTHY{RESET}"
        label      = f"{BOLD}{agent}{RESET}"
        print(f"  {status_str}  {CYAN}{host}:{port}{RESET}  →  {label}")
    elif result["error"]:
        print(f"  {RED}✗ ERROR  {RESET}  {host}:{port}  →  {RED}{result['error']}{RESET}")
    else:
        print(f"  {YELLOW}? UNKNOWN{RESET}  {host}:{port}  →  status={result['status']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enumerate AI agents from nmap grepable output"
    )
    parser.add_argument(
        "-f", "--file",
        required=True,
        metavar="NMAP_FILE",
        help="nmap grepable output file (-oG)"
    )
    parser.add_argument(
        "-o", "--output",
        metavar="OUTPUT_FILE",
        help="Save results to JSON file"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        metavar="N",
        help="Concurrent threads (default: 10)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        metavar="SEC",
        help="Request timeout in seconds (default: 5)"
    )
    args = parser.parse_args()

    print(BANNER)

    # ── Parse nmap file ───────────────────────────────────────────────────────
    targets = parse_nmap_grepable(args.file)

    if not targets:
        print(f"{RED}[!] No Uvicorn services found in {args.file}{RESET}")
        sys.exit(1)

    total_ports = sum(len(v) for v in targets.values())
    print(f"{BOLD}[*] Found {len(targets)} hosts with {total_ports} Uvicorn services{RESET}\n")

    # ── Probe all agents concurrently ─────────────────────────────────────────
    all_results: list[dict] = []
    tasks = [
        (host, port)
        for host, ports in sorted(targets.items())
        for port in sorted(ports)
    ]

    current_host = None
    results_by_host: dict[str, list[dict]] = {}

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_task = {
            executor.submit(probe_agent, host, port, args.timeout): (host, port)
            for host, port in tasks
        }

        # Collect results maintaining host grouping
        pending: dict[str, list[dict]] = {h: [] for h in targets}
        for future in as_completed(future_to_task):
            result = future.result()
            pending[result["host"]].append(result)

    # ── Print grouped by host ─────────────────────────────────────────────────
    for host in sorted(pending.keys()):
        results = sorted(pending[host], key=lambda r: r["port"])
        healthy = sum(1 for r in results if r["healthy"])
        print(f"{BOLD}{CYAN}═══ {host} ({healthy}/{len(results)} healthy) ═══{RESET}")
        for result in results:
            print_result(result)
            all_results.append(result)
        print()

    # ── Summary ───────────────────────────────────────────────────────────────
    total_healthy = sum(1 for r in all_results if r["healthy"])
    print(f"{BOLD}[+] Total: {total_healthy}/{len(all_results)} agents healthy{RESET}")

    # ── Agent inventory table ─────────────────────────────────────────────────
    healthy_agents = [r for r in all_results if r["healthy"]]
    if healthy_agents:
        print(f"\n{BOLD}{'HOST':<18} {'PORT':<8} {'AGENT NAME'}{RESET}")
        print("─" * 55)
        for r in sorted(healthy_agents, key=lambda x: (x["host"], x["port"])):
            print(f"  {r['host']:<16} {r['port']:<8} {r['agent']}")

    # ── Save to file ──────────────────────────────────────────────────────────
    if args.output:
        output_data = {
            "scan_time": datetime.now().isoformat(),
            "source_file": args.file,
            "summary": {
                "total_hosts": len(targets),
                "total_agents": len(all_results),
                "healthy_agents": total_healthy,
            },
            "agents": all_results,
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\n{GREEN}[+] Results saved to: {args.output}{RESET}")


if __name__ == "__main__":
    main()
