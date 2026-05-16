"""Agent loading and selection. Lifted from ai_sploit.py."""
from __future__ import annotations

import json
import sys
import urllib.parse

import requests

from aisuite.core.logger import error, found
from aisuite.core.input import choose


def load_agents(filepath: str) -> list[dict]:
    """Load agents.json. Accepts either a top-level list or {'agents': [...]}.

    Filters to healthy=True entries (default True if key missing). Exits on
    file-not-found or invalid JSON — this is a CLI helper, not a library
    primitive.
    """
    try:
        with open(filepath) as f:
            data = json.load(f)
        agents = data.get("agents", data) if isinstance(data, dict) else data
        healthy = [a for a in agents if a.get("healthy", True)]
        if not healthy:
            error("No healthy agents found in file.")
            sys.exit(1)
        return healthy
    except FileNotFoundError:
        error(f"File not found: {filepath}")
        sys.exit(1)
    except json.JSONDecodeError:
        error(f"Invalid JSON: {filepath}")
        sys.exit(1)


def select_agent(agents: list[dict]) -> dict:
    """Interactive target picker."""
    options = [f"{a['agent']}  ({a['host']}:{a['port']})" for a in agents]
    idx = choose("Select target agent:", options)
    return agents[idx]


def agent_from_url(url: str) -> list[dict]:
    """Build a single-agent list from a full endpoint URL.

    Example: http://192.168.50.30:8030/chat
    """
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "unknown"
    port = parsed.port or 80
    endpoint = parsed.path or "/chat"

    # Try /health to pick up the real agent name.
    health_url = f"http://{host}:{port}/health"
    name = f"Agent:{port}"
    try:
        r = requests.get(health_url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            name = data.get("agent") or data.get("name") or data.get("service") or name
    except Exception:
        pass

    agent = {
        "host": host,
        "port": port,
        "agent": name,
        "healthy": True,
        "tools": "",
        "api_format": endpoint,
    }
    found(f"Target: {name}  ({host}:{port}{endpoint})")
    return [agent]
