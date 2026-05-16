"""Attack result tracking.

When an Engagement is provided, results are also persisted to the engagement
DB. With engagement=None this falls back to a process-global list, preserving
backward compatibility with the original standalone CLI scripts.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from aisuite.engine.engagement import Engagement

_results: list[dict] = []


def record(
    attack_type: str,
    agent: dict,
    payload: Any,
    response: Any,
    success_flag: bool,
    *,
    engagement: "Engagement | None" = None,
) -> dict:
    """Append one attack outcome. Returns the dict for chaining."""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "attack": attack_type,
        "target": f"{agent['host']}:{agent['port']}",
        "agent": agent.get("agent", "unknown"),
        "payload": payload,
        "response": str(response)[:1000],
        "success": success_flag,
    }
    if engagement is not None:
        engagement.record_attack(entry)
    else:
        _results.append(entry)
    return entry


def get_results() -> list[dict]:
    """Return the process-global results list (standalone CLI mode)."""
    return _results


def save_results(filepath: str) -> None:
    """Dump the global list to JSON. No-op for engagement-backed runs."""
    with open(filepath, "w") as f:
        json.dump(_results, f, indent=2)
