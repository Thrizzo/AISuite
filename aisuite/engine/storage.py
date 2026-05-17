"""SQLite persistence for engagements.

One DB per engagement under ~/.aisuite/engagements/<id>/engagement.db.
Schema is intentionally minimal — three tables: engagement metadata,
discovered agents, and attack results. The full v2.0 design has a much
richer schema (assumptions, trust zones, crown jewels, decisions, MITRE
mappings) but for the GUI MVP we only persist what's actually written.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS engagement (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS agent (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL,
    host          TEXT NOT NULL,
    port          INTEGER NOT NULL,
    name          TEXT,
    api_format    TEXT,
    purpose       TEXT,
    tools         TEXT,
    healthy       INTEGER NOT NULL DEFAULT 1,
    metadata_json TEXT,
    created_at    TEXT NOT NULL,
    UNIQUE(engagement_id, host, port),
    FOREIGN KEY(engagement_id) REFERENCES engagement(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attack_result (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL,
    technique_id  TEXT NOT NULL,
    target        TEXT NOT NULL,
    params_json   TEXT,
    response_text TEXT,
    success       INTEGER NOT NULL DEFAULT 0,
    timestamp     TEXT NOT NULL,
    FOREIGN KEY(engagement_id) REFERENCES engagement(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_agent_engagement ON agent(engagement_id);
CREATE INDEX IF NOT EXISTS idx_result_engagement ON attack_result(engagement_id);
"""


def default_root() -> Path:
    return Path.home() / ".aisuite" / "engagements"


class Store:
    """Thin wrapper over sqlite3 with per-engagement file isolation."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or default_root()
        self.root.mkdir(parents=True, exist_ok=True)

    def _db_path(self, engagement_id: str) -> Path:
        return self.root / engagement_id / "engagement.db"

    @contextmanager
    def _connect(self, engagement_id: str) -> Iterator[sqlite3.Connection]:
        path = self._db_path(engagement_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            conn.executescript(SCHEMA)
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ── Engagement CRUD ────────────────────────────────────────────────
    def create_engagement(self, name: str, notes: str = "") -> str:
        eid = uuid.uuid4().hex[:12]
        with self._connect(eid) as c:
            c.execute(
                "INSERT INTO engagement(id, name, created_at, notes) VALUES (?,?,?,?)",
                (eid, name, datetime.utcnow().isoformat(), notes),
            )
        return eid

    def list_engagements(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not self.root.exists():
            return out
        for sub in sorted(self.root.iterdir()):
            db = sub / "engagement.db"
            if not db.exists():
                continue
            try:
                with self._connect(sub.name) as c:
                    row = c.execute(
                        "SELECT id, name, created_at, notes FROM engagement"
                    ).fetchone()
                    if row:
                        agent_count = c.execute(
                            "SELECT COUNT(*) FROM agent"
                        ).fetchone()[0]
                        result_count = c.execute(
                            "SELECT COUNT(*) FROM attack_result"
                        ).fetchone()[0]
                        out.append({
                            **dict(row),
                            "agents": agent_count,
                            "results": result_count,
                        })
            except sqlite3.DatabaseError:
                continue
        return sorted(out, key=lambda r: r["created_at"], reverse=True)

    def get_engagement(self, eid: str) -> dict[str, Any] | None:
        with self._connect(eid) as c:
            row = c.execute(
                "SELECT id, name, created_at, notes FROM engagement WHERE id=?",
                (eid,),
            ).fetchone()
            return dict(row) if row else None

    def delete_engagement(self, eid: str) -> None:
        path = self._db_path(eid)
        if path.exists():
            path.unlink()
        if path.parent.exists() and not any(path.parent.iterdir()):
            path.parent.rmdir()

    # ── Agents ─────────────────────────────────────────────────────────
    def upsert_agent(self, eid: str, agent: dict[str, Any]) -> int:
        with self._connect(eid) as c:
            cur = c.execute(
                """
                INSERT INTO agent(engagement_id, host, port, name, api_format,
                                  purpose, tools, healthy, metadata_json, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(engagement_id, host, port) DO UPDATE SET
                    name        = excluded.name,
                    api_format  = excluded.api_format,
                    purpose     = excluded.purpose,
                    tools       = excluded.tools,
                    healthy     = excluded.healthy,
                    metadata_json = excluded.metadata_json
                """,
                (
                    eid,
                    agent["host"],
                    int(agent["port"]),
                    agent.get("name") or agent.get("agent"),
                    agent.get("api_format"),
                    agent.get("purpose"),
                    agent.get("tools"),
                    1 if agent.get("healthy", True) else 0,
                    json.dumps(agent.get("metadata") or {}),
                    datetime.utcnow().isoformat(),
                ),
            )
            return cur.lastrowid or 0

    def list_agents(self, eid: str) -> list[dict[str, Any]]:
        with self._connect(eid) as c:
            rows = c.execute(
                "SELECT * FROM agent WHERE engagement_id=? ORDER BY host, port",
                (eid,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_agent(self, eid: str, agent_id: int) -> dict[str, Any] | None:
        with self._connect(eid) as c:
            row = c.execute(
                "SELECT * FROM agent WHERE engagement_id=? AND id=?",
                (eid, agent_id),
            ).fetchone()
            return dict(row) if row else None

    # ── Attack results ────────────────────────────────────────────────
    def record_result(
        self,
        eid: str,
        *,
        technique_id: str,
        target: str,
        params: dict[str, Any],
        response_text: str,
        success: bool,
    ) -> int:
        with self._connect(eid) as c:
            cur = c.execute(
                """
                INSERT INTO attack_result(engagement_id, technique_id, target,
                                          params_json, response_text, success, timestamp)
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    eid,
                    technique_id,
                    target,
                    json.dumps(params),
                    response_text[:8000],
                    1 if success else 0,
                    datetime.utcnow().isoformat(),
                ),
            )
            return cur.lastrowid or 0

    def list_results(
        self, eid: str, *, technique_id: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        with self._connect(eid) as c:
            if technique_id:
                rows = c.execute(
                    "SELECT * FROM attack_result WHERE engagement_id=? AND technique_id=? "
                    "ORDER BY id DESC LIMIT ?",
                    (eid, technique_id, limit),
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT * FROM attack_result WHERE engagement_id=? "
                    "ORDER BY id DESC LIMIT ?",
                    (eid, limit),
                ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["params"] = json.loads(d.pop("params_json") or "{}")
                except json.JSONDecodeError:
                    d["params"] = {}
                out.append(d)
            return out
