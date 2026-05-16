# AISuite v2.0 — Design Document

**Author:** Claude Code (for review by Jeff Simpson)
**Date:** 2026-05-09
**Branch:** `v2.0/build`
**Status:** AWAITING APPROVAL — no package code will be written until sign-off

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Core Module Layout](#2-core-module-layout)
3. [Engine Module Layout](#3-engine-module-layout)
4. [Attack Catalog & Canonical Numbering](#4-attack-catalog--canonical-numbering)
5. [Recon Module Layout](#5-recon-module-layout)
6. [Attack Module Layout](#6-attack-module-layout)
7. [SQLite Schema & Engagement Data Model](#7-sqlite-schema--engagement-data-model)
8. [Attack Intelligence Brief Schema](#8-attack-intelligence-brief-schema)
9. [Detection Rule Database](#9-detection-rule-database)
10. [MITRE ATLAS Technique Catalog](#10-mitre-atlas-technique-catalog)
11. [GUI Screens & API Endpoints](#11-gui-screens--api-endpoints)
12. [Engagement Modes](#12-engagement-modes)
13. [Course Script Integration](#13-course-script-integration)
14. [Embedding Inversion Integration](#14-embedding-inversion-integration)
15. [UI Design Language](#15-ui-design-language)
16. [Signature Normalization Log](#16-signature-normalization-log)
17. [Package Layout & pyproject.toml](#17-package-layout--pyprojecttoml)
18. [Build Phases](#18-build-phases)
19. [Open Questions](#19-open-questions)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 3 — INTERFACES                                          │
│  ┌─────────────┐  ┌──────────────────────────────────────────┐ │
│  │  cli.py      │  │  web.py (FastAPI)                       │ │
│  │  (Click)     │  │  api.py (REST endpoints)                │ │
│  │              │  │  static/ (HTMX + AlpineJS + Tailwind)   │ │
│  └──────┬───────┘  └──────────────┬───────────────────────────┘ │
│         │                         │                             │
│         ▼                         ▼         SSE (live stream)   │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  Layer 2 — ENGINE + PLUGINS                                ││
│  │  ┌────────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐ ││
│  │  │ engagement │ │ recon/*  │ │ attacks/*│ │ reports/*   │ ││
│  │  │ brief      │ │          │ │          │ │             │ ││
│  │  │ assumption │ │ network  │ │ chat/    │ │ html        │ ││
│  │  │ trust_zone │ │ surface  │ │ poison/  │ │ markdown    │ ││
│  │  │ escalation │ │ finger   │ │ persist/ │ │ pdf         │ ││
│  │  │ crown_jewel│ │ rag_det  │ │ a2a/     │ │ brief_render│ ││
│  │  │ mitre      │ │ embed    │ │          │ │             │ ││
│  │  │ roe        │ │          │ │          │ │             │ ││
│  │  │ decision   │ │          │ │          │ │             │ ││
│  │  │ attack_base│ │          │ │          │ │             │ ││
│  │  └────────────┘ └──────────┘ └──────────┘ └─────────────┘ ││
│  └─────────────────────────┬───────────────────────────────────┘│
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  Layer 1 — CORE (shared primitives)                        ││
│  │  logger · http · curl · input · agents · results ·         ││
│  │  storage · stealth · detection_db                          ││
│  └─────────────────────────────────────────────────────────────┘│
│                            │                                    │
│                            ▼                                    │
│                    ~/.aisuite/engagements/<name>/                │
│                    engagement.db  artifacts/  reports/           │
└─────────────────────────────────────────────────────────────────┘
```

**Key constraints:**
- HTMX + AlpineJS + Tailwind via CDN — no build step, no SPA framework
- FastAPI serves HTML fragments for HTMX swaps + REST JSON for programmatic access
- SQLite per engagement, Alembic for migrations
- SSE for live phase output streaming
- Localhost:8888 by default, `--remote` enables 0.0.0.0 with token auth

---

## 2. Core Module Layout

`aisuite/core/` — shared primitives imported by everything above.

### `logger.py` — Terminal output helpers

```python
def info(msg: str) -> None          # [*] cyan prefix
def success(msg: str) -> None       # [+] green prefix
def warn(msg: str) -> None          # [!] yellow prefix
def error(msg: str) -> None         # [✗] red prefix
def found(msg: str) -> None         # [►] green bold prefix
def divider(title: str = "") -> None  # ─── boxed title ───
def banner(title: str, phase: str = "") -> None  # ═══ phase banner ═══
```

ANSI color constants exported: `GREEN, RED, YELLOW, CYAN, MAGENTA, BOLD, DIM, RESET`.

**Normalization note:** Banner color standardized to RED (matches ai_sploit.py, the primary attack interface). ai_suite.py used CYAN for recon banners — that distinction moves to the `phase` parameter display, not the banner frame color.

### `http.py` — HTTP primitives

```python
def post(url: str, data: dict, timeout: int = 15) -> requests.Response | None
def get(url: str, timeout: int = 5) -> requests.Response | None
def send_chat(
    host: str, port: int, message: str, *,
    session_id: str | None = None,
    endpoint: str = "/chat",
    timeout: int = 30,
) -> dict | None
def smart_chat(
    host: str, port: int, message: str, *,
    session_id: str | None = None,
    timeout: int = 10,
    rate_delay: float = 0.0,
) -> dict  # always returns dict with text/sources/metadata/format_used/raw
def upload_file(
    host: str, port: int, filepath: str, *,
    endpoint: str = "/upload",
    timeout: int = 30,
) -> requests.Response | None
```

**Normalization note:** `_post` renamed to `post` (no leading underscore — it's a public API). Default timeout for `send_chat` normalized to 30s (rag_attacks value — the higher value is safer for RAG systems that do retrieval before responding). `smart_chat` preserved from ai_suite.py with its multi-format probing. `upload_file` promoted from rag_attacks.py.

### `curl.py` — Curl preview builder

```python
def build_curl(
    host: str, port: int, endpoint: str, payload: dict, *,
    method: str = "POST",
    file_upload: bool = False,
) -> str
```

### `input.py` — Interactive input helpers

```python
def ask(prompt: str, default: str | None = None) -> str | None
def choose(prompt: str, options: list[str]) -> int  # 0-based index
def preview_and_confirm(curl_cmd: str, payload_preview: str | None = None) -> str
    # Returns 'y', 'e', or 'n'. Never returns bool.
```

**Normalization note:** `preview_and_confirm` return type fixed to `str` everywhere. ai_sploit.py's `-> bool` annotation was wrong — the function already returned `'y'/'e'/'n'` strings and callers compared against strings.

### `agents.py` — Agent loading and selection

```python
def load_agents(filepath: str) -> list[dict]
def select_agent(agents: list[dict]) -> dict
def agent_from_url(url: str) -> list[dict]
```

### `results.py` — Attack result tracking

```python
def record(
    attack_type: str, agent: dict,
    payload: Any, response: Any, success_flag: bool,
    *, engagement: "Engagement | None" = None,
) -> dict  # returns the result dict for chaining
def get_results() -> list[dict]
def save_results(filepath: str) -> None
```

**Normalization note:** When `engagement` is provided, the result is also written to the engagement DB's `attack_results` table. When None, falls back to the global results list (backward-compatible with standalone CLI mode).

### `storage.py` — SQLite engagement DB

```python
def get_engine(db_path: str) -> Engine
def get_session(engine: Engine) -> Session
def init_db(db_path: str) -> Engine  # runs Alembic migrations
def get_engagement_dir(name: str) -> Path  # ~/.aisuite/engagements/<name>/
def get_active_engagement() -> str | None  # reads ~/.aisuite/active symlink
def set_active_engagement(name: str) -> None  # sets symlink
```

### `stealth.py` — Rate limiting and jitter

```python
def rate_limit(delay: float) -> None  # sleep with jitter
def apply_stealth(*, rate: float = 0.0, jitter: float = 0.0) -> None
```

### `detection_db.py` — Detection rule → evasion mapping

```python
@dataclass
class DetectionRule:
    id: str              # e.g. "D02", "AIM3_KEYWORDS", "WORKFLOW_SKIP"
    name: str            # human-readable name
    triggers_on: str     # what behavior fires the rule
    category: str        # "recon", "injection", "a2a", "workflow"

@dataclass
class EvasionTechnique:
    id: str              # e.g. "CHAR_SPACING", "CRESCENDO"
    name: str            # "Character spacing"
    description: str     # how it works
    bypasses: list[str]  # rule IDs this technique bypasses

def get_all_rules() -> list[DetectionRule]
def get_all_evasions() -> list[EvasionTechnique]
def get_evasions_for_rule(rule_id: str) -> list[EvasionTechnique]
def get_rules_triggered_by(attack_id: str) -> list[DetectionRule]
```

Populated from checklist §17 "Detection Evasion" table. See [Section 9](#9-detection-rule-database) for the full data.

---

## 3. Engine Module Layout

`aisuite/engine/` — engagement logic, data models, the Attack Intelligence Brief.

### `engagement.py` — Central engagement state

```python
@dataclass
class EngagementConfig:
    name: str
    client: str                    # for --company injection in seed banks
    target_scope: str              # CIDR or target list
    mode: EngagementMode           # lab / grey_box / black_box
    created_at: datetime
    roe: "RulesOfEngagement | None"

class Engagement:
    config: EngagementConfig
    brief: "AttackIntelligenceBrief"
    db: Session                    # SQLAlchemy session

    def create(name: str, ...) -> "Engagement"
    def load(name: str) -> "Engagement"
    def list_all() -> list[str]
    def get_active() -> "Engagement | None"
    def record_attack(result: dict) -> None
    def record_decision(entry: DecisionLogEntry) -> None
    def add_assumption(obs: str, hypothesis: str, confidence: str) -> Assumption
    def add_target(host: str, port: int, agent_name: str, **details) -> Target
    def export_brief(format: str = "markdown") -> str
```

### `brief.py` — Attack Intelligence Brief data model

```python
class AttackIntelligenceBrief:
    version: str                     # "1.0", "1.1", etc — auto-increments
    target_summary: TargetSummary
    architecture_confidence: str     # HIGH / MEDIUM / LOW
    crown_jewels: list[CrownJewel]
    assumptions: list[Assumption]
    trust_zones: list[TrustZone]
    escalation_paths: list[EscalationPath]
    decision_log: list[DecisionLogEntry]
    version_history: list[BriefVersion]

    def bump_version(reason: str) -> str    # returns new version string
    def snapshot() -> BriefVersion          # immutable snapshot for history
    def to_dict() -> dict                   # serializable
```

See [Section 8](#8-attack-intelligence-brief-schema) for the full schema.

### `assumption.py`

```python
@dataclass
class Assumption:
    id: int
    observation: str
    hypothesis: str
    confidence: str       # HIGH / MEDIUM / LOW
    status: str           # VALIDATED / UNVALIDATED / INVALIDATED
    source: str           # which recon phase or attack produced this
    validated_by: str | None  # attack or observation that validated
    created_at: datetime
    updated_at: datetime
```

### `trust_zone.py`

```python
@dataclass
class TrustZone:
    id: int
    name: str
    components: list[str]        # agent names, services
    boundary_type: str           # "validated" or "unvalidated"
    notes: str

@dataclass
class TrustBoundary:
    id: int
    zone_a_id: int
    zone_b_id: int
    validated: bool              # solid line if True, dashed if False
    crossing_method: str | None  # how to cross (attack reference)
```

### `escalation.py`

```python
@dataclass
class EscalationPath:
    id: int
    name: str
    status: str               # HOLD / GO / BLOCKED
    steps: list[str]          # ordered list of attack IDs or actions
    mitre_atlas: list[str]    # MITRE ATLAS technique IDs
    mitre_attack: list[str]   # MITRE ATT&CK technique IDs
    detection_risk: str       # HIGH / MEDIUM / LOW
    time_window: str | None   # RoE time constraint
    rationale: str            # why this path, why this status
    blocking_reason: str | None
```

### `crown_jewel.py`

```python
@dataclass
class CrownJewel:
    id: int
    name: str
    description: str
    offensive_value: int          # 1-10 ranking
    access_status: str            # OBTAINED / ACCESSIBLE / BEHIND-N-BOUNDARIES
    boundaries_count: int | None  # for BEHIND-N
    evidence: str | None          # attack result reference
```

### `mitre.py` — Technique catalog

```python
@dataclass
class MitreTechnique:
    id: str              # "AML.T0051.000"
    name: str            # "LLM Prompt Injection: Direct"
    framework: str       # "ATLAS" or "ATT&CK"
    tactic: str          # "Initial Access", "Persistence", etc.
    description: str

def get_technique(id: str) -> MitreTechnique | None
def get_techniques_for_attack(attack_id: str) -> list[MitreTechnique]
def get_all_techniques() -> list[MitreTechnique]
```

See [Section 10](#10-mitre-atlas-technique-catalog) for the full data.

### `roe.py` — Rules of Engagement enforcement

```python
@dataclass
class RulesOfEngagement:
    time_windows: list[TimeWindow]       # allowed testing hours
    in_scope: list[str]                  # CIDRs, hostnames
    out_of_scope: list[str]
    allowed_actions: list[str]
    blocked_actions: list[str]
    reporting_requirements: list[str]    # e.g. "MCP invocations within 24h"

class RoEEnforcer:
    def check_target(host: str, port: int) -> RoEResult
    def check_time_window() -> RoEResult
    def check_action(action: str) -> RoEResult
```

In `lab` mode, the enforcer always returns ALLOW. In `grey_box` and `black_box`, violations return BLOCK with reason.

### `decision_log.py`

```python
@dataclass
class DecisionLogEntry:
    id: int
    timestamp: datetime
    type: str              # "GO", "NO_GO", "HOLD", "OBSERVATION", "ATTACK", "BRIEF_VERSION"
    description: str
    rationale: str
    attack_id: str | None  # if this decision was tied to an attack
    brief_version: str     # which brief version this was logged under
    auto: bool             # True if system-generated (attack result), False if manual
```

### `attack_base.py` — Base class for all attacks

```python
class BaseAttack(ABC):
    # Class-level declarations (set by each subclass)
    catalog_id: str            # checklist section number, e.g. "2"
    name: str                  # "System Prompt Extraction"
    kill_chain_phase: str      # "RECON" / "POISON" / "HIJACK" / "PERSIST" / "IMPACT"
    osai_chapter: str          # "3.2.1"
    triggers_detection: list[str]   # ["AIM3_KEYWORDS"]
    evasion_options: list[str]      # ["CHAR_SPACING", "REFRAME"]
    mitre_atlas: list[str]          # ["AML.T0051.000"]
    requires: list[str]             # ["file_read", "config_lookup"]
    implemented: bool               # False for placeholders

    @abstractmethod
    def execute(self, agent: dict, engagement: Engagement, **kwargs) -> dict:
        """Run the attack. Returns result dict."""
        ...

    @abstractmethod
    def get_parameters(self) -> list[AttackParameter]:
        """Return parameter schema for GUI form generation."""
        ...

    def pre_flight_check(self, agent: dict, engagement: Engagement) -> list[str]:
        """Return list of warnings (detection rules, RoE, etc)."""
        ...
```

### `recon_base.py` — Base class for recon phases

```python
class BaseRecon(ABC):
    name: str
    phase_number: int

    @abstractmethod
    async def execute(self, engagement: Engagement, **kwargs) -> AsyncIterator[str]:
        """Run recon phase, yielding SSE-friendly progress lines."""
        ...

    @abstractmethod
    def get_parameters(self) -> list[ReconParameter]:
        ...
```

---

## 4. Attack Catalog & Canonical Numbering

Canonical IDs use checklist section numbers. This matches OSAI chapter structure and avoids confusion during the exam.

| Catalog ID | Name | Kill Chain | OSAI Ch | Status | ai_sploit.py Old # |
|---|---|---|---|---|---|
| 1 | AI Enumeration (Recon) | RECON | 2+3.1 | Implemented (ai_suite.py) | — |
| 2 | System Prompt Extraction | HIJACK | 3.2.1 | Implemented | 1 |
| 3 | Goal Hijacking | HIJACK | 3.2.2 | Implemented | 2 |
| 4 | Document Fragmentation | POISON | 3.3.1 | Implemented | 3 |
| 5 | CSS Web Injection | POISON | 3.3.2 | Implemented | 4 |
| 6 | Code Import Resolution | POISON | 3.3.3 | Implemented | 5 |
| 7 | Database Poisoning | PERSIST | 3.4.1 | Implemented | 6 |
| 8 | Session Enumeration | PERSIST | 3.4.2 | Implemented | 7 |
| 8G | Guided Engagement | FULL CHAIN | — | Implemented | 8 |
| 9 | A2A Multi-Agent Enumeration | RECON | 4.1 | Placeholder | — |
| 10 | Workflow Integrity Bypass | HIJACK | 4.4.1 | Placeholder | — |
| 11 | Malicious Link Injection | IMPACT | 4.4.2 | Placeholder | — |
| 12 | LLM-Mediated SQL Injection | IMPACT | 4.4.3 | Placeholder | — |
| 13 | Rogue Agent Registration | POISON | 4.2 | Placeholder | — |
| 14 | Agent Card Spoofing | HIJACK | 4.3 | Placeholder | — |
| 15 | A2A Data Poisoning | POISON | 4.5 | Placeholder | — |
| R12 | Ingestion Poisoning | POISON | 5.2.2 | Implemented | 12 |
| R13 | Embedding Collision | POISON | 5.2.3 | Implemented | 13 |
| R14 | Retrieval Hijacking | POISON | 5.2.4 | Implemented | 14 |

**Notes:**
- RAG attacks (R12-R14) use the `R` prefix because checklist sections 12-15 are already taken by A2A/SQLi attacks. The `R` prefix signals "RAG chapter" and preserves the OSAI 5.2.x numbering the user is already familiar with from ai_sploit.py.
- Catalog ID "8G" for Guided Engagement — it's a meta-attack that chains others, not a standalone technique.
- **Confirm or override:** Is `R12/R13/R14` acceptable, or would you prefer a different scheme (e.g., `5.2.2`, `5.2.3`, `5.2.4` matching OSAI chapters directly)?

---

## 5. Recon Module Layout

`aisuite/recon/` — each module wraps existing recon functionality.

### `network_scan.py`
Wraps ai_enum.py + ai_suite.py Phase 1-2 (nmap parse/run + /health probing).

```python
class NetworkScan(BaseRecon):
    async def execute(engagement, *, nmap_file=None, target_spec=None, stealth=False, rate=0):
        # Parse nmap or run nmap → probe /health → yield progress → write to engagement DB
```

### `surface_map.py`
Wraps ai_suite.py Phase 3 (OpenAPI discovery, tool enumeration, smart_chat purpose query).

```python
class SurfaceMap(BaseRecon):
    async def execute(engagement):
        # For each healthy agent → smart_chat "what do you do" → get_openapi_endpoints → write surface data
```

### `fingerprint.py`
Wraps ai_suite.py Phase 4 (identity probing, stealth fingerprint, contradiction test).

```python
class Fingerprint(BaseRecon):
    async def execute(engagement, *, stealth=True):
        # Stealth: metadata leak → contradiction → context window
        # Normal: identity probes
```

### `rag_detect.py`
Wraps ai_suite.py Phase 5 (8 probe queries × 7 signals).

```python
class RAGDetect(BaseRecon):
    async def execute(engagement):
        # RAG_QUERIES → signal detection → RAG confirmation → doc name extraction
```

### `embed_recon.py`
Wraps existing embed_recon.py + imports course-provided scripts.

```python
class EmbedRecon(BaseRecon):
    async def execute(engagement, *, host, port=None, collection=None, ...):
        # detect_vector_db → export → fingerprint_model → triage_chunks

    def run_inference_probing(npy_path, url, **kwargs) -> dict:
        # Wraps course inference_probing.py main() as callable function

    def run_chunk_triage(npy_path, **kwargs) -> dict:
        # Wraps course chunk_triage_pipe.py main() as callable function
```

---

## 6. Attack Module Layout

`aisuite/attacks/` — grouped by NVIDIA Kill Chain phase.

### `chat/` — Direct chat-based attacks (Catalog 2-3)

```python
# prompt_extraction.py — Catalog ID: 2 (was Attack 1)
class PromptExtraction(BaseAttack):
    catalog_id = "2"
    name = "System Prompt Extraction"
    kill_chain_phase = "HIJACK"
    osai_chapter = "3.2.1"
    triggers_detection = ["AIM3_KEYWORDS"]
    evasion_options = ["CHAR_SPACING", "REFRAME", "SOCIAL_ENG", "TRANSLATION"]
    mitre_atlas = ["AML.T0051.000"]
    requires = ["file_read", "config_lookup"]  # optional, attack still works without
    implemented = True

# goal_hijacking.py — Catalog ID: 3 (was Attack 2)
class GoalHijacking(BaseAttack):
    catalog_id = "3"
    ...
```

### `poison/` — Poisoning attacks (Catalog 4-6, R12-R14)

```python
# doc_fragmentation.py — Catalog ID: 4 (was Attack 3)
# css_injection.py     — Catalog ID: 5 (was Attack 4)
# code_import.py       — Catalog ID: 6 (was Attack 5)
# ingestion.py         — Catalog ID: R12 (was Attack 12)
# collision.py         — Catalog ID: R13 (was Attack 13)
# hijacking.py         — Catalog ID: R14 (was Attack 14)
```

### `persist/` — Persistence attacks (Catalog 7-8)

```python
# db_poisoning.py      — Catalog ID: 7 (was Attack 6)
# session_enum.py      — Catalog ID: 8 (was Attack 7)
```

### `a2a/` — A2A attacks (Catalog 9-15) — PLACEHOLDER

```python
# __init__.py
"""
A2A attack modules — not implemented in v2.0.
Checklist sections 9-15 are documented with full curl commands.
Drop-in implementation can follow the BaseAttack pattern.

TODO v2.1:
  - attacks/a2a/multi_agent_enum.py   (Catalog 9)
  - attacks/a2a/workflow_bypass.py    (Catalog 10)
  - attacks/a2a/link_injection.py     (Catalog 11)
  - attacks/a2a/sql_injection.py      (Catalog 12)
  - attacks/a2a/rogue_agent.py        (Catalog 13)
  - attacks/a2a/card_spoofing.py      (Catalog 14)
  - attacks/a2a/data_poisoning.py     (Catalog 15)
"""
```

### `guided.py` — Catalog ID: 8G (Guided Engagement meta-attack)

Wraps attack_guided_engagement — a multi-step chain that lets the user select attacks in sequence.

---

## 7. SQLite Schema & Engagement Data Model

Normalized schema, managed by Alembic. One `engagement.db` per engagement directory.

```sql
-- Core
CREATE TABLE engagements (
    id          INTEGER PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    client      TEXT NOT NULL DEFAULT '',
    target_scope TEXT NOT NULL,
    mode        TEXT NOT NULL CHECK(mode IN ('lab','grey_box','black_box')),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE roe (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER REFERENCES engagements(id),
    time_windows    TEXT,  -- JSON array of {start, end, days}
    in_scope        TEXT,  -- JSON array
    out_of_scope    TEXT,  -- JSON array
    allowed_actions TEXT,  -- JSON array
    blocked_actions TEXT,  -- JSON array
    reporting_reqs  TEXT   -- JSON array
);

-- Targets discovered during recon
CREATE TABLE targets (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER REFERENCES engagements(id),
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL,
    agent_name      TEXT,
    healthy         BOOLEAN DEFAULT TRUE,
    purpose         TEXT,
    tools           TEXT,           -- JSON array
    endpoints       TEXT,           -- JSON array
    api_format      TEXT,
    model_family    TEXT,
    rag_active      BOOLEAN DEFAULT FALSE,
    rag_signals     TEXT,           -- JSON array of signal names
    rag_documents   TEXT,           -- JSON array of doc names
    surface_data    TEXT,           -- JSON blob for extra surface map data
    created_at      TEXT NOT NULL,
    UNIQUE(engagement_id, host, port)
);

-- Attack Intelligence Brief
CREATE TABLE brief_versions (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER REFERENCES engagements(id),
    version         TEXT NOT NULL,          -- "1.0", "1.1"
    reason          TEXT NOT NULL,          -- why version bumped
    snapshot        TEXT NOT NULL,          -- full JSON snapshot of brief state
    created_at      TEXT NOT NULL
);

CREATE TABLE assumptions (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER REFERENCES engagements(id),
    observation     TEXT NOT NULL,
    hypothesis      TEXT NOT NULL,
    confidence      TEXT NOT NULL CHECK(confidence IN ('HIGH','MEDIUM','LOW')),
    status          TEXT NOT NULL CHECK(status IN ('VALIDATED','UNVALIDATED','INVALIDATED')),
    source          TEXT NOT NULL,
    validated_by    TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE trust_zones (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER REFERENCES engagements(id),
    name            TEXT NOT NULL,
    components      TEXT,           -- JSON array
    boundary_type   TEXT NOT NULL CHECK(boundary_type IN ('validated','unvalidated')),
    notes           TEXT
);

CREATE TABLE trust_boundaries (
    id              INTEGER PRIMARY KEY,
    zone_a_id       INTEGER REFERENCES trust_zones(id),
    zone_b_id       INTEGER REFERENCES trust_zones(id),
    validated       BOOLEAN DEFAULT FALSE,
    crossing_method TEXT
);

CREATE TABLE escalation_paths (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER REFERENCES engagements(id),
    name            TEXT NOT NULL,
    status          TEXT NOT NULL CHECK(status IN ('HOLD','GO','BLOCKED')),
    steps           TEXT,           -- JSON array
    mitre_atlas     TEXT,           -- JSON array of technique IDs
    mitre_attack    TEXT,           -- JSON array
    detection_risk  TEXT CHECK(detection_risk IN ('HIGH','MEDIUM','LOW')),
    time_window     TEXT,
    rationale       TEXT NOT NULL,
    blocking_reason TEXT
);

CREATE TABLE crown_jewels (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER REFERENCES engagements(id),
    name            TEXT NOT NULL,
    description     TEXT,
    offensive_value INTEGER CHECK(offensive_value BETWEEN 1 AND 10),
    access_status   TEXT CHECK(access_status IN ('OBTAINED','ACCESSIBLE','BEHIND_N_BOUNDARIES')),
    boundaries_count INTEGER,
    evidence        TEXT
);

CREATE TABLE decision_log (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER REFERENCES engagements(id),
    timestamp       TEXT NOT NULL,
    type            TEXT NOT NULL,
    description     TEXT NOT NULL,
    rationale       TEXT,
    attack_id       TEXT,
    brief_version   TEXT NOT NULL,
    auto            BOOLEAN DEFAULT FALSE
);

-- Attack execution history
CREATE TABLE attack_results (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER REFERENCES engagements(id),
    timestamp       TEXT NOT NULL,
    catalog_id      TEXT NOT NULL,       -- "2", "R12", etc.
    attack_name     TEXT NOT NULL,
    target_host     TEXT NOT NULL,
    target_port     INTEGER NOT NULL,
    agent_name      TEXT,
    payload         TEXT,               -- JSON
    response        TEXT,               -- truncated response
    success         BOOLEAN,
    curl_command    TEXT,               -- for evidence
    notes           TEXT
);

-- Ground truth for inversion comparison
CREATE TABLE ground_truth (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER REFERENCES engagements(id),
    chunk_index     INTEGER NOT NULL,
    source_file     TEXT,               -- "MC1_password_reset.pdf"
    original_text   TEXT NOT NULL,
    uploaded_at     TEXT NOT NULL
);

-- Inversion results
CREATE TABLE inversion_results (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER REFERENCES engagements(id),
    chunk_index     INTEGER NOT NULL,
    method          TEXT NOT NULL CHECK(method IN ('emb_fin','zero2text')),
    recovered_text  TEXT NOT NULL,
    similarity      REAL,
    slots           TEXT,               -- JSON: {"PASSWORD": {"value": "N0=Acc3ss", "confidence": "HIGH"}}
    template_used   TEXT,
    config          TEXT,               -- JSON: full config snapshot
    created_at      TEXT NOT NULL
);

-- MCP invocation tracking (grey_box mode)
CREATE TABLE mcp_invocations (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER REFERENCES engagements(id),
    timestamp       TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    parameters      TEXT,              -- JSON
    result_summary  TEXT,
    reported        BOOLEAN DEFAULT FALSE,
    report_deadline TEXT               -- 24h from timestamp
);
```

---

## 8. Attack Intelligence Brief Schema

The brief mirrors OSAI Module 10's structure. JSON representation:

```json
{
  "version": "1.3",
  "engagement": "MegaCorpAI Grey-Box 2026-05",
  "target_summary": {
    "scope": "192.168.50.21-30",
    "hosts_discovered": 10,
    "agents_healthy": 8,
    "architecture_confidence": "MEDIUM",
    "notes": "RAG confirmed on 3 agents, A2A not detected"
  },
  "crown_jewels": [
    {
      "name": "PostgreSQL production credentials",
      "offensive_value": 9,
      "access_status": "OBTAINED",
      "evidence": "Attack 2 via character spacing on :8011"
    }
  ],
  "assumptions": [
    {
      "observation": "Agent on :8030 returns bm25_score in RAG responses",
      "hypothesis": "Hybrid retrieval (vector + BM25) active",
      "confidence": "HIGH",
      "status": "VALIDATED",
      "source": "Recon Phase 5",
      "validated_by": "Attack R13 hit 83% of test queries"
    }
  ],
  "trust_zones": [
    {
      "name": "RAG Pipeline Zone",
      "components": ["Employee Helpdesk :8030", "Weaviate :8080"],
      "boundary_type": "validated"
    }
  ],
  "escalation_paths": [
    {
      "name": "RAG → File Read → .profile extraction",
      "status": "GO",
      "steps": ["R14 (wine.txt cover)", "Stage 1 dump", "Stage 2 grep"],
      "mitre_atlas": ["AML.T0051.001"],
      "detection_risk": "LOW",
      "rationale": "Cover doc topic unrelated to KB — only attacker query triggers"
    }
  ],
  "decision_log": [
    {
      "timestamp": "2026-05-09T14:30:00",
      "type": "GO",
      "description": "Proceed with retrieval hijacking via wine.txt cover",
      "rationale": "Capability recon confirmed file_read EXISTS_FILTERED, cover topic clear of KB",
      "attack_id": "R14",
      "brief_version": "1.2"
    }
  ]
}
```

**Auto-versioning rules:**
- Version bumps on: assumption status change, escalation path status change, crown jewel added/status changed, finding added to attack_results
- Each bump stores an immutable JSON snapshot in `brief_versions` table
- GUI shows current version + dropdown to view any past version

---

## 9. Detection Rule Database

Derived from checklist §17 "Detection Evasion" table + "A2A Detection Rules Reference". Hardcoded in `core/detection_db.py`.

### Evasion Technique → Rule Bypass Map

| Technique ID | Technique Name | Bypasses Rule(s) |
|---|---|---|
| `CHAR_SPACING` | Character spacing | `OUTPUT_STRING_MATCH` |
| `SINGLE_KEYWORD` | Single keyword reframe | `KEYWORD_DENSITY` |
| `CRESCENDO` | Multi-turn crescendo | `PER_MESSAGE_ANALYSIS` |
| `CSS_HIDDEN` | CSS hidden text | `CONTENT_EXTRACTION` |
| `IMPORT_RESOLUTION` | Import resolution | `CONTENT_SCANNER` |
| `DESCRIPTIVE` | Descriptive phrasing | `IMPERATIVE_COMMAND`, `AIM3_STORED_MEMORY` |
| `HISTORY_INJECTION` | History injection | `PROMPT_CONTENT_RULES`, `WORKFLOW_SKIP` |
| `HOMOGRAPH` | Homograph domains | `UNSEEN_IP` |
| `SQL_CAST` | SQL CAST encoding | `XP_CMDSHELL_KEYWORD` |
| `SUBSET_REGISTER` | Subset capability register | `DUPLICATE_CAPABILITY` |
| `RESPONSE_JITTER` | Response jitter | `TIMING_ANOMALY` |
| `SELECTIVE_INTERCEPT` | Selective interception | `EXCESSIVE_RETRIEVAL` |
| `HOSTS_FILE` | Hosts file (vs DNS) | `UNAUTHORIZED_DNS` |
| `SEMANTIC_DISGUISE` | Semantic disguise | `AIM3_KEYWORDS`, `INJECTION_KEYWORDS_DATA` |
| `FRAGMENTATION` | Fragmentation | `EXECUTABLE_INSTRUCTIONS`, `AIM3_INGESTED` |
| `STEALTH_FLAG` | --stealth flag | `D03_IDENTITY_PROBING` |
| `RATE_FLAG` | --rate flag | `D02_SEQUENTIAL_ENUM` |

### Detection Rule Catalog

| Rule ID | Rule Name | Triggers On | Category |
|---|---|---|---|
| `D02_SEQUENTIAL_ENUM` | Sequential Enumeration | Rapid requests to AI API paths | recon |
| `D03_IDENTITY_PROBING` | Identity Probing | Multiple identity questions same session | recon |
| `E01_DOC_ENUM` | Document Enumeration | "what documents", "list documents" in query | recon |
| `E04_PROMPT_EXTRACT` | System Prompt Extraction | "system prompt", "your instructions" in query | recon |
| `AIM3_KEYWORDS` | Prompt Injection Keywords | "ignore", "instead output", "your new task" | injection |
| `AIM3_INGESTED` | Instruction Strings in Ingested Content | Injection phrases in uploaded files | injection |
| `AIM3_STORED_MEMORY` | Imperative Commands in Stored Memory | "direct users to", "tell them to" | injection |
| `OUTPUT_STRING_MATCH` | Output String Matching | Credential patterns in output | injection |
| `KEYWORD_DENSITY` | Keyword Density | 3+ monitored terms in one message | injection |
| `PER_MESSAGE_ANALYSIS` | Per-Message Analysis | Single-message intent classification | injection |
| `CONTENT_EXTRACTION` | Content Extraction Pipeline | Hidden content in fetched pages | injection |
| `CONTENT_SCANNER` | Content Scanner | Malicious patterns in uploaded code | injection |
| `IMPERATIVE_COMMAND` | Imperative Command Detector | Command verbs in stored data | injection |
| `PROMPT_CONTENT_RULES` | Prompt Content Rules | Routing signals in prompt | workflow |
| `WORKFLOW_SKIP` | Security Scan Workflow Step Skipped | Missing validation step | workflow |
| `UNSEEN_IP` | A2A Traffic to Previously Unseen IP | Request to unknown IP | a2a |
| `XP_CMDSHELL_KEYWORD` | Dangerous XP_CmdShell Usage | xp_cmdshell in SQL | a2a |
| `DUPLICATE_CAPABILITY` | Duplicate Agent Capability Registration | Same capability re-registered | a2a |
| `TIMING_ANOMALY` | Timing Anomaly Detection | Unusual response timing | a2a |
| `EXCESSIVE_RETRIEVAL` | Excessive Data Retrieval | High-volume data requests | a2a |
| `UNAUTHORIZED_DNS` | DNS Response from Unauthorized Source | DNS hijack | a2a |
| `INJECTION_KEYWORDS_DATA` | Prompt Injection Keywords in Data Field | Injection in product/CRM data | a2a |
| `EXECUTABLE_INSTRUCTIONS` | Executable Instructions in Product Data | Imperatives in data fields | a2a |
| `VECTOR_RAPID_PAGE` | Vector Store Rapid Pagination | Many GraphQL/HTTP calls in seconds | recon |

### Per-Attack Detection Mapping

Each `BaseAttack` subclass declares `triggers_detection` and `evasion_options`. Here's the complete map:

| Catalog ID | Attack | Triggers | Evasion Options |
|---|---|---|---|
| 2 | System Prompt Extraction | `AIM3_KEYWORDS` | `CHAR_SPACING`, `SINGLE_KEYWORD`, `SEMANTIC_DISGUISE` |
| 3 | Goal Hijacking | `AIM3_KEYWORDS`, `KEYWORD_DENSITY` | `SINGLE_KEYWORD`, `CRESCENDO` |
| 4 | Document Fragmentation | `AIM3_INGESTED` | `FRAGMENTATION`, `DESCRIPTIVE` |
| 5 | CSS Web Injection | `CONTENT_EXTRACTION` | `CSS_HIDDEN` |
| 6 | Code Import Resolution | `CONTENT_SCANNER` | `IMPORT_RESOLUTION` |
| 7 | Database Poisoning | `AIM3_STORED_MEMORY` | `DESCRIPTIVE` |
| 8 | Session Enumeration | (none — looks like normal traffic) | (none needed) |
| R12 | Ingestion Poisoning | `AIM3_INGESTED` | `DESCRIPTIVE`, `FRAGMENTATION` |
| R13 | Embedding Collision | `AIM3_INGESTED` | `DESCRIPTIVE`, `FRAGMENTATION` |
| R14 | Retrieval Hijacking | `AIM3_INGESTED` | `SEMANTIC_DISGUISE` |

---

## 10. MITRE ATLAS Technique Catalog

From checklist §17 "MITRE ATLAS Mappings":

| Attack (Catalog ID) | MITRE Technique | Framework |
|---|---|---|
| 1 (Recon) | AML.T0014 — Search Victim-Owned Websites | ATLAS |
| 2 | AML.T0051.000 — LLM Prompt Injection: Direct | ATLAS |
| 3 | AML.T0051.000 — LLM Prompt Injection: Direct | ATLAS |
| 4 | AML.T0051.001 — LLM Prompt Injection: Indirect | ATLAS |
| 5 | AML.T0051.001 — LLM Prompt Injection: Indirect | ATLAS |
| 6 | AML.T0051.001 — LLM Prompt Injection: Indirect | ATLAS |
| 7 | AML.T0020 — Poison Training Data | ATLAS |
| 8 | AML.T0037 — Model Family Discovery (extended) | ATLAS |
| 9 | AML.T0014 — Recon: Search Victim-Owned Websites | ATLAS |
| 10 | AML.T0051.000 — LLM Prompt Injection: Direct | ATLAS |
| 11 | AML.T0048 — External Harms | ATLAS |
| 12 | AML.T0050 — Command and Scripting Interpreter | ATLAS |
| 13 | AML.T0010.001 — AI Supply Chain: AI Software | ATLAS |
| 14 | AML.T0010.001 + T1557 — AitM | ATLAS + ATT&CK |
| 15 | AML.T0020 + AML.T0051.001 | ATLAS |
| R12 | AML.T0020 — Poison Training Data | ATLAS |
| R13 | AML.T0020 — Poison Training Data | ATLAS |
| R14 | AML.T0051.001 — LLM Prompt Injection: Indirect | ATLAS |

---

## 11. GUI Screens & API Endpoints

### Screen 1: Engagement Dashboard (`/`)

**What it shows:** List of all engagements with name, mode, created date, target count, attack count. "New Engagement" button. Active engagement highlighted.

**API:**
- `GET /api/engagements` → JSON list
- `POST /api/engagements` → create new
- `POST /api/engagements/{id}/activate` → set as active

**HTMX:** Main content area swaps via `hx-get`. Alpine.js handles the "New Engagement" form modal.

---

### Screen 2: Engagement Brief (home screen) (`/engagement/{id}`)

**What it shows:** The Attack Intelligence Brief — the live-updating central artifact.

**Sections:**
1. **Header** — engagement name, mode badge, version indicator ("v1.3"), version history dropdown
2. **Target Summary** — hosts discovered, agents healthy, architecture confidence rating (with color: green/yellow/red)
3. **Crown Jewels** — table ranked by offensive value, access status badges (OBTAINED=green, ACCESSIBLE=yellow, BEHIND-N=red)
4. **Assumption Register** — filterable table: observation → hypothesis → confidence → status → source. Inline edit for status changes (triggers version bump).
5. **Trust Zones** — visual diagram area. Solid borders = validated, dashed = unvalidated. Components listed inside each zone. (Phase 7 polish: SVG rendering. Initial build: structured table representation.)
6. **Escalation Paths** — cards with status (HOLD/GO/BLOCKED), MITRE tags, detection risk, time constraints. Status toggleable.
7. **Decision Log** — reverse-chronological list, filterable by type. Auto-entries (from attacks) marked with a system badge.
8. **Export buttons** — Markdown / HTML / PDF / JSON

**API:**
- `GET /api/engagements/{id}/brief` → full brief JSON
- `GET /api/engagements/{id}/brief/html` → rendered HTML fragment (HTMX)
- `PATCH /api/engagements/{id}/assumptions/{aid}` → update assumption status
- `POST /api/engagements/{id}/assumptions` → add assumption
- `PATCH /api/engagements/{id}/escalation-paths/{pid}` → update status
- `POST /api/engagements/{id}/crown-jewels` → add crown jewel
- `POST /api/engagements/{id}/decision-log` → manual entry
- `GET /api/engagements/{id}/brief/versions` → version list
- `GET /api/engagements/{id}/brief/versions/{v}` → snapshot
- `GET /api/engagements/{id}/brief/export?format=markdown` → export

---

### Screen 3: Recon Console (`/engagement/{id}/recon`)

**What it shows:** Phase-by-phase recon runner with live output streaming.

**Layout:**
- Left sidebar: phase list (1. Network Scan → 2. Agent Discovery → 3. Surface Mapping → 4. Fingerprinting → 5. RAG Detection → 6. Embed Recon). Status indicator per phase (pending/running/complete).
- Main area: live terminal-style output (SSE-driven, monospace, ANSI-colored via a JS ANSI renderer). Phase parameter form at top. "Run Phase" button.
- Right sidebar: discovered targets table (auto-populates from Phase 1-2 results).

**API:**
- `GET /api/engagements/{id}/recon/phases` → phase status list
- `POST /api/engagements/{id}/recon/phases/{n}/run` → kick off phase (returns SSE stream)
- `GET /api/engagements/{id}/recon/stream` → SSE endpoint for live output
- `GET /api/engagements/{id}/targets` → discovered targets

---

### Screen 4: Attack Workbench (`/engagement/{id}/attacks`)

**What it shows:** Attack catalog + execution interface.

**Layout:**
- Left sidebar: attacks grouped by NVIDIA Kill Chain phase:
  - RECON: 1
  - HIJACK: 2, 3, 10*, 14*
  - POISON: 4, 5, 6, R12, R13, R14, 13*, 15*
  - PERSIST: 7, 8
  - IMPACT: 11*, 12*
  - FULL CHAIN: 8G
  (* = placeholder, greyed out with "not implemented" badge)
- Main area: when attack selected:
  1. **Info header** — name, OSAI chapter, MITRE technique, kill chain phase
  2. **Detection warning panel** — if detection-aware mode: "This attack triggers [rule names]. Available evasions: [list with checkboxes]." In grey_box/black_box mode, this BLOCKS the send button until user explicitly acknowledges.
  3. **Parameter form** — generated from `get_parameters()`. Includes target agent selector.
  4. **Curl preview pane** — live-updates as parameters change
  5. **"Send" button** — executes via API
  6. **Result panel** — response display, success/fail indicator
- Bottom: attack history table for this engagement

**API:**
- `GET /api/attacks/catalog` → full catalog with implementation status
- `GET /api/attacks/{catalog_id}/parameters` → parameter schema
- `GET /api/attacks/{catalog_id}/detection-info` → triggered rules + evasion options
- `POST /api/engagements/{id}/attacks/{catalog_id}/execute` → run attack (returns result)
- `GET /api/engagements/{id}/attacks/history` → attack result history

---

### Screen 5: RAG Pipeline View (`/engagement/{id}/rag`)

**What it shows:** Specialized view for embedding work.

**Layout (3-column):**
- **Left panel — Vector DB Detection:** DB type, host:port, auth status, collections list. "Detect" button triggers auto-detection.
- **Middle panel — Export + Fingerprint:**
  - Export status (embeddings.npy shape, file size)
  - Dimension-based model candidates table
  - Config grep results (if config-paths provided)
  - Inference probing results (from course script) — model candidates with confidence ratings, similarity scores
- **Right panel — Chunk Triage:**
  - Fused score table from chunk_triage_pipe.py
  - Score-gap cutoff visualization (bar chart showing isolation scores with gap marker)
  - "Extract chunk N" button for each row → saves to engagement artifacts/

**Pipeline flow** (shown as a horizontal stepper at top):
`Detect VDB → Export → Fingerprint → Triage → Extract Chunk → Generate Templates → Invert → Done`

**API:**
- `POST /api/engagements/{id}/rag/detect` → run VDB detection
- `POST /api/engagements/{id}/rag/export` → export embeddings (SSE for progress)
- `POST /api/engagements/{id}/rag/fingerprint` → run fingerprint (dimension + config grep)
- `POST /api/engagements/{id}/rag/inference-probe` → run inference_probing.py wrapper
- `POST /api/engagements/{id}/rag/triage` → run chunk_triage_pipe.py wrapper
- `POST /api/engagements/{id}/rag/extract-chunk` → extract single chunk
- `POST /api/engagements/{id}/rag/generate-templates` → run generate_templates.py wrapper
- `POST /api/engagements/{id}/rag/invert` → run emb_fin or zero2text inversion
- `POST /api/engagements/{id}/rag/ground-truth` → upload ground truth document
- `GET /api/engagements/{id}/rag/ground-truth/{chunk}` → get ground truth for chunk
- `GET /api/engagements/{id}/rag/inversion-results` → all inversion results
- `GET /api/engagements/{id}/rag/status` → current pipeline state

---

### Screen 6: Report Builder (`/engagement/{id}/report`)

**What it shows:** Drag-drop report composition from attack results.

**Layout:**
- Left: available findings (from attack_results, grouped by category)
- Center: report sections (Executive Summary, Findings, Evidence, Remediation). Each section is a drop target.
- Right: finding detail editor (severity, MITRE technique, evidence curl + response, remediation text)
- Bottom: export buttons (HTML / Markdown / PDF)

Each finding auto-populates:
- Severity (editable)
- MITRE ATLAS technique (from attack catalog)
- Evidence (curl command + truncated response from attack_results)
- Remediation (suggested based on attack type — editable)

**API:**
- `GET /api/engagements/{id}/report` → report structure
- `PUT /api/engagements/{id}/report` → save report structure
- `POST /api/engagements/{id}/report/findings` → add finding from attack result
- `GET /api/engagements/{id}/report/export?format=html` → rendered export
- `GET /api/engagements/{id}/report/mcp-report` → 24hr MCP invocation report (grey_box only)

---

### Global UI Elements

- **Top nav:** AISuite logo | Active engagement name + mode badge | Engagement switcher dropdown
- **Sidebar nav:** Brief | Recon | Attacks | RAG Pipeline | Report
- **Status bar:** Connection status (localhost:8888), active engagement, brief version

---

## 12. Engagement Modes

### Mode Comparison Matrix

| Feature | `lab` | `grey_box` | `black_box` |
|---|---|---|---|
| All attacks enabled | Yes | Yes | Yes (after recon unlock) |
| Detection warnings shown | Yes (info only) | Yes (BLOCKING) | Yes (BLOCKING) |
| RoE enforcement | None | Active | Active |
| Time window checks | None | Active | Active |
| MCP 24hr reporter | Off | Active | Active |
| Pre-loaded targets | Allowed | Allowed | Disallowed |
| Default --stealth | Off | Off | Always on |
| Default --rate | 0 (no delay) | 0 | 10 (seconds) |
| Recon-before-attack gate | No | No | Yes — must complete recon phases 1-2 before attack catalog unlocks |
| Production write warnings | No | Yes (on DB poison, file upload) | Yes |

### Recon Gate (black_box only)

In `black_box` mode, the Attack Workbench sidebar shows all attacks but they're disabled until:
1. Phase 1 (Network Scan) completes — unlocks attacks that don't need agent info
2. Phase 2 (Agent Discovery) completes — unlocks agent-targeted attacks
3. Per-agent: Surface Mapping for that agent reveals the required capability → unlocks the specific attack

This prevents the user from skipping recon and running blind attacks, which is realistic for a true black-box engagement.

---

## 13. Course Script Integration

### chunk_triage_pipe.py

**Location:** `./chunk_triage_pipe.py` (extracted from terminal paste, kept at project root alongside other scripts)

**Integration:** `aisuite/recon/embed_recon.py` imports it:

```python
def run_chunk_triage(
    embeddings_path: str, *,
    stages: str = "density,pw,recon",
    model: str = "sentence-transformers/all-MiniLM-L6-v2",
    company: str | None = None,
    top: int = 10,
    output_path: str | None = None,
) -> dict:
    """Wrapper that calls chunk_triage_pipe.main() programmatically."""
    # Build sys.argv equivalent and call main()
    # OR: refactor to call stage_density/stage_pw/stage_reconstruction directly
    # Second option preferred — avoids sys.argv manipulation
```

**Decision point:** The cleanest integration is to import the stage functions directly (`stage_density`, `stage_pw`, `stage_reconstruction`, `fuse_rankings`) rather than simulating CLI invocation. This doesn't modify the course script — we import its public functions. **Confirm this approach is acceptable.**

### inference_probing.py

**Location:** `./inference_probing.py` (extracted from terminal paste)

**Integration:** Same pattern — import `run_probing`, `score_candidate`, `extract_segments` directly.

The `--save-pairs` output (ALGEN alignment data) is saved to the engagement's `artifacts/` directory.

### Dependencies

Both scripts require `sentence_transformers` (pulls in PyTorch ~2GB). This goes in the `[embedding]` extras group:

```toml
[project.optional-dependencies]
embedding = ["sentence-transformers>=2.2.0"]
```

The GUI shows a clear error if the user clicks "Run Inference Probing" without `sentence_transformers` installed, with the install command.

---

## 14. Embedding Inversion Integration

**Scope change (2026-05-09):** Modules 6.3 inversion methods are in scope. Module 6.4 (ALGEN, Vec2Text — GPU training time) remains out.

### Scripts (DO NOT MODIFY)

| Script | Lines | What it does | Key classes | Entry point |
|---|---|---|---|---|
| `emb_fin.py` | 1582 | Template bank scoring + margin-aware slot filling (OSAI 6.3.1) | `EmbeddingEngine`, `SlotPipeline`, `PipelineConfig` | `SlotPipeline(config).attack_chunks(embeddings, chunk_indices)` |
| `zero2text_impl.py` | 2418 | Zero2Text algorithm (arXiv 2602.01757v2) + entropy detection + slot filling (OSAI 6.3.2) | `EmbeddingEngine`, `Zero2TextPipeline`, `Zero2TextConfig` | `Zero2TextPipeline(config).attack_chunks(embeddings, chunk_indices)` |
| `generate_templates.py` | 2641 | Template generator with auto-domain detection from embeddings (OSAI 6.3.1 prep) | `AdvancedTemplateGenerator`, `GeneratorConfig` | `generator.generate(count)` |

All three use `transformers` (AutoModel, AutoTokenizer) + `torch` + `numpy`. Added to existing `[embedding]` extras group.

### Wrapper Design

Located in `aisuite/recon/embed_recon.py`, extending the existing module:

```python
def run_template_generation(
    embeddings_path: str, *,
    chunk_index: int = 0,
    domain: str | None = None,       # auto-detect if None
    count: int = 100000,
    output_path: str | None = None,
) -> dict:
    """Wraps generate_templates.py — produces templates.json for inversion."""
    # Import AdvancedTemplateGenerator, GeneratorConfig, detect_domain
    # from generate_templates (project root, on PYTHONPATH via pip install -e .)
    ...

def run_emb_fin(
    embeddings_path: str, *,
    chunk_indices: list[int],
    templates_path: str | None = None,  # from run_template_generation
    wordlist_path: str | None = None,
    slots: list[str] | None = None,     # e.g. ["PASSWORD", "URL"]
    slot_defaults: dict[str, str] | None = None,  # e.g. {"URL": "https://login.megacorpone.ai"}
    model: str = "sentence-transformers/all-MiniLM-L6-v2",
    device: str = "auto",
    output_path: str | None = None,
) -> list[dict]:
    """Wraps emb_fin.py — template+slot inversion pipeline."""
    # Import PipelineConfig, SlotPipeline from emb_fin
    # Build config, run pipeline.attack_chunks(), return results
    ...

def run_zero2text(
    embeddings_path: str, *,
    chunk_indices: list[int],
    templates_path: str | None = None,
    wordlist_path: str | None = None,
    slots: list[str] | None = None,
    slot_defaults: dict[str, str] | None = None,
    model: str = "sentence-transformers/all-MiniLM-L6-v2",
    device: str = "auto",
    max_tokens: int = 32,
    lm_model: str = "gpt2",
    output_path: str | None = None,
) -> list[dict]:
    """Wraps zero2text_impl.py — Zero2Text inversion pipeline."""
    # Import Zero2TextConfig, Zero2TextPipeline from zero2text_impl
    # Build config, run pipeline.attack_chunks(), return results
    ...
```

**Import strategy:** Direct import of classes/functions (same as chunk_triage_pipe.py). Scripts live at project root, available via `pip install -e .` PYTHONPATH. No subprocess, no sys.argv manipulation.

### Ground-Truth Comparison

The ground-truth document (`MC1_password_reset.pdf`) contains:

> *"Please navigate to https://login.megacorpone.ai and click on 'Need help signing in'. The default password after resetting is N0=Acc3ss which must be changed immediately upon first login."*

**Schema addition** — `ground_truth` table:

```sql
CREATE TABLE ground_truth (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER REFERENCES engagements(id),
    chunk_index     INTEGER NOT NULL,
    source_file     TEXT,               -- "MC1_password_reset.pdf"
    original_text   TEXT NOT NULL,
    uploaded_at     TEXT NOT NULL
);
```

**GUI display:** The inversion result view shows a side-by-side diff:

```
┌─ RECOVERED TEXT (emb_fin) ──────────────────────┐  ┌─ GROUND TRUTH ────────────────────────────────┐
│ Please navigate to {URL} and click on Need help  │  │ Please navigate to https://login.megacorpone.  │
│ signing in. The default password after resetting │  │ ai and click on "Need help signing in". The    │
│ is {PASSWORD} which must be changed immediately  │  │ default password after resetting is N0=Acc3ss   │
│ upon first login.                                │  │ which must be changed immediately upon first    │
│                                                  │  │ login.                                         │
│ Slots recovered:                                 │  │                                                │
│   PASSWORD: N0=Acc3ss  [confidence: HIGH]        │  │ Verified: PASSWORD = N0=Acc3ss                  │
│   URL: https://login.megacorpone.ai [HIGH]       │  │ Verified: URL = https://login.megacorpone.ai   │
└──────────────────────────────────────────────────┘  └────────────────────────────────────────────────┘
```

Ground truth is optional — when not available, the right panel is hidden and only recovered text + confidence scores are shown. Ground truth files are uploaded via the GUI and stored in `artifacts/ground_truth/`.

### Extended RAG Pipeline View

The pipeline stepper becomes:

```
Detect VDB → Export → Fingerprint → Triage → Extract Chunk → Generate Templates → Invert → Done
```

The RAG Pipeline view (Screen 5) gains a fourth panel below the existing three columns:

**Bottom panel — Inversion Results:**
- **Method selector:** `emb_fin (template+slot)` / `zero2text (generative)` toggle
- **Parameters form:** chunk index, wordlist path, slots, slot defaults, model, device
- **"Generate Templates" button** → runs `generate_templates.py` → shows domain detection + template count
- **"Run Inversion" button** → runs selected method → shows:
  - Best recovered text with slot values highlighted
  - Confidence per slot (HIGH/MEDIUM/LOW with color)
  - Similarity score to target embedding
  - Template used (for emb_fin) or token sequence (for zero2text)
- **Ground truth toggle** → if ground truth uploaded for this chunk, shows side-by-side diff panel
- **"Upload Ground Truth" button** → file picker for PDF/TXT, extracts text, stores in DB

**API additions:**
- `POST /api/engagements/{id}/rag/generate-templates` → run template generation
- `POST /api/engagements/{id}/rag/invert` → run inversion (emb_fin or zero2text)
- `POST /api/engagements/{id}/rag/ground-truth` → upload ground truth document
- `GET /api/engagements/{id}/rag/ground-truth/{chunk}` → get ground truth for chunk
- `GET /api/engagements/{id}/rag/inversion-results` → all inversion results

### Dependencies Update

```toml
[project.optional-dependencies]
embedding = [
    "sentence-transformers>=2.2.0",
    "transformers>=4.30.0",
    "torch>=2.0.0",
]
```

Note: `sentence-transformers` already pulls in `transformers` and `torch`, but listing them explicitly documents the direct dependency from the inversion scripts.

---

## 15. UI Design Language

The GUI should feel clean, modern, and professional — a tool built for operators, not a research prototype.

### Design Principles

1. **Dark theme by default** — operators work long hours, often in low-light environments. Dark backgrounds (#0f172a slate-900) with light text. Accent colors from Tailwind's slate/blue palette.
2. **Information density over whitespace** — this is a professional tool, not a marketing site. Tables should be compact. Panels should use available space. But not cramped — consistent 1rem/1.5rem spacing.
3. **Status at a glance** — color-coded badges everywhere: confidence levels (green HIGH, amber MEDIUM, red LOW), access status, phase completion, engagement mode.
4. **Monospace where it matters** — curl previews, terminal output, recovered text, and slot values use a monospace font (JetBrains Mono via CDN or system mono stack). Prose content uses Inter or system sans.
5. **Minimal chrome** — no gradients, no shadows deeper than `shadow-sm`, no rounded corners larger than `rounded-md`. Borders use subtle slate-700/slate-800 tones.
6. **Cards for grouping** — each logical section (assumption register, escalation path, crown jewel) lives in a card with a subtle border and a header bar. Cards use `bg-slate-800/50` on the dark theme.
7. **Interactive feedback** — HTMX swaps should show a brief loading indicator (not a full-page spinner). Alpine.js transitions for panel open/close. Toast notifications for success/error on API calls.

### Color System (Tailwind classes)

| Purpose | Light | Dark |
|---|---|---|
| Background | `bg-white` | `bg-slate-900` |
| Surface (cards) | `bg-gray-50` | `bg-slate-800/50` |
| Surface elevated | `bg-white` | `bg-slate-800` |
| Primary text | `text-gray-900` | `text-slate-100` |
| Secondary text | `text-gray-500` | `text-slate-400` |
| Borders | `border-gray-200` | `border-slate-700` |
| Accent (links, active) | `text-blue-600` | `text-blue-400` |
| Success | `text-emerald-600` | `text-emerald-400` |
| Warning | `text-amber-500` | `text-amber-400` |
| Danger | `text-red-600` | `text-red-400` |

### Component Patterns

**Navigation sidebar:** Fixed left, 14rem wide, slate-950 background, active item has a blue-500 left border + bg-slate-800. Icons optional (Heroicons via CDN if needed, or text-only).

**Data tables:** Compact rows (py-2 px-3), alternating row shading (`even:bg-slate-800/30`), sticky headers, sortable columns where relevant.

**Terminal output (recon console):** Black background (`bg-black`), green-on-black monospace text (a la traditional terminal). ANSI colors rendered via ansi_up.js. Scrollable with auto-scroll-to-bottom on new output.

**Forms:** Inputs use `bg-slate-700 border-slate-600 text-slate-100` on dark theme. Focus ring `ring-blue-500`. Labels above inputs, not inline.

**Buttons:** Primary = `bg-blue-600 hover:bg-blue-500 text-white`. Danger = `bg-red-600`. Ghost = `border border-slate-600 hover:bg-slate-700`. All with `rounded-md px-4 py-2 text-sm font-medium`.

**Badges:** Small rounded pills for status indicators. `bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/20` pattern for colored badges.

**Toast notifications:** Top-right corner, auto-dismiss after 4s, slide-in animation via Alpine.js `x-transition`.

### Typography

```html
<!-- System font stack — no external font dependency -->
<style>
  :root {
    --font-sans: ui-sans-serif, system-ui, -apple-system, sans-serif;
    --font-mono: ui-monospace, 'JetBrains Mono', 'Fira Code', monospace;
  }
</style>
```

Text sizes: `text-sm` (13px) for table cells and secondary content, `text-base` (16px) for body, `text-lg` for section headers, `text-xl` for page titles. Nothing larger.

---

## 16. Signature Normalization Log

Functions being extracted to `core/` with the following normalizations. **Review each — confirm or override.**

| Function | Change | Rationale |
|---|---|---|
| `_post` → `core.http.post` | Default timeout 15s (ai_sploit value). Dropped leading underscore — it's a public API in the new package. | 15s is more common across the codebase (2 of 3 files). ai_suite's 10s was too aggressive for RAG targets. |
| `send_chat` | Default timeout → 30s. Added explicit `endpoint` kwarg. | rag_attacks.py's 30s is safer — RAG retrieval adds latency. All callers already pass endpoint or use default "/chat". |
| `preview_and_confirm` | Return type annotation fixed to `-> str`. | ai_sploit.py had `-> bool` but returned strings and callers compared to `"n"`. This was a bug. |
| `banner` | Color standardized to RED frame. | ai_suite.py used CYAN for recon banners. In v2.0, the phase badge provides the visual distinction. |
| `upload_file` | Promoted from rag_attacks.py to `core.http`. | Was only in rag_attacks but is generally useful for any file upload attack. |
| `smart_chat` | Moved to `core.http`. Rate delay parameterized instead of reading global state. | ai_suite.py's version read from `state["rate"]` — global state access doesn't work in a package. |

**Signature NOT changed (identical across all files):**
info, success, warn, error, found, divider, ask, choose

---

## 17. Package Layout & pyproject.toml

### Directory Structure

```
AISuite/
├── pyproject.toml
├── README.md
├── LICENSE
├── .gitignore
├── design.md                    # this document
├── checklist.md                 # exam prep checklist (reference)
├── OSAI Course Material.md      # course material (reference)
│
├── ai_sploit.py                 # 3-line shim → aisuite.ui.cli:sploit
├── ai_suite.py                  # 3-line shim → aisuite.ui.cli:suite
├── ai_enum.py                   # 3-line shim → aisuite.ui.cli:enum
├── session_enum.py              # 3-line shim → aisuite.ui.cli:session_enum
├── embed_recon.py               # 3-line shim → aisuite.ui.cli:embed_recon
│
├── chunk_triage_pipe.py         # course-provided (DO NOT MODIFY)
├── inference_probing.py         # course-provided (DO NOT MODIFY)
├── emb_fin.py                   # inversion: template+slot (DO NOT MODIFY)
├── zero2text_impl.py            # inversion: Zero2Text (DO NOT MODIFY)
├── generate_templates.py        # inversion: template generator (DO NOT MODIFY)
├── MC1_password_reset.pdf       # ground-truth reference data
│
├── aisuite/
│   ├── __init__.py
│   ├── __main__.py              # python -m aisuite
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── logger.py
│   │   ├── http.py
│   │   ├── curl.py
│   │   ├── input.py
│   │   ├── agents.py
│   │   ├── results.py
│   │   ├── storage.py
│   │   ├── stealth.py
│   │   └── detection_db.py
│   │
│   ├── engine/
│   │   ├── __init__.py
│   │   ├── engagement.py
│   │   ├── brief.py
│   │   ├── assumption.py
│   │   ├── trust_zone.py
│   │   ├── escalation.py
│   │   ├── crown_jewel.py
│   │   ├── mitre.py
│   │   ├── roe.py
│   │   ├── decision_log.py
│   │   ├── attack_base.py
│   │   └── recon_base.py
│   │
│   ├── recon/
│   │   ├── __init__.py
│   │   ├── network_scan.py
│   │   ├── surface_map.py
│   │   ├── fingerprint.py
│   │   ├── rag_detect.py
│   │   └── embed_recon.py
│   │
│   ├── attacks/
│   │   ├── __init__.py
│   │   ├── guided.py
│   │   ├── chat/
│   │   │   ├── __init__.py
│   │   │   ├── prompt_extraction.py
│   │   │   └── goal_hijacking.py
│   │   ├── poison/
│   │   │   ├── __init__.py
│   │   │   ├── doc_fragmentation.py
│   │   │   ├── css_injection.py
│   │   │   ├── code_import.py
│   │   │   ├── ingestion.py
│   │   │   ├── collision.py
│   │   │   └── hijacking.py
│   │   ├── persist/
│   │   │   ├── __init__.py
│   │   │   ├── db_poisoning.py
│   │   │   └── session_enum.py
│   │   └── a2a/
│   │       └── __init__.py      # TODO placeholder
│   │
│   ├── reports/
│   │   ├── __init__.py
│   │   ├── html.py
│   │   ├── markdown.py
│   │   ├── pdf.py
│   │   └── brief_render.py
│   │
│   ├── migrations/               # Alembic
│   │   ├── env.py
│   │   ├── script.py.mako
│   │   └── versions/
│   │
│   └── ui/
│       ├── __init__.py
│       ├── cli.py
│       ├── web.py
│       ├── api.py
│       └── static/
│           ├── index.html
│           ├── app.js
│           └── style.css
│
└── tests/
    └── ...
```

### pyproject.toml

```toml
[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "aisuite"
version = "2.0.0"
description = "AI Red Team Engagement Toolkit"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.11"
authors = [{name = "Jeffrey Simpson"}]

dependencies = [
    "requests>=2.31.0",
    "numpy>=1.24.0",
    "click>=8.1.0",
    "fastapi>=0.104.0",
    "uvicorn[standard]>=0.24.0",
    "sqlalchemy>=2.0.0",
    "alembic>=1.13.0",
    "sse-starlette>=1.6.0",
    "jinja2>=3.1.0",
]

[project.optional-dependencies]
embedding = [
    "sentence-transformers>=2.2.0",
    "transformers>=4.30.0",
    "torch>=2.0.0",
]
pdf = [
    "weasyprint>=60.0",
]
db = [
    "psycopg2-binary>=2.9.0",
]
full = [
    "aisuite[embedding,pdf,db]",
]

[project.scripts]
aisuite = "aisuite.ui.cli:main"

[tool.setuptools.packages.find]
include = ["aisuite*"]
```

### .gitignore additions

```
*.zip
*.pyc
__pycache__/
*.egg-info/
dist/
build/
.venv/
venv/
export/
*.npy
*.parquet
```

### Files to clean up before Phase 1

The following files are reference/lab artifacts and should NOT be tracked in git. They'll be moved to a `reference/` directory or deleted:

| File | Disposition |
|---|---|
| `HTB Notes.ipynb`, `Notes.ipynb` | Personal notes — move to reference/ or delete |
| `OSAI Course Material.ipynb` | 19MB notebook — keep .md only, gitignore .ipynb |
| `ai_suite (1).py` | Duplicate — delete |
| `animals.txt`, `desert.txt`, `mountain.txt`, `pizza.txt`, `vacation.txt` | Lab test payloads — move to reference/ |
| `collision_embedded.pdf` | Lab artifact — move to reference/ |
| `reset_password.txt` | Lab artifact — move to reference/ |
| `check_cell.py`, `format_notebook.py`, `merge_notes.py` | Utility scripts — move to reference/ |
| `data poison.py` | Lab snippet — move to reference/ |
| `from huggingface_hub import HfApi, hf_hu.py` | Snippet — delete |
| `embeddings.npy`, `embeddings2.npy` | Lab data — gitignored |
| `files (3).zip` | Download artifact — gitignored |

---

## 18. Build Phases

### Phase 1: Foundation (`[Foundation]` commits)

1. Extract `chunk_triage_pipe.py` and `inference_probing.py` from terminal paste
2. Create package structure (`aisuite/` directory tree)
3. Write `pyproject.toml` + `.gitignore`
4. Implement `core/` modules (logger, http, curl, input, agents, results, stealth)
5. Implement `core/storage.py` + SQLite schema + Alembic initial migration
6. Implement `core/detection_db.py` with full rule/evasion data
7. Implement `engine/` data models (engagement, brief, assumption, trust_zone, escalation, crown_jewel, mitre, roe, decision_log)
8. Implement `engine/attack_base.py` and `engine/recon_base.py`
9. Migrate existing scripts to import from `core/` — create shim scripts
10. Verify: `python3 ai_sploit.py -f agents.json` still works identically

### Phase 2: GUI Shell (`[GUI]` commits)

1. Implement `ui/web.py` (FastAPI app, Jinja2 templates, static serving)
2. Implement `ui/api.py` (engagement CRUD endpoints)
3. Build `static/index.html` — base layout with HTMX + AlpineJS + Tailwind CDN
4. Screen 1: Engagement Dashboard
5. Screen 2: Engagement Brief view (read-only first, then inline editing)
6. `aisuite serve` command wired up

### Phase 3: Recon Console (`[Recon]` commits)

1. Wrap recon phases into `recon/` modules
2. SSE streaming endpoint
3. Screen 3: Recon Console with live output
4. Auto-populate brief from recon findings

### Phase 4: Attack Workbench (`[Attacks]` commits — one commit per attack)

1. Wire up BaseAttack subclasses for each implemented attack
2. Screen 4: Attack Workbench shell (catalog sidebar, parameter form, curl preview)
3. Detection-aware pre-send warning panel
4. Migrate attacks one-by-one: 2, 3, 4, 5, 6, 7, 8, 8G, R12, R13, R14
5. Auto-log to decision log on each execution

### Phase 5: RAG Pipeline (`[RAG]` commits)

1. Wrap inference_probing.py + chunk_triage_pipe.py
2. Wrap emb_fin.py + zero2text_impl.py + generate_templates.py (inversion wrappers)
3. Screen 5: RAG Pipeline view (detect → export → fingerprint → triage → extract → invert)
4. Score-gap visualization
5. Extract chunk → engagement artifacts
6. Inversion result display with slot confidence
7. Ground-truth upload + side-by-side diff panel

### Phase 6: Reports (`[Reports]` commits)

1. Screen 6: Report Builder
2. HTML + Markdown export
3. PDF export (weasyprint)
4. Brief export (all formats)
5. MCP invocation reporter (grey_box mode)

---

## 19. Open Questions

Items I flagged for your review before building:

1. **RAG attack catalog IDs:** I used `R12`, `R13`, `R14` since checklist sections 12-15 are A2A attacks. Alternatives: use OSAI chapter numbers (`5.2.2`, `5.2.3`, `5.2.4`) or a flat namespace (`RAG-1`, `RAG-2`, `RAG-3`). Which do you prefer?

2. **Course script integration approach:** Import stage functions directly from `chunk_triage_pipe.py` (e.g., `from chunk_triage_pipe import stage_density, stage_pw`) rather than simulating CLI invocation via subprocess. This is cleaner but means the import path needs to be on PYTHONPATH. Since the scripts sit at the project root and we `pip install -e .`, this works. Confirm?

3. **Trust zone visualization:** Phase 7 says "SVG rendering" for trust zones. For the initial build, I'll use a structured table representation (zone name, components, boundary status). Actual visual diagramming is a polish item. Is that acceptable for the first pass, or is visual diagramming a hard requirement for the brief?

4. **ANSI rendering in browser:** The recon SSE stream will contain ANSI color codes from the existing scripts. I'll use a lightweight JS ANSI-to-HTML converter (ansi_up.js, ~8KB, MIT license). This is technically a new dependency but it's a single JS file served from static/, not an npm package. Acceptable?

5. **Alembic auto-migration on startup:** When `aisuite serve` or any CLI command opens an engagement DB, it should auto-run Alembic migrations to bring the schema up to date. This is standard for SQLite (no multi-user concerns). Confirm?

---

**End of design document. Awaiting approval before writing any package code.**
