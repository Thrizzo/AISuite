# AISuite — AI Security Toolkit

A modular toolkit for red teaming AI agent infrastructure.
Built during OffSec OSAI (AI-300) course work.

Structured around the **NVIDIA AI Kill Chain**: `Recon → Poison → Hijack → Persist → Impact`

---

## Toolkit Structure

```
AISuite/
├── ai_enum.py        — Quick agent discovery (health check only)
├── ai_suite.py       — Full interactive 5-phase recon suite + HTML report
├── ai_sploit.py      — 8-attack exploitation suite
├── session_enum.py   — Standalone session ID brute force
├── toolkit.html      — Browser-based GUI (no server needed)
└── README.md
```

---

## Quick Start

```bash
# Install dependencies
pip install requests psycopg2-binary --break-system-packages

# Step 1 — Full recon (recommended)
python3 ai_suite.py -t 192.168.1.21-30 -o agents.json

# Step 1 — Quick health check only
python3 ai_enum.py -f nmap_results.txt -o agents.json

# Step 2 — Exploit
python3 ai_sploit.py -f agents.json -o results.json

# Step 2 — Session enumeration (standalone)
python3 session_enum.py --target http://192.168.1.24:8018/chat --prefix MC --days 14

# Toolkit GUI — open in any browser
open toolkit.html
```

---

## ai_enum.py — Quick Agent Discovery

Parses nmap grepable output, hits `/health` on all Uvicorn services concurrently.
Use this for a fast first pass when you just need to know what agents are alive.

```bash
# Requires nmap grepable output (-oG)
nmap -sV --open -p 1-10000 192.168.1.21-30 -oG nmap_results.txt
python3 ai_enum.py -f nmap_results.txt -o agents.json

# With custom thread count and timeout
python3 ai_enum.py -f nmap_results.txt -o agents.json --threads 20 --timeout 10
```

**Output:** Agent name, host, port, health status — grouped by host.

---

## ai_suite.py — Full Recon Suite

Interactive 5-phase reconnaissance tool. Generates JSON report and an HTML report
you can open in a browser for a visual overview of all agents found.

```bash
# From existing nmap file
python3 ai_suite.py -f nmap_results.txt -o results.json

# Run nmap automatically (range)
python3 ai_suite.py -t 192.168.1.21-30 -o results.json

# Run nmap automatically (comma separated)
python3 ai_suite.py -t 192.168.1.21,192.168.1.22 -o results.json

# Stealth mode — low-risk fingerprinting only (won't trigger D03)
python3 ai_suite.py -t 192.168.1.21-30 -o results.json --stealth

# Rate limited — N seconds between every request (prevents D02)
python3 ai_suite.py -t 192.168.1.21-30 -o results.json --rate 10

# Full stealth engagement (recommended)
python3 ai_suite.py -t 192.168.1.21-30 -o results.json --stealth --rate 10
```

### Flags

| Flag | What it does |
|------|-------------|
| `-t` | Target range or comma-separated IPs — runs nmap automatically |
| `-f` | Existing nmap grepable output file |
| `-o` | Output JSON file (HTML report generated alongside it) |
| `--stealth` | Phase 4 uses 3 low-risk techniques instead of direct identity probes |
| `--rate N` | N seconds between every `smart_chat()` request |

### Phases

| Phase | What it does |
|-------|-------------|
| 1 — Network Scan | Parses nmap file or runs nmap against target range |
| 2 — Agent Discovery | Hits `/health` on every Uvicorn port concurrently |
| 3 — Surface Mapping | Purpose, tools, endpoints via `/openapi.json` per agent |
| 4 — Fingerprinting | Normal: 4 identity probes. Stealth: metadata leak + contradiction + context window |
| 5 — RAG Detection | 7-signal knowledge base detection |
| 6 — Report | Curl commands, findings, attack suggestions per agent |

### Menu at each phase
```
[n] Next    [r] Repeat    [s] Skip    [q] Quit and report
```

### Stealth Fingerprinting (--stealth)

Normal mode sends direct identity probes which can trigger the D03 detection rule.
Stealth mode uses three low-risk techniques instead:

| Technique | How | Detection Risk |
|-----------|-----|---------------|
| Metadata leak | Single innocent message — checks JSON for model/provider fields | None |
| Contradiction test | False attribution ("Thanks Claude!") — model corrects itself | Low |
| Context window test | Injects ZEBRA-42 marker — tests recall after context fill | None |

Results are combined into a best-guess with confidence: `[2/3 signals]`.

### HTML Report

When `-o` is specified, a `.html` file is generated alongside the JSON.
Open it in any browser — shows agent inventory, model badges, dangerous tools,
interesting endpoints, RAG status, and suggested next steps per agent.

---

## ai_sploit.py — Exploitation Suite

Targeted attack tool. Takes `agents.json` from `ai_suite.py` as input.

```bash
python3 ai_sploit.py -f agents.json -o results.json
```

### Attack Menu

| # | Attack | Kill Chain | Target |
|---|--------|-----------|--------|
| 1 | Direct Prompt Injection | HIJACK | Agents with file/config tools |
| 2 | Goal Hijacking | HIJACK | Knowledge base agents with RAG |
| 3 | Document Fragmentation | POISON | Agents with `/upload` + `/summarize` |
| 4 | CSS Web Injection | POISON | Agents with `/browse` (web fetch) |
| 5 | Code Import Resolution | POISON | Code review agents with filesystem access |
| 6 | Database Poisoning | PERSIST | Wiki/KB agents backed by PostgreSQL |
| 7 | Session Enumeration | PERSIST | Notes agents with predictable session IDs |
| 8 | Guided Engagement | FULL CHAIN | Flexible multi-step attack chain |

### Features
- Select target agent from discovered inventory
- Choose prebuilt payload or enter custom
- **Full curl preview before every request** — `[y]` Send `[e]` Edit `[n]` Cancel
- Debug mode for troubleshooting
- Rerun last command without re-entering parameters
- JSON output with all results and timestamps

---

## session_enum.py — Session ID Brute Force

Standalone script for enumerating predictable session IDs against notes/memory agents.
Each request looks like normal `/chat` traffic — undetectable.

```bash
# Basic usage
python3 session_enum.py --target http://192.168.1.24:8018/chat

# Full options
python3 session_enum.py \
  --target http://192.168.1.24:8018/chat \
  --prefix MC \
  --date 20260325 \
  --days 14 \
  --max 20 \
  --output results.json
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | — | Chat endpoint URL (required) |
| `--prefix` | `MC` | Session ID prefix |
| `--date` | today | Start date YYYYMMDD |
| `--days` | 14 | Days back to scan |
| `--max` | 20 | Max counter per day |
| `--output` | — | Save results to JSON |

**Pattern:** `PREFIX-YYYYMMDD-NNNN` — e.g. `MC-20260325-0016`

Sessions containing credential keywords (`password`, `token`, `key`, `secret`, etc.)
are flagged as `[!] SENSITIVE` in the output.

---

## toolkit.html — Browser GUI

Single-file webapp. Open directly in any browser — no server, no dependencies.

**Features:**
- Drop `agents.json` to populate agent dropdown
- Select attack type — parameter fields change per attack
- Generate paste-ready curl commands with copy buttons
- Theory sections per attack phase (collapsible)
- Lab checklist with localStorage persistence
- Tools and links reference

```bash
# Just open it
open toolkit.html
# or double-click in your file manager
```

---

## RAG Detection Signals

Phase 5 detects RAG via 7 independent signals:

- Structured `sources` array in response JSON
- `retrieval_time_ms` / `retrieval_info` fields
- Chunk IDs in response body
- Vector / BM25 relevance scores
- PDF filename citations in text
- "According to [document]" citation patterns
- Document title patterns in response text

**RAG active** → crescendo goal hijacking target
**No RAG** → better direct injection target (no grounding to fight)

---

## Workflow

```
nmap scan
    ↓
ai_suite.py --stealth --rate 10    →  agents.json + agents.html
    ↓
Review HTML report — identify attack targets
    ↓
ai_sploit.py -f agents.json        →  results.json
    ↓
session_enum.py (if memory_search tools found)
```

---

## Detection Rules Reference

| Rule | Triggers On | Bypass |
|------|------------|--------|
| D02 — Sequential Enumeration | Rapid requests to AI paths | `--rate 10` |
| D03 — Identity Probing | Multiple identity questions same session | `--stealth` |
| AIM3: Prompt Injection Keywords | "ignore", "instead output" | Character spacing, framing |
| AIM3: Instruction Strings in Ingested Content | Injection phrases in uploaded files | Document fragmentation |
| AIM3: Imperative Commands in Stored Memory | "direct users to", "tell them to" | Descriptive phrasing |

---

## Requirements

```bash
pip install requests psycopg2-binary --break-system-packages

# For MinIO/S3 credential verification
pip install awscli --break-system-packages
# or
pip install boto3 --break-system-packages
```

- Python 3.10+
- nmap (for network scanning in `-t` mode)

---

## Legal

For authorized penetration testing and security research only.
Use responsibly and only against systems you have explicit permission to test.

---

*Built during OffSec AI-300 — OSAI | Jeffrey Simpson CISSP, CISM*
