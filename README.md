# AISuite — AI Security Toolkit

A modular toolkit for red teaming AI agent infrastructure.
Built during OffSec OSAI (AI-300) course work.

Structured around the **NVIDIA AI Kill Chain**: Recon → Poison → Hijack → Persist → Impact

---

## Toolkit Structure

```
AISuite/
├── ai_enum.py      # Phase 1-2: Quick agent discovery (health check only)
├── ai_suite.py     # Phase 1-5: Full interactive recon suite
└── ai_sploit.py    # Phase 6+: Targeted exploitation suite
```

---

## Quick Start

```bash
# Install dependencies
pip install requests psycopg2-binary --break-system-packages

# Step 1 — Recon (full suite)
python3 ai_suite.py -t 192.168.1.21-30 -o agents.json

# Step 1 — Quick health check only
python3 ai_enum.py -f nmap_results.txt -o agents.json

# Step 2 — Exploit
python3 ai_sploit.py -f agents.json -o results.json
```

---

## ai_enum.py — Agent Discovery

Parses nmap grepable output, hits `/health` on all Uvicorn services concurrently.

```bash
# Requires nmap grepable output (-oG)
nmap -sV --open -p 1-10000 192.168.1.21-30 -oG nmap_results.txt
python3 ai_enum.py -f nmap_results.txt -o agents.json
```

---

## ai_suite.py — Full Recon Suite

Interactive 5-phase reconnaissance tool.

```bash
# From existing nmap file
python3 ai_suite.py -f nmap_results.txt -o results.json

# Run nmap automatically (range)
python3 ai_suite.py -t 192.168.1.21-30 -o results.json

# Run nmap automatically (comma separated)
python3 ai_suite.py -t 192.168.1.21,192.168.1.22 -o results.json
```

### Phases

| Phase | What it does |
|-------|-------------|
| 1 — Network Scan | Parses nmap file or runs nmap against target range |
| 2 — Agent Discovery | Hits `/health` on every Uvicorn port concurrently |
| 3 — Surface Mapping | Purpose, tools, `/openapi.json` endpoints per agent |
| 4 — Fingerprinting | Identity probe + contradiction test + metadata leak |
| 5 — RAG Detection | 7-signal knowledge base detection |
| 6 — Report | Curl commands + findings + next steps per agent |

### Menu at each phase
```
[n] Next phase
[r] Repeat this phase
[s] Skip this phase
[q] Quit and show report
```

---

## ai_sploit.py — Exploitation Suite

Targeted attack tool. Takes `agents.json` from ai_suite.py as input.

```bash
python3 ai_sploit.py -f agents.json -o results.json
```

### Attack Menu

| # | Attack | Phase | Target |
|---|--------|-------|--------|
| 1 | Direct Prompt Injection | HIJACK | Agents with file/config tools |
| 2 | Goal Hijacking | HIJACK | Knowledge base agents |
| 3 | Document Fragmentation | POISON | Agents with /upload + /summarize |
| 4 | CSS Web Injection | POISON | Agents with /browse (web fetch) |
| 5 | Code Import Resolution | POISON | Code review agents with filesystem access |
| 6 | Database Poisoning | PERSIST | Wiki/KB agents backed by PostgreSQL |
| 7 | Session Enumeration | PERSIST | Notes agents with predictable session IDs |
| 8 | Guided Engagement | FULL CHAIN | Flexible multi-step attack chain |

### Features
- Select target agent from discovered inventory
- Choose prebuilt payload OR enter custom
- **Preview full curl command before sending**
- `[y]` Send / `[e]` Edit / `[n]` Cancel
- JSON output with all results

---

## RAG Detection Signals (ai_suite.py Phase 5)

Detects RAG activity via 7 independent signals:

- Structured `sources` array in response
- `retrieval_time_ms` / `retrieval_info` fields
- Chunk IDs in response body
- Vector/BM25 scores
- PDF filename citations in text
- "According to X" citation patterns
- Document title patterns

---

## Requirements

```bash
pip install requests psycopg2-binary --break-system-packages
```

- Python 3.10+
- nmap (for network scanning)
- awscli or boto3 (for MinIO/S3 credential verification)

---

## Workflow

```
nmap scan
    ↓
ai_suite.py (recon)     →  agents.json
    ↓
ai_sploit.py (exploit)  →  results.json
```

---

## Legal

For authorized penetration testing and security research only.
Use responsibly and only against systems you have permission to test.

---

*Built during OffSec AI-300 — OSAI course*
