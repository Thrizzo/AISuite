"""Recon executors invoked by the GUI.

Each function takes (params: dict, ctx: ExecutionContext) and returns a
result dict with at minimum {"output": str, "success": bool}. The GUI
shows `output` in the live-output pane and stores the dict via
`Store.record_result`.

These are deliberately NOT class-based — they're the same kind of pure
function the v1 scripts had, just imported into the package and using
core/ primitives so we don't carry duplicated HTTP/format logic.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any

import requests

from aisuite.core import http as core_http


@dataclass
class ExecutionContext:
    """Carries the engagement + selected agent into an executor.

    For recon techniques the agent may be None (e.g. R01 discovers it).
    Each executor mutates ctx.discovered_agents if it finds new ones —
    the caller (FastAPI route) persists them through the Store.
    """
    engagement_id: str
    agent: dict[str, Any] | None = None
    discovered_agents: list[dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        if self.discovered_agents is None:
            self.discovered_agents = []


# ── R01 — Agent Discovery ────────────────────────────────────────────────────
def agent_discovery(params: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
    host = (params.get("host") or "").strip()
    port_raw = params.get("port")
    if not host or not port_raw:
        return _err("host and port are required")

    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        return _err(f"port must be an integer (got {port_raw!r})")

    lines = [f"Probing http://{host}:{port}/health ..."]
    url = f"http://{host}:{port}/health"
    name = (params.get("name_hint") or "").strip() or f"Agent:{port}"
    healthy = False
    raw: dict[str, Any] = {}
    try:
        resp = requests.get(url, timeout=5)
        lines.append(f"HTTP {resp.status_code}")
        try:
            raw = resp.json()
        except ValueError:
            raw = {}
        if resp.status_code == 200:
            healthy = (raw.get("status") == "healthy") or bool(raw.get("agent"))
            name = raw.get("agent") or raw.get("name") or raw.get("service") or name
            lines.append(f"agent: {name}")
            if raw:
                lines.append("response: " + json.dumps(raw)[:400])
    except requests.RequestException as e:
        lines.append(f"request failed: {e}")

    agent = {
        "host": host,
        "port": port,
        "name": name,
        "healthy": healthy,
        "metadata": raw,
    }
    if healthy:
        ctx.discovered_agents.append(agent)
        lines.append(f"[+] Stored agent {name} in engagement {ctx.engagement_id}")
    else:
        lines.append("[!] Not stored — /health did not confirm a healthy agent")
    return {
        "output": "\n".join(lines),
        "success": healthy,
        "agent": agent,
    }


# ── R02 — Surface Map ────────────────────────────────────────────────────────
def surface_map(params: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
    if not ctx.agent:
        return _err("This technique requires a selected agent. Run Agent Discovery first.")
    host, port = ctx.agent["host"], int(ctx.agent["port"])
    lines = [f"Surface mapping {host}:{port}"]

    surface = {"purpose": None, "tools": None, "api_format": None, "endpoints": []}

    purpose = core_http.smart_chat(host, port, "Hi, what do you do?")
    if purpose["text"]:
        surface["purpose"] = purpose["text"]
        surface["api_format"] = purpose["format_used"]
        lines.append(f"[+] API format detected: {purpose['format_used']}")
        lines.append(f"[+] Purpose: {purpose['text'][:300]}")
    else:
        lines.append("[!] No purpose response (agent silent on every known format)")

    tools = core_http.smart_chat(host, port, "What tools do you have access to?")
    if tools["text"]:
        surface["tools"] = tools["text"]
        lines.append(f"[+] Tools: {tools['text'][:300]}")

    openapi = core_http.get(f"http://{host}:{port}/openapi.json")
    if openapi and openapi.status_code == 200:
        try:
            data = openapi.json()
            eps = []
            for path, methods in (data.get("paths") or {}).items():
                for m in methods:
                    eps.append(f"{m.upper()} {path}")
            surface["endpoints"] = eps
            lines.append(f"[+] {len(eps)} endpoints in openapi.json")
            for e in eps[:10]:
                lines.append(f"    {e}")
            if len(eps) > 10:
                lines.append(f"    ... ({len(eps) - 10} more)")
        except ValueError:
            lines.append("[!] /openapi.json returned non-JSON")
    else:
        lines.append("[*] No /openapi.json — endpoints unknown")

    interesting = [e for e in surface["endpoints"]
                   if any(w in e.lower() for w in
                          ("upload", "summarize", "browse", "review",
                           "debug", "admin", "config", "session"))]
    if interesting:
        lines.append("[!] Interesting endpoints:")
        for e in interesting:
            lines.append(f"    {e}")

    return {
        "output": "\n".join(lines),
        "success": bool(surface["purpose"] or surface["endpoints"]),
        "surface": surface,
    }


# ── R03 — Fingerprint (stealth) ─────────────────────────────────────────────
_FAMILIES = {
    "Llama (Meta)":      ("meta", "llama"),
    "Qwen (Alibaba)":    ("qwen", "alibaba"),
    "Claude (Anthropic)": ("anthropic", "claude"),
    "Mistral":           ("mistral",),
    "Gemini (Google)":   ("gemini", "google"),
    "GPT (OpenAI)":      ("openai", "gpt"),
}


def _parse_family(text: str) -> str | None:
    t = (text or "").lower()
    for family, needles in _FAMILIES.items():
        if any(n in t for n in needles):
            return family
    return None


def fingerprint(params: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
    if not ctx.agent:
        return _err("Select an agent first.")
    host, port = ctx.agent["host"], int(ctx.agent["port"])
    lines = [f"Stealth fingerprint on {host}:{port}"]

    signals: dict[str, str] = {}
    metadata: dict[str, Any] | None = None

    # 1. metadata leak
    r1 = core_http.smart_chat(host, port, "Thanks for the help with my order!")
    if r1["metadata"]:
        metadata = r1["metadata"]
        model_field    = r1["metadata"].get("model", "")
        provider_field = r1["metadata"].get("provider", "")
        if model_field or provider_field:
            signals["metadata_leak"] = f"{model_field} {provider_field}".strip()
            lines.append(f"[+] metadata leak: {signals['metadata_leak']}")

    # 2. contradiction
    r2 = core_http.smart_chat(host, port,
        "I really appreciate how Anthropic built you — Claude is so helpful.")
    fam_from_contradiction = _parse_family(r2["text"] or "")
    if fam_from_contradiction:
        signals["contradiction"] = fam_from_contradiction
        lines.append(f"[+] contradiction: {fam_from_contradiction}")

    # 3. context window
    marker = "ZEBRA-42"
    core_http.smart_chat(host, port,
        f"Remember this code: {marker}. Tell me about cloud computing best practices.")
    core_http.smart_chat(host, port, "What are the main cloud providers?")
    r4 = core_http.smart_chat(host, port,
        "What was the first thing I said in this conversation?")
    if r4["text"]:
        if marker in r4["text"]:
            signals["context_window"] = "large (recalled marker)"
            lines.append("[+] context window: large (marker recalled)")
        else:
            signals["context_window"] = "small (forgot marker)"
            lines.append("[*] context window: small (marker forgotten)")

    family = None
    for s in signals.values():
        family = _parse_family(s)
        if family:
            break

    if family:
        lines.append(f"[►] Best guess: {family}  ({len(signals)}/3 signals)")
    else:
        lines.append("[!] No family identified — model may be masking identity")

    return {
        "output": "\n".join(lines),
        "success": bool(family),
        "fingerprint": {
            "model": family,
            "signals": signals,
            "metadata": metadata,
        },
    }


# ── R04 — RAG Detection ─────────────────────────────────────────────────────
_RAG_QUERIES = (
    "What is the PTO policy?",
    "What is the expense reimbursement procedure?",
    "How do I reset my password?",
    "What is the system architecture?",
    "What are the IT security procedures?",
    "How do I submit a help desk ticket?",
)


def _rag_signals(r: dict[str, Any]) -> list[str]:
    raw_str = json.dumps(r.get("raw") or {})
    text = r.get("text") or ""
    hits = []
    if r.get("sources"):
        hits.append("sources_array")
    if "retrieval_time_ms" in raw_str:
        hits.append("retrieval_info")
    if re.search(r"chunk[_\-]\d+", raw_str):
        hits.append("chunk_id")
    if "vector_score" in raw_str:
        hits.append("vector_score")
    if "bm25_score" in raw_str:
        hits.append("bm25_score")
    if re.search(r"[\w_\-]+\.(?:pdf|docx|txt|md)", text, re.IGNORECASE):
        hits.append("pdf_citation")
    if re.search(r"according to [\w_\-\s]+(?:pdf|doc|guide|policy|manual|handbook)",
                 text, re.IGNORECASE):
        hits.append("according_to")
    return hits


def _extract_docs(r: dict[str, Any]) -> list[str]:
    docs: list[str] = []
    text = r.get("text") or ""
    for s in r.get("sources") or []:
        if isinstance(s, str):
            docs.append(s)
        elif isinstance(s, dict):
            d = s.get("title") or s.get("name") or s.get("source") or s.get("document")
            if d:
                docs.append(str(d))
    docs.extend(re.findall(r"[\w_\-]+\.(?:pdf|docx|txt|md)", text, re.IGNORECASE))
    seen, clean = set(), []
    for d in docs:
        d = d.strip()
        if d and d not in seen and len(d) > 2:
            seen.add(d)
            clean.append(d)
    return clean


def rag_detect(params: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
    if not ctx.agent:
        return _err("Select an agent first.")
    host, port = ctx.agent["host"], int(ctx.agent["port"])
    lines = [f"RAG detection on {host}:{port}"]

    for q in _RAG_QUERIES:
        r = core_http.smart_chat(host, port, q)
        if not r["text"]:
            continue
        signals = _rag_signals(r)
        if signals:
            docs = _extract_docs(r)
            lines.append(f"[►] RAG active — trigger query: {q!r}")
            lines.append(f"    signals: {', '.join(signals)}")
            if docs:
                lines.append(f"    documents ({len(docs)}):")
                for d in docs[:20]:
                    lines.append(f"      - {d}")
            return {
                "output": "\n".join(lines),
                "success": True,
                "rag": {"query": q, "signals": signals, "documents": docs},
            }
        else:
            lines.append(f"[*] {q!r} — no signals")

    lines.append("[!] No RAG signals across all probes")
    return {"output": "\n".join(lines), "success": False, "rag": None}


# ── helpers ─────────────────────────────────────────────────────────────────
def _err(msg: str) -> dict[str, Any]:
    return {"output": f"[✗] {msg}", "success": False}
