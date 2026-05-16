"""HTTP primitives.

Public functions (`post`, `get`) drop the underscore prefix the original
scripts used — they're the public API of this module. `send_chat` default
timeout is 30s, the safer value from rag_attacks.py (RAG systems do
retrieval before responding and the 15s ai_sploit default was tight).
`smart_chat` is preserved from ai_suite.py with multi-format probing; the
old `state["rate"]` global is replaced by an explicit `rate_delay` arg
so this module has no hidden coupling to CLI state.
"""
from __future__ import annotations

import time
from typing import Callable, Any

import requests

from aisuite.core import logger


def post(url: str, data: dict, timeout: int = 15) -> requests.Response | None:
    try:
        return requests.post(
            url,
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
    except Exception:
        return None


def get(url: str, timeout: int = 5) -> requests.Response | None:
    try:
        return requests.get(url, timeout=timeout)
    except Exception:
        return None


def send_chat(
    host: str,
    port: int,
    message: str,
    *,
    session_id: str | None = None,
    endpoint: str = "/chat",
    timeout: int = 30,
) -> dict | None:
    """Single-endpoint chat send. Use smart_chat to auto-discover the format."""
    payload: dict[str, Any] = {"message": message}
    if session_id:
        payload["session_id"] = session_id
    url = f"http://{host}:{port}{endpoint}"
    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        if resp.status_code == 200:
            try:
                return resp.json()
            except Exception:
                return {"response": resp.text}
    except Exception as e:
        logger.error(f"Request error: {e}")
    return None


# Multi-format API helpers.
# These agents don't all use the same API. smart_chat() tries every known
# format until one returns 200 with extractable text.
#
# Format      | Endpoint               | Payload key  | Response key
# ------------|------------------------|--------------|------------------
# Simple msg  | /chat                  | message      | response/content
# Query/RAG   | /chat or /api/chat     | query        | answer/response
# OpenAI      | /v1/chat/completions   | messages[]   | choices[0]...
# Ollama      | /api/generate          | prompt       | response
# Ollama chat | /api/chat              | messages[]   | message.content

CHAT_FORMATS: list[tuple[str, Callable[[str], dict]]] = [
    ("/chat",                lambda m: {"message": m}),
    ("/chat",                lambda m: {"query": m}),
    ("/v1/chat/completions", lambda m: {"messages": [{"role": "user", "content": m}]}),
    ("/api/chat",            lambda m: {"query": m}),
    ("/api/chat",            lambda m: {"messages": [{"role": "user", "content": m}]}),
    ("/api/generate",        lambda m: {"prompt": m, "stream": False}),
    ("/v1/completions",      lambda m: {"prompt": m, "max_tokens": 512}),
]


def _extract_text(data: dict) -> str | None:
    """Pull response text from any known format."""
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        pass
    try:
        return data["choices"][0]["text"]
    except (KeyError, IndexError, TypeError):
        pass
    try:
        return data["message"]["content"]
    except (KeyError, TypeError):
        pass
    for key in ("response", "content", "answer", "text", "output", "result"):
        if key in data and isinstance(data[key], str) and data[key].strip():
            return data[key]
    return None


def _extract_sources(data: dict) -> list:
    """Pull source documents from any known RAG format."""
    if "sources" in data and isinstance(data["sources"], list):
        return data["sources"]
    if "source_documents" in data:
        return data["source_documents"]
    if "context" in data and isinstance(data["context"], list):
        return data["context"]
    return []


def _extract_metadata(data: dict) -> dict | None:
    """Pull model metadata from response."""
    for key in ("metadata", "model_info", "debug", "info"):
        if key in data and isinstance(data[key], dict):
            return data[key]
    top_level = {k: data[k] for k in ("model", "provider", "version") if k in data}
    return top_level if top_level else None


def smart_chat(
    host: str,
    port: int,
    message: str,
    *,
    session_id: str | None = None,
    timeout: int = 10,
    rate_delay: float = 0.0,
) -> dict:
    """Try every known API format until one returns extractable text.

    Always returns a dict with keys: text, sources, metadata, format_used, raw.
    `text` is None when no format matched (caller checks for truthiness).
    """
    if rate_delay > 0:
        time.sleep(rate_delay)

    result: dict[str, Any] = {
        "text": None,
        "sources": [],
        "metadata": None,
        "format_used": None,
        "raw": None,
    }

    for endpoint, payload_fn in CHAT_FORMATS:
        payload = payload_fn(message)
        if session_id:
            payload["session_id"] = session_id
        url = f"http://{host}:{port}{endpoint}"
        resp = post(url, payload, timeout=timeout)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                text = _extract_text(data)
                if text:
                    result["text"] = text
                    result["sources"] = _extract_sources(data)
                    result["metadata"] = _extract_metadata(data)
                    result["format_used"] = endpoint
                    result["raw"] = data
                    return result
            except Exception:
                pass
    return result


def upload_file(
    host: str,
    port: int,
    filepath: str,
    *,
    endpoint: str = "/upload",
    timeout: int = 30,
) -> requests.Response | None:
    """POST a file as multipart/form-data. Returns the raw Response."""
    url = f"http://{host}:{port}{endpoint}"
    try:
        with open(filepath, "rb") as f:
            return requests.post(url, files={"file": f}, timeout=timeout)
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return None
