"""AISuite v2.0 — Guided Engagement Web UI.

Start with:
    python -m aisuite.ui.app
    # or via the CLI:
    aisuite gui

Routes:
    GET  /                              — engagement list / create
    POST /engagements                   — create engagement
    POST /engagements/{eid}/delete      — delete engagement
    GET  /engagement/{eid}              — engagement dashboard
    GET  /engagement/{eid}/t/{tid}      — technique detail (HTMX fragment)
    POST /engagement/{eid}/execute/{tid} — run a technique (HTMX swap)
    GET  /engagement/{eid}/agents       — agent inventory (HTMX fragment)
    GET  /engagement/{eid}/results      — recent results (HTMX fragment)

This is intentionally a single-file FastAPI app. Templates live under
aisuite/ui/templates/ and a single small stylesheet under static/.
"""
from __future__ import annotations

import importlib
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from aisuite.engine import registry as reg
from aisuite.engine.recon import ExecutionContext
from aisuite.engine.storage import Store


HERE = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(HERE / "templates"))
STATIC_DIR = HERE / "static"

app = FastAPI(title="AISuite v2.0 — Guided Engagement")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

store = Store()


def _resolve_executor(dotted: str):
    """'aisuite.engine.attacks:direct_injection' → callable."""
    if not dotted or ":" not in dotted:
        return None
    module_path, func_name = dotted.split(":", 1)
    try:
        module = importlib.import_module(module_path)
    except ImportError:
        return None
    return getattr(module, func_name, None)


# ── Routes ──────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> Any:
    engagements = store.list_engagements()
    return TEMPLATES.TemplateResponse(
        request, "index.html", {"engagements": engagements},
    )


@app.post("/engagements", response_class=HTMLResponse)
def create_engagement(name: str = Form(...), notes: str = Form("")) -> Any:
    name = (name or "").strip()
    if not name:
        raise HTTPException(400, "name required")
    eid = store.create_engagement(name=name, notes=notes)
    return RedirectResponse(f"/engagement/{eid}", status_code=303)


@app.post("/engagements/{eid}/delete")
def delete_engagement(eid: str) -> Any:
    store.delete_engagement(eid)
    return RedirectResponse("/", status_code=303)


@app.get("/engagement/{eid}", response_class=HTMLResponse)
def dashboard(request: Request, eid: str) -> Any:
    eng = store.get_engagement(eid)
    if not eng:
        raise HTTPException(404, "engagement not found")
    agents = store.list_agents(eid)
    results = store.list_results(eid, limit=20)
    return TEMPLATES.TemplateResponse(
        request,
        "dashboard.html",
        {
            "engagement": eng,
            "agents": agents,
            "results": results,
            "phases": reg.PHASE_ORDER,
            "phase_color": reg.PHASE_COLOR,
            "by_phase": reg.by_phase(),
        },
    )


@app.get("/engagement/{eid}/t/{tid}", response_class=HTMLResponse)
def technique_detail(request: Request, eid: str, tid: str) -> Any:
    eng = store.get_engagement(eid)
    if not eng:
        raise HTTPException(404, "engagement not found")
    tech = reg.by_id(tid)
    if not tech:
        raise HTTPException(404, f"unknown technique {tid}")
    agents = store.list_agents(eid)
    results = store.list_results(eid, technique_id=tid, limit=5)
    return TEMPLATES.TemplateResponse(
        request,
        "technique.html",
        {
            "engagement": eng,
            "technique": tech,
            "agents": agents,
            "results": results,
            "phase_color": reg.PHASE_COLOR,
        },
    )


@app.post("/engagement/{eid}/execute/{tid}", response_class=HTMLResponse)
async def execute(request: Request, eid: str, tid: str) -> Any:
    eng = store.get_engagement(eid)
    if not eng:
        raise HTTPException(404, "engagement not found")
    tech = reg.by_id(tid)
    if not tech:
        raise HTTPException(404, f"unknown technique {tid}")
    if not tech.implemented:
        return _result_fragment(request, tech, {
            "output": "[!] This technique is a placeholder for v2.1.",
            "success": False,
            "curl": None,
            "response_text": "",
        })

    form = await request.form()
    params: dict[str, Any] = {p.name: form.get(p.name, p.default) for p in tech.params}

    # Agent selection (if the technique requires one)
    agent: dict[str, Any] | None = None
    if tech.needs_agent:
        agent_id = form.get("agent_id")
        if agent_id:
            try:
                agent = store.get_agent(eid, int(agent_id))
            except (TypeError, ValueError):
                agent = None
        if not agent:
            return _result_fragment(request, tech, {
                "output": "[✗] Select a target agent first (use Agent Discovery to add one).",
                "success": False,
                "curl": None,
                "response_text": "",
            })
        # Map storage shape → executor shape (executor expects `host`/`port` flat)
        agent_for_ctx = {
            "host": agent["host"],
            "port": agent["port"],
            "agent": agent.get("name") or "agent",
        }
    else:
        agent_for_ctx = None

    ctx = ExecutionContext(engagement_id=eid, agent=agent_for_ctx)

    fn = _resolve_executor(tech.executor)
    if fn is None:
        return _result_fragment(request, tech, {
            "output": f"[✗] Executor not found: {tech.executor!r}",
            "success": False,
            "curl": None,
            "response_text": "",
        })

    try:
        result = fn(params, ctx)
    except Exception as e:
        result = {
            "output": f"[✗] Executor raised {type(e).__name__}: {e}",
            "success": False,
            "curl": None,
            "response_text": "",
        }

    # Persist newly discovered agents (R01)
    for new_agent in ctx.discovered_agents:
        store.upsert_agent(eid, new_agent)

    # Persist surface/fingerprint/rag onto the agent record if returned
    if agent and (
        "surface" in result or "fingerprint" in result or "rag" in result
    ):
        merged = {
            "host": agent["host"],
            "port": agent["port"],
            "name": agent.get("name"),
            "healthy": True,
        }
        if "surface" in result and isinstance(result["surface"], dict):
            merged["purpose"] = result["surface"].get("purpose") or agent.get("purpose")
            merged["tools"] = result["surface"].get("tools") or agent.get("tools")
            merged["api_format"] = (
                result["surface"].get("api_format") or agent.get("api_format")
            )
        store.upsert_agent(eid, merged)

    # Record the result
    target_str = (f"{agent['host']}:{agent['port']}" if agent
                  else f"{params.get('host', '-')}:{params.get('port', '-')}")
    store.record_result(
        eid,
        technique_id=tid,
        target=target_str,
        params=params,
        response_text=result.get("response_text") or result.get("output", ""),
        success=bool(result.get("success")),
    )

    return _result_fragment(request, tech, result)


def _result_fragment(request: Request, tech: reg.Technique, result: dict[str, Any]) -> Any:
    return TEMPLATES.TemplateResponse(
        request,
        "_result.html",
        {
            "technique": tech,
            "result": result,
            "phase_color": reg.PHASE_COLOR,
        },
    )


@app.get("/engagement/{eid}/agents", response_class=HTMLResponse)
def agent_inventory(request: Request, eid: str) -> Any:
    agents = store.list_agents(eid)
    return TEMPLATES.TemplateResponse(
        request, "_agents.html", {"engagement_id": eid, "agents": agents},
    )


@app.get("/engagement/{eid}/results", response_class=HTMLResponse)
def results_panel(request: Request, eid: str) -> Any:
    results = store.list_results(eid, limit=50)
    return TEMPLATES.TemplateResponse(
        request, "_results.html", {"engagement_id": eid, "results": results},
    )


# ── Entry point ────────────────────────────────────────────────────────────
def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    host = os.environ.get("AISUITE_HOST", "127.0.0.1")
    port = int(os.environ.get("AISUITE_PORT", "8000"))
    serve(host, port)
