"""
server.py — SOCPilot HTTP / WebSocket API

Exposes the SOCPilot agent over FastAPI for integration with dashboards,
SOAR platforms, and webhook-triggered automation.

Endpoints:
    GET  /health               — Liveness check
    GET  /playbooks            — List available SOC playbooks
    GET  /tools                — List tool definitions
    POST /query                — Run an investigation (SSE streaming)
    WS   /ws/{session_id}      — Stateful interactive session (WebSocket)
    POST /webhook/siem         — SIEM alert → auto-trigger IR playbook (SSE)
    POST /report               — Run a playbook and save to Markdown file

All streaming endpoints emit JSON-encoded event objects on separate lines
(SSE format: "data: {...}\n\n").

Run locally:
    uvicorn server:app --host 0.0.0.0 --port 8000 --reload

Production (Docker):
    CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator

from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect,
    HTTPException, Request, status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from agent import PLAYBOOK_PROMPTS, SECURITY_TOOLS, run_investigation
from config import cfg
from mcp_client import MCPClientPool
from onboard import (
    TOOLS as _ONBOARD_TOOLS,
    TIERS as _TIERS,
    _write_env,
    _load_existing_env,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Shared MCP pool — one pool per server instance, not per request
# ─────────────────────────────────────────────────────────────────────────────

_pool: MCPClientPool | None = None

# ─────────────────────────────────────────────────────────────────────────────
# Session history store — persists across WebSocket reconnects
# ─────────────────────────────────────────────────────────────────────────────

_session_store: dict[str, list[dict]] = {}
_sessions_dir  = Path(__file__).parent / "sessions"


def _load_session(session_id: str) -> list[dict]:
    """Return history for session_id, loading from disk if available."""
    if session_id in _session_store:
        return _session_store[session_id]
    path = _sessions_dir / f"{session_id}.json"
    if path.exists():
        try:
            data = json.loads(path.read_text())
            if isinstance(data, list):
                _session_store[session_id] = data
                return data
        except Exception:
            pass
    history: list[dict] = []
    _session_store[session_id] = history
    return history


def _save_session(session_id: str, history: list[dict]) -> None:
    """Persist session history to disk (best-effort)."""
    try:
        _sessions_dir.mkdir(exist_ok=True)
        path = _sessions_dir / f"{session_id}.json"
        path.write_text(json.dumps(history))
    except Exception:
        pass


def _delete_session(session_id: str) -> None:
    """Remove session from memory and disk."""
    _session_store.pop(session_id, None)
    path = _sessions_dir / f"{session_id}.json"
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Start the MCP pool when the server starts; shut it down on exit."""
    global _pool
    if cfg.live:
        _pool = MCPClientPool(cfg)
        logger.info("MCP pool initialised (live mode)")
    else:
        logger.info("MCP pool not started (mock mode)")
    try:
        yield
    finally:
        if _pool is not None:
            await _pool.shutdown()
            logger.info("MCP pool shut down")


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI application
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SOCPilot API",
    description="AI Security Operations Co-pilot — private-subnet deployment",
    version="1.0.0",
    lifespan=_lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Allow browser-based UI to call the API (useful during local development)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_UI_DIR = Path(__file__).parent / "ui"


# ─────────────────────────────────────────────────────────────────────────────
# Request / response models
# ─────────────────────────────────────────────────────────────────────────────

class QueryRequest(BaseModel):
    query:    str
    verbose:  bool = False

class PlaybookRequest(BaseModel):
    playbook: str
    target:   str
    verbose:  bool = False

class ReportRequest(BaseModel):
    playbook:  str
    target:    str
    filename:  str | None = None   # auto-generated if None

class SIEMWebhookPayload(BaseModel):
    """Generic SIEM alert payload — accepts any shape."""
    alert_id:   str | None = None
    title:      str | None = None
    severity:   str | None = None
    description: str | None = None
    raw:        dict[str, Any] = {}


# ─────────────────────────────────────────────────────────────────────────────
# SSE helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sse(event: dict[str, Any]) -> str:
    """Format a dict as a Server-Sent Event line."""
    return f"data: {json.dumps(event)}\n\n"


async def _stream_investigation(
    query: str,
    history: list[dict] | None = None,
    verbose: bool = False,
) -> AsyncGenerator[str, None]:
    """Async generator that yields SSE-formatted strings."""
    async for event in run_investigation(
        query,
        history=history,
        pool=_pool,
        verbose=verbose,
    ):
        yield _sse(event)


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["ops"])
async def health() -> dict[str, Any]:
    """Liveness check."""
    return {
        "status":   "ok",
        "mode":     "live" if cfg.live else "mock",
        "provider": cfg.provider,
        "model":    cfg.model,
        "base_url": cfg.base_url,
        "ts":       datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health/llm", tags=["ops"])
async def health_llm() -> dict[str, Any]:
    """
    Test LLM connectivity by sending a minimal probe message.

    Returns { status: "ok"|"error", provider, model, base_url, latency_ms, error? }
    Times out after 15 s so the UI stays responsive.
    """
    import time
    result: dict[str, Any] = {
        "provider": cfg.provider,
        "model":    cfg.model,
        "base_url": cfg.base_url or ("https://api.anthropic.com" if cfg.provider == "anthropic" else "http://localhost:11434/v1"),
        "status":   "error",
    }

    if cfg.provider == "demo":
        result["status"]      = "ok"
        result["model"]       = "demo"
        result["latency_ms"]  = 0
        result["response"]    = "demo mode — no API call needed"
        return result

    if cfg.provider == "anthropic" and not cfg.api_key:
        result["error"] = "AI_API_KEY is not set — add it to your .env file"
        return result

    t0 = time.monotonic()
    try:
        if cfg.provider == "openai":
            from openai import AsyncOpenAI
            client = AsyncOpenAI(
                api_key=cfg.api_key or "local",
                base_url=cfg.base_url or "http://localhost:11434/v1",
            )
            resp = await asyncio.wait_for(
                client.chat.completions.create(
                    model=cfg.model,
                    messages=[{"role": "user", "content": "Reply with the single word: OK"}],
                    max_tokens=5,
                    temperature=0,
                ),
                timeout=15.0,
            )
            preview = (resp.choices[0].message.content or "").strip()[:30]
        else:
            import anthropic as _sdk
            kwargs: dict[str, Any] = {"api_key": cfg.api_key}
            if cfg.base_url:
                kwargs["base_url"] = cfg.base_url
            aclient = _sdk.AsyncAnthropic(**kwargs)
            resp = await asyncio.wait_for(
                aclient.messages.create(
                    model=cfg.model,
                    max_tokens=5,
                    messages=[{"role": "user", "content": "Reply with the single word: OK"}],
                ),
                timeout=15.0,
            )
            preview = (resp.content[0].text if resp.content else "").strip()[:30]

        result["status"]       = "ok"
        result["latency_ms"]   = round((time.monotonic() - t0) * 1000)
        result["response"]     = preview

    except asyncio.TimeoutError:
        result["error"] = "Connection timed out after 15 s — is the server running?"
    except Exception as exc:
        result["error"] = str(exc)[:300]

    return result


@app.get("/playbooks", tags=["agent"])
async def list_playbooks() -> dict[str, list[str]]:
    """Return all available SOC playbook names."""
    return {"playbooks": list(PLAYBOOK_PROMPTS.keys())}


@app.get("/tools", tags=["agent"])
async def list_tools() -> dict[str, Any]:
    """Return the agent tool definitions."""
    return {"tools": SECURITY_TOOLS, "count": len(SECURITY_TOOLS)}


@app.post("/query", tags=["agent"])
async def query_stream(req: QueryRequest) -> StreamingResponse:
    """
    Run a free-form security investigation.

    Returns a Server-Sent Events stream of JSON event objects.
    Each line: ``data: {"type": "text"|"tool_call"|"tool_result"|"done"|"error", ...}``
    """
    if not cfg.api_key and cfg.provider != "demo":
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="AI_API_KEY not configured")
    return StreamingResponse(
        _stream_investigation(req.query, verbose=req.verbose),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/playbook", tags=["agent"])
async def run_playbook(req: PlaybookRequest) -> StreamingResponse:
    """
    Run a named SOC playbook against a target.

    Returns a Server-Sent Events stream.
    """
    if req.playbook not in PLAYBOOK_PROMPTS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            detail=f"Unknown playbook '{req.playbook}'. "
                                   f"Valid: {list(PLAYBOOK_PROMPTS.keys())}")
    if not cfg.api_key and cfg.provider != "demo":
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="AI_API_KEY not configured")
    prompt = PLAYBOOK_PROMPTS[req.playbook].format(target=req.target)
    return StreamingResponse(
        _stream_investigation(prompt, verbose=req.verbose),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/report", tags=["agent"])
async def generate_report(req: ReportRequest) -> dict[str, Any]:
    """
    Run a playbook and save the output to a Markdown file.

    Returns synchronously after the investigation completes (may take minutes).
    """
    if req.playbook not in PLAYBOOK_PROMPTS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            detail=f"Unknown playbook '{req.playbook}'")
    if not cfg.api_key and cfg.provider != "demo":
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="AI_API_KEY not configured")

    prompt   = PLAYBOOK_PROMPTS[req.playbook].format(target=req.target)
    filename = req.filename or (
        f"{req.playbook}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.md"
    )
    report_path = cfg.reports_dir / filename
    report_path.parent.mkdir(parents=True, exist_ok=True)

    ts    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    parts = [f"# SOCPilot Report — {req.playbook}\n\n"
             f"**Target:** {req.target}\n\n"
             f"**Generated:** {ts}\n\n---\n\n"]
    turns = 0

    async for event in run_investigation(prompt, pool=_pool):
        etype = event["type"]
        if etype == "text":
            parts.append(event["text"])
        elif etype == "tool_call":
            parts.append(f"\n\n**→ Tool: {event['name']}**\n"
                         f"```json\n{json.dumps(event['inputs'], indent=2)}\n```\n")
        elif etype == "tool_result":
            parts.append(f"\n**Result:**\n```\n{event['content']}\n```\n")
        elif etype == "done":
            turns = event["turns"]
        elif etype == "error":
            parts.append(f"\n\n**Error:** {event['message']}\n")

    report_path.write_text("".join(parts))
    return {
        "status":   "ok",
        "file":     str(report_path),
        "turns":    turns,
        "bytes":    report_path.stat().st_size,
    }


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket — stateful interactive session
# ─────────────────────────────────────────────────────────────────────────────

@app.websocket("/ws/{session_id}")
async def ws_session(websocket: WebSocket, session_id: str) -> None:
    """
    Stateful interactive WebSocket session.

    The client sends plain-text queries; the server streams JSON event objects
    back. The conversation history is maintained for the life of the connection.

    Client → server: ``{"query": "...", "verbose": false}``
    Server → client: ``{"type": "text"|"tool_call"|..., ...}``
                     ``{"type": "done", "turns": N}``
    """
    await websocket.accept()
    history = _load_session(session_id)
    logger.info("WebSocket session started: %s (history: %d msgs)", session_id, len(history))

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg     = json.loads(raw)
                query   = msg.get("query", "").strip()
                verbose = bool(msg.get("verbose", False))
            except (json.JSONDecodeError, AttributeError):
                query   = raw.strip()
                verbose = False

            if not query:
                continue

            async for event in run_investigation(
                query,
                history=history,
                pool=_pool,
                verbose=verbose,
            ):
                await websocket.send_text(json.dumps(event))

            # Persist after each completed turn
            _save_session(session_id, history)

    except WebSocketDisconnect:
        _save_session(session_id, history)
        logger.info("WebSocket session ended: %s (history: %d msgs)", session_id, len(history))
    except Exception as exc:
        _save_session(session_id, history)
        logger.exception("WebSocket error in session %s: %s", session_id, exc)
        try:
            await websocket.send_text(json.dumps({"type": "error", "message": str(exc)}))
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Session management
# ─────────────────────────────────────────────────────────────────────────────

@app.delete("/sessions/{session_id}", tags=["sessions"])
async def delete_session(session_id: str):
    """Clear conversation history for a session (used by 'Clear History' in UI)."""
    _delete_session(session_id)
    return {"status": "cleared", "session_id": session_id}


# ─────────────────────────────────────────────────────────────────────────────
# SIEM Webhook — auto-trigger incident response
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/webhook/siem", tags=["automation"])
async def siem_webhook(payload: SIEMWebhookPayload) -> StreamingResponse:
    """
    Receive a SIEM alert and automatically trigger the incident-response playbook.

    Designed to be called by Microsoft Sentinel logic apps, Splunk alert actions,
    Elastic watcher, or Datadog monitors.

    Returns a Server-Sent Events stream of investigation events.
    """
    if not cfg.api_key and cfg.provider != "demo":
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="AI_API_KEY not configured")

    # Build a rich description from whatever fields the SIEM provides
    alert_id    = payload.alert_id or str(uuid.uuid4())
    title       = payload.title or "Unnamed alert"
    severity    = payload.severity or "unknown"
    description = payload.description or ""
    raw_preview = json.dumps(payload.raw)[:400] if payload.raw else ""

    target = (
        f"SIEM alert [{alert_id}]: {title}\n"
        f"Severity: {severity}\n"
        f"Description: {description}\n"
        + (f"Raw data: {raw_preview}" if raw_preview else "")
    ).strip()

    prompt = PLAYBOOK_PROMPTS["incident-response"].format(target=target)
    logger.info("SIEM webhook → IR playbook | alert=%s severity=%s", alert_id, severity)

    return StreamingResponse(
        _stream_investigation(prompt),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─────────────────────────────────────────────────────────────────────────────
# UI serving
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def serve_ui() -> FileResponse:
    """Serve the browser-based chat UI."""
    index = _UI_DIR / "index.html"
    if not index.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="UI not built — run: mkdir -p ui")
    return FileResponse(str(index))


# ─────────────────────────────────────────────────────────────────────────────
# Extended playbooks endpoint (includes full prompt templates)
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/playbooks/detail", tags=["agent"])
async def playbooks_detail() -> dict[str, Any]:
    """Return playbook names with their full prompt templates (including {target} placeholder)."""
    return {"playbooks": PLAYBOOK_PROMPTS}


# ─────────────────────────────────────────────────────────────────────────────
# Onboarding API — exposes the onboard.py catalog to the browser wizard
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/onboard/tools", tags=["onboarding"])
async def get_onboard_catalog() -> dict[str, Any]:
    """Return the full tool catalog and tier definitions for the UI onboarding wizard."""
    return {
        "tools": {
            tid: {
                "id": t.id,
                "display": t.display,
                "category": t.category,
                "description": t.description,
                "tiers": t.tiers,
                "free": t.free,
                "doc_url": t.doc_url,
                "credentials": [
                    {
                        "key": c.key,
                        "label": c.label,
                        "secret": c.secret,
                        "optional": c.optional,
                        "hint": c.hint,
                    }
                    for c in t.credentials
                ],
            }
            for tid, t in _ONBOARD_TOOLS.items()
        },
        "tiers": _TIERS,
    }


class EnvApplyRequest(BaseModel):
    values: dict[str, str]


@app.post("/onboard/env", tags=["onboarding"])
async def apply_env(req: EnvApplyRequest) -> dict[str, Any]:
    """
    Merge the provided key-value pairs into the .env file and write it to disk.
    Existing keys not in the payload are preserved.
    Restart the server after applying to pick up new environment variables.
    """
    env_path = Path(".env")
    existing = _load_existing_env(env_path)
    # Only write non-empty values; preserve existing keys not in payload
    merged = {**existing, **{k: v for k, v in req.values.items() if v.strip()}}
    _write_env(merged, env_path)
    return {
        "status": "ok",
        "file": str(env_path.resolve()),
        "keys_written": len(merged),
        "note": "Restart the server to activate the new configuration.",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Report download
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/reports/{filename:path}", tags=["agent"])
async def download_report(filename: str) -> FileResponse:
    """Download a previously generated Markdown investigation report."""
    # Strip directory components to prevent path traversal
    safe_name = Path(filename).name
    report_path = cfg.reports_dir / safe_name
    if not report_path.exists() or not report_path.is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Report '{safe_name}' not found")
    return FileResponse(
        str(report_path),
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Entry point for direct invocation
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host=cfg.server_host,
        port=cfg.server_port,
        reload=False,
        log_level="info",
    )
