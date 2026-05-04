"""FastAPI server for the delegation chain visualizer.

Endpoints:
  GET  /              -> serves the React dashboard (static build)
  GET  /api/scenarios -> list available scenarios
  POST /api/run       -> run a scenario, stream events via WebSocket
  WS   /ws/{chain_id} -> WebSocket for real-time delegation events

Usage:
  deepxpia demo
  # or directly:
  uvicorn deep_xpia.server:app --reload
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from deep_xpia.events import ChainEvent, EventType


def create_app() -> FastAPI:
    app = FastAPI(
        title="deep-xpia",
        description="Multi-hop cross-prompt injection benchmark visualizer",
        version="0.1.0",
    )

    # Active WebSocket connections {chain_id: [websocket, ...]}
    _connections: dict[str, list[WebSocket]] = {}

    async def broadcast(chain_id: str, event: dict[str, Any]) -> None:
        dead = []
        for ws in _connections.get(chain_id, []):
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            _connections.get(chain_id, []).remove(ws)

    @app.websocket("/ws/{chain_id}")
    async def ws_endpoint(websocket: WebSocket, chain_id: str) -> None:
        await websocket.accept()
        _connections.setdefault(chain_id, []).append(websocket)
        try:
            while True:
                await websocket.receive_text()  # keep alive
        except WebSocketDisconnect:
            conns = _connections.get(chain_id, [])
            if websocket in conns:
                conns.remove(websocket)

    @app.get("/api/scenarios")
    async def list_scenarios() -> JSONResponse:
        return JSONResponse({
            "scenarios": [
                {
                    "id": "session_smuggling",
                    "taxonomy_id": "DXPIA-001",
                    "title": "Session Smuggling",
                    "hop_mechanism": "instruction_piggyback",
                    "depth": 3,
                    "description": "Injection rides inside a legitimate delegation response.",
                },
                {
                    "id": "memory_poisoning",
                    "taxonomy_id": "DXPIA-002",
                    "title": "Cross-Agent Memory Poisoning",
                    "hop_mechanism": "temporal_persistence",
                    "depth": 3,
                    "description": "Injection persists across session boundaries.",
                },
                {
                    "id": "intent_laundering",
                    "taxonomy_id": "DXPIA-006",
                    "title": "Intent Laundering",
                    "hop_mechanism": "adversarial_refinement",
                    "depth": 4,
                    "description": "Intermediate agent makes injection harder to detect.",
                },
            ]
        })

    @app.post("/api/run/{scenario_id}")
    async def run_scenario(
        scenario_id: str,
        attack: bool = True,
        defense: str | None = None,
    ) -> JSONResponse:
        chain_id = f"{scenario_id}-{uuid.uuid4().hex[:8]}"

        async def _run_and_stream() -> None:
            try:
                if scenario_id == "session_smuggling":
                    from scenarios.session_smuggling.pipeline import SessionSmugglingPipeline
                    p = SessionSmugglingPipeline(attack=attack, defense=defense)
                    result = p.run(chain_id=chain_id)
                    events = result.events
                elif scenario_id == "memory_poisoning":
                    from scenarios.memory_poisoning.pipeline import MemoryPoisoningPipeline
                    p = MemoryPoisoningPipeline(attack=attack)
                    result = p.run()
                    events = result.session1_events + result.session2_events
                elif scenario_id == "intent_laundering":
                    from scenarios.intent_laundering.pipeline import IntentLaunderingPipeline
                    p = IntentLaunderingPipeline(attack=attack, defense=defense)
                    result = p.run(chain_id=chain_id)
                    events = result.events
                else:
                    return

                for ev in events:
                    payload = {
                        "event_type": EventType.DELEGATION_RESULT.value,
                        "chain_id": chain_id,
                        "hop_number": getattr(ev, "hop", 0),
                        "hop_depth": len(events),
                        "from_agent": getattr(ev, "from_agent", ""),
                        "to_agent": getattr(ev, "to_agent", getattr(ev, "agent", "")),
                        "intent": getattr(ev, "intent", ""),
                        "content": getattr(ev, "actual_output", getattr(ev, "content", "")),
                        "drift_score": getattr(ev, "drift_score", 0.0),
                        "taint_set": [],
                        "timestamp_ms": getattr(ev, "timestamp_ms", 0.0),
                        "ground_truth_label": ev.ground_truth_label,
                    }
                    await broadcast(chain_id, payload)
                    await asyncio.sleep(0.3)  # pace for visualizer animation

                await broadcast(chain_id, {
                    "event_type": EventType.CHAIN_COMPLETE.value,
                    "chain_id": chain_id,
                    "attack_succeeded": getattr(result, "attack_succeeded", False),
                })
            except Exception as e:
                await broadcast(chain_id, {"event_type": "error", "chain_id": chain_id, "error": str(e)})

        asyncio.create_task(_run_and_stream())
        return JSONResponse({"chain_id": chain_id, "status": "running"})

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok", "version": "0.1.0"})

    @app.get("/")
    async def root() -> HTMLResponse:
        # Minimal fallback when dashboard build isn't present
        return HTMLResponse("""
<!DOCTYPE html>
<html>
<head><title>deep-xpia</title></head>
<body>
<h1>deep-xpia</h1>
<p>Backend running. Dashboard build not found.</p>
<p>Run: <code>cd dashboard && npm install && npm run build</code></p>
<p><a href="/docs">API docs</a></p>
</body>
</html>
""")

    # Mount static dashboard build if it exists
    dashboard_build = Path(__file__).parent.parent.parent.parent / "dashboard" / "dist"
    if dashboard_build.exists():
        app.mount("/", StaticFiles(directory=str(dashboard_build), html=True), name="dashboard")

    return app


# For uvicorn direct run
app = create_app()
