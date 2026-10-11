"""FastAPI server for the delegation chain visualizer.

Endpoints:
  GET  /              -> serves the React dashboard (static build)
  GET  /api/scenarios -> list available scenarios
  POST /api/run/{scenario_id} -> run a scenario, stream events via WebSocket
  WS   /ws/{chain_id} -> WebSocket for real-time delegation events

Usage:
  deepxpia demo
  # or directly:
  uvicorn deep_xpia.server:app --reload
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from deep_xpia import __version__
from deep_xpia.events import ChainEvent, EventType


RUNNABLE_SCENARIOS = ("session_smuggling", "memory_poisoning", "intent_laundering", "registry_injection")


def create_app() -> FastAPI:
    app = FastAPI(
        title="deep-xpia",
        description="Multi-hop cross-prompt injection benchmark visualizer",
        version=__version__,
    )

    # Active WebSocket connections {chain_id: [websocket, ...]}
    _connections: dict[str, list[WebSocket]] = {}
    _tasks: set[asyncio.Task[None]] = set()

    def _drop(chain_id: str, ws: WebSocket) -> None:
        conns = _connections.get(chain_id, [])
        if ws in conns:
            conns.remove(ws)
        if not conns:
            _connections.pop(chain_id, None)  # don't keep one empty list per finished chain

    async def broadcast(chain_id: str, event: dict[str, Any]) -> None:
        dead = []
        for ws in _connections.get(chain_id, []):
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            _drop(chain_id, ws)

    @app.websocket("/ws/{chain_id}")
    async def ws_endpoint(websocket: WebSocket, chain_id: str) -> None:
        await websocket.accept()
        _connections.setdefault(chain_id, []).append(websocket)
        try:
            while True:
                await websocket.receive_text()  # keep alive
        except WebSocketDisconnect:
            _drop(chain_id, websocket)

    @app.get("/api/scenarios")
    async def list_scenarios() -> JSONResponse:
        # depth = delegation edges (taxonomy depth_definition), read from ground truth
        from deep_xpia.scenarios.intent_laundering.ground_truth import TOPOLOGY as IL_TOPOLOGY
        from deep_xpia.scenarios.memory_poisoning.ground_truth import TOPOLOGY as MP_TOPOLOGY
        from deep_xpia.scenarios.registry_injection.ground_truth import GROUND_TRUTH as REGISTRY_GT
        from deep_xpia.scenarios.session_smuggling.ground_truth import TOPOLOGY as SS_TOPOLOGY

        return JSONResponse({
            "scenarios": [
                {
                    "id": "session_smuggling",
                    "taxonomy_id": "DXPIA-001",
                    "title": "Session Smuggling",
                    "hop_mechanism": "instruction_piggyback",
                    "depth": SS_TOPOLOGY.hop_count,
                    "description": "Injection rides inside a legitimate delegation response.",
                },
                {
                    "id": "memory_poisoning",
                    "taxonomy_id": "DXPIA-002",
                    "title": "Cross-Agent Memory Poisoning",
                    "hop_mechanism": "temporal_persistence",
                    "depth": MP_TOPOLOGY.hop_count,
                    "description": "Injection persists across session boundaries.",
                },
                {
                    "id": "intent_laundering",
                    "taxonomy_id": "DXPIA-006",
                    "title": "Intent Laundering",
                    "hop_mechanism": "adversarial_refinement",
                    "depth": IL_TOPOLOGY.hop_count,
                    "description": "Intermediate agent makes injection harder to detect.",
                },
                {
                    "id": "registry_injection",
                    "taxonomy_id": "DXPIA-008",
                    "title": "Registry Injection",
                    "hop_mechanism": "trust_boundary_sideload",
                    "depth": REGISTRY_GT["depth"],
                    "description": "Injection enters via tool manifest metadata at registration.",
                },
            ]
        })

    @app.post("/api/run/{scenario_id}")
    async def run_scenario(
        scenario_id: str,
        attack: bool = True,
        defense: str | None = None,
    ) -> JSONResponse:
        if scenario_id not in RUNNABLE_SCENARIOS:
            raise HTTPException(status_code=404, detail=f"unknown scenario {scenario_id!r}")
        chain_id = f"{scenario_id}-{uuid.uuid4().hex[:8]}"

        async def _run_and_stream() -> None:
            # The client learns chain_id from this response and only then opens
            # the WebSocket; wait briefly for a subscriber so early events aren't lost.
            for _ in range(50):
                if _connections.get(chain_id):
                    break
                await asyncio.sleep(0.1)
            result: Any
            events: list[Any]
            try:
                if scenario_id == "session_smuggling":
                    from deep_xpia.scenarios.session_smuggling.pipeline import SessionSmugglingPipeline
                    result = SessionSmugglingPipeline(attack=attack, defense=defense).run(
                        chain_id=chain_id
                    )
                    events = result.events
                elif scenario_id == "memory_poisoning":
                    from deep_xpia.scenarios.memory_poisoning.pipeline import MemoryPoisoningPipeline
                    # the scenario's defense is taint-aware memory
                    result = MemoryPoisoningPipeline(
                        attack=attack, taint_aware_memory=defense in ("taint", "all")
                    ).run()
                    events = result.session1_events + result.session2_events
                elif scenario_id == "intent_laundering":
                    from deep_xpia.scenarios.intent_laundering.pipeline import IntentLaunderingPipeline
                    result = IntentLaunderingPipeline(attack=attack, defense=defense).run(
                        chain_id=chain_id
                    )
                    events = result.events
                else:  # registry_injection
                    from deep_xpia.scenarios.registry_injection.pipeline import RegistryInjectionPipeline
                    result = RegistryInjectionPipeline(attack=attack, defense=defense).run(
                        chain_id=chain_id
                    )
                    events = result.events

                # Scenario event dataclasses differ: DelegationEvent has from/to_agent +
                # actual_output; LaunderingHopEvent has agent + output_content;
                # SessionEvent has agent + content. Normalize here.
                prev_agent = "user"
                for ev in events:
                    to_agent = str(getattr(ev, "to_agent", None) or getattr(ev, "agent", ""))
                    from_agent = str(getattr(ev, "from_agent", None) or prev_agent)
                    prev_agent = to_agent
                    content = next(
                        (v for v in (getattr(ev, a, None) for a in
                                     ("actual_output", "output_content", "content"))
                         if v is not None),
                        "",
                    )
                    raw_drift: Any = getattr(ev, "drift_score", None)
                    if raw_drift is None:  # LaunderingHopEvent
                        raw_drift = getattr(ev, "drift_score_raw", 0.0)
                    drift = float(raw_drift)
                    payload = ChainEvent(
                        event_type=EventType.DELEGATION_RESULT,
                        chain_id=chain_id,
                        hop_number=getattr(ev, "hop", 0),
                        hop_depth=len(events),
                        from_agent=from_agent,
                        to_agent=to_agent,
                        intent=getattr(ev, "intent", ""),
                        content=content,
                        drift_score=drift,
                        taint_set=[],
                        timestamp_ms=getattr(ev, "timestamp_ms", 0.0),
                        ground_truth_label=ev.ground_truth_label,
                    ).model_dump(mode="json")
                    await broadcast(chain_id, payload)
                    await asyncio.sleep(0.3)  # pace for visualizer animation

                await broadcast(chain_id, {
                    "event_type": EventType.CHAIN_COMPLETE.value,
                    "chain_id": chain_id,
                    "attack_succeeded": getattr(
                        result, "attack_succeeded", getattr(result, "attack_activated", False)
                    ),
                })
            except Exception as e:
                await broadcast(chain_id, {"event_type": "error", "chain_id": chain_id, "error": str(e)})

        # keep a reference so the task isn't garbage-collected mid-run
        task = asyncio.create_task(_run_and_stream())
        _tasks.add(task)
        task.add_done_callback(_tasks.discard)
        return JSONResponse({"chain_id": chain_id, "status": "running"})

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok", "version": __version__})

    # src/deep_xpia/server.py -> parents[2] is the repo root
    dashboard_build = Path(__file__).resolve().parents[2] / "dashboard" / "dist"

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

    # Serve the static dashboard build if it exists; otherwise the fallback page.
    # (A GET "/" route registered first would shadow the mount.)
    if dashboard_build.exists():
        app.mount("/", StaticFiles(directory=str(dashboard_build), html=True), name="dashboard")
    else:
        app.add_api_route("/", root, methods=["GET"])

    return app


# For uvicorn direct run
app = create_app()
