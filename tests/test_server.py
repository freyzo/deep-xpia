"""Demo server API: scenario listing, run validation, event stream."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from deep_xpia.server import RUNNABLE_SCENARIOS, create_app


def _stream(client: TestClient, scenario: str, query: str = "") -> list[dict[str, Any]]:
    chain_id = client.post(f"/api/run/{scenario}{query}").json()["chain_id"]
    events = []
    with client.websocket_connect(f"/ws/{chain_id}") as ws:
        while True:
            event = ws.receive_json()
            events.append(event)
            if event["event_type"] in ("chain_complete", "error"):
                return events


def test_unknown_scenario_is_404() -> None:
    assert TestClient(create_app()).post("/api/run/nope").status_code == 404


def test_listed_scenarios_are_runnable() -> None:
    listed = [s["id"] for s in TestClient(create_app()).get("/api/scenarios").json()["scenarios"]]
    assert sorted(listed) == sorted(RUNNABLE_SCENARIOS)


@pytest.mark.parametrize("scenario", RUNNABLE_SCENARIOS)
def test_each_scenario_streams_to_completion(scenario: str) -> None:
    with TestClient(create_app()) as client:
        events = _stream(client, scenario)
    assert events[-1]["event_type"] == "chain_complete"
    assert events[-1]["attack_succeeded"] is True  # undefended attack runs succeed
    assert events[0]["hop_number"] == min(e["hop_number"] for e in events[:-1])


def test_memory_poisoning_taint_defense_detects() -> None:
    with TestClient(create_app()) as client:
        events = _stream(client, "memory_poisoning", "?defense=taint")
    assert any(e.get("ground_truth_label") == "detected" for e in events)
    assert events[-1]["attack_succeeded"] is False


def test_closed_websocket_leaves_no_connection_entry() -> None:
    app = create_app()
    client = TestClient(app)
    with client.websocket_connect("/ws/abc"):
        pass
    endpoint = next(r for r in app.routes if getattr(r, "path", "") == "/ws/{chain_id}")
    closure = dict(zip(endpoint.endpoint.__code__.co_freevars,
                       (c.cell_contents for c in endpoint.endpoint.__closure__ or ())))
    assert "abc" not in closure["_connections"]


def test_root_redirects_to_static_site_in_checkout() -> None:
    client = TestClient(create_app())
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 307) and r.headers["location"] == "/deep-xpia/"
    page = client.get("/deep-xpia/")
    assert page.status_code == 200 and '<div id="root">' in page.text
