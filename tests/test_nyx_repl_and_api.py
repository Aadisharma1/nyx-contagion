"""End-to-end tests for the nyx-style REPL session and the FastAPI telemetry
API (dashboard, health, campaign lifecycle, ladder, WebSocket stream, and the
AIVSS audit-bundle export).

One real HoneypotServer is started at module scope and shared by the REPL
sessions; the API endpoints boot their own process-wide shared server over
127.0.0.1 via fastapi.testclient.TestClient (no external network).
"""

import io
import json
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from contagion.api.app import app as api_app
from contagion.surfaces.honeypot_server import HoneypotServer
from contagion.tui.repl import NyxREPL, NyxSession

SESSIONS_DIR = Path.home() / ".nyx_contagion" / "sessions"

REPL_COMMANDS = (
    "/agents\n"
    "/use mcts-planner bias toward split surface\n"
    "/memory\n"
    "/questions\n"
    "/step 2\n"
    "/quit\n"
)

MINIMAL_BENCHMARK = {
    "benchmark": "t",
    "seed": 1,
    "trials_per_defender": 1,
    "max_turns": 1,
    "defenders": {},
    "ranking_inversion": {
        "static_ranking": [],
        "dynamic_ranking": [],
        "per_defender_ranks": {},
        "inversions": [],
    },
    "incentive_matrix": {},
    "total_episodes": 0,
    "trial_rows": [],
}


@pytest.fixture(scope="module")
def honeypot_server():
    server = HoneypotServer()
    server.start()
    yield server
    server.stop()


@pytest.fixture(scope="module")
def api_client():
    return TestClient(api_app)



def test_repl_full_operator_flow(honeypot_server):
    before = set(SESSIONS_DIR.glob("*.json")) if SESSIONS_DIR.exists() else set()

    session = NyxSession(defender="budget-fast-single", server=honeypot_server, seed=7)
    out = io.StringIO()
    exit_code = NyxREPL(session, out).run(io.StringIO(REPL_COMMANDS))
    text = out.getvalue()

    assert exit_code == 0
    for agent in ("dom-compiler", "pdf-poisoner", "mcts-planner", "trajectory-verifier"):
        assert agent in text, f"missing sub-agent {agent!r} in /agents output"
    assert "steering routed to mcts-planner" in text
    assert "attacker belief state" in text
    assert "(no open questions" in text
    assert "[Agent: nyx-lead" in text
    assert "Verified Breaks" in text
    assert "saved:" in text

    new_files = [
        p
        for p in SESSIONS_DIR.glob("*.json")
        if p not in before and time.time() - p.stat().st_mtime < 60
    ]
    assert new_files, "REPL /quit did not persist a new session json file"


def test_session_step_and_status_line(honeypot_server):
    session = NyxSession(defender="budget-fast-single", server=honeypot_server, seed=7)
    try:
        entry = session.step()
        assert {"turn", "arm", "tier"} <= set(entry)
        status = session.status_line()
        assert "Session Spend: $" in status
        assert status.startswith("[Agent: nyx-lead")
        assert status.endswith("]")
    finally:
        session.close()



def test_api_dashboard_and_health(api_client):
    dashboard = api_client.get("/")
    assert dashboard.status_code == 200
    assert "NYX" in dashboard.text
    assert "CONTAGION" in dashboard.text

    health = api_client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"


def test_api_campaign_lifecycle_and_ladder(api_client):
    started = api_client.post(
        "/api/campaign/start",
        json={"defender": "budget-fast-single", "max_turns": 4},
    )
    assert started.status_code == 200
    campaign_id = started.json()["campaign_id"]
    assert campaign_id

    state = {}
    deadline = time.time() + 15.0
    while time.time() < deadline:
        state = api_client.get(f"/api/campaign/{campaign_id}").json()
        if state["status"] == "complete":
            break
        time.sleep(0.15)
    assert state["status"] == "complete", state
    assert state["error"] is None, state
    assert state["result"] is not None

    ladder = api_client.get(f"/api/ladder/{campaign_id}")
    assert ladder.status_code == 200
    tier_trace = ladder.json()["tier_trace"]
    assert isinstance(tier_trace, list)
    assert len(tier_trace) >= 1


def test_api_websocket_telemetry_stream(api_client):
    started = api_client.post(
        "/api/campaign/start",
        json={"defender": "budget-fast-single", "max_turns": 3},
    )
    assert started.status_code == 200
    campaign_id = started.json()["campaign_id"]

    received_complete = False
    with api_client.websocket_connect(f"/ws/telemetry/{campaign_id}") as ws:
        for _ in range(60):
            message = ws.receive_json()
            if message.get("type") == "campaign_complete":
                received_complete = True
                break
    assert received_complete, "websocket stream never delivered campaign_complete"


def test_api_export_bundle_sha256(api_client, tmp_path, monkeypatch):
    benchmark_path = tmp_path / "ace_benchmark.json"
    benchmark_path.write_text(json.dumps(MINIMAL_BENCHMARK), encoding="utf-8")
    monkeypatch.setenv("NYX_BENCHMARK_PATH", str(benchmark_path))

    response = api_client.post("/api/export/bundle")
    assert response.status_code == 200
    body = response.json()
    assert re.fullmatch(r"[0-9a-f]{64}", body["bundle_sha256"])
