"""FastAPI server streaming live WebSocket campaign telemetry + REST endpoints.

Serves the Obsidian dashboard at ``/``, live campaign control under
``/api/campaign/*``, the latest committed ACE benchmark under
``/api/benchmark/latest``, one-click AIVSS audit-bundle export, and
``/ws/telemetry/{campaign_id}`` for real-time ladder progression.
"""
from __future__ import annotations

import asyncio
import json
import os
import threading
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from ..attacker.mcts_planner import MCTSPlanner
from ..attacker.side_channel_analyzer import SideChannelAnalyzer
from ..attacker.trajectory_verifier import TrajectoryVerifier
from ..config import DEFAULT_SEED, REPO_VERSION
from ..defenses.defender_profiles import get_profile
from ..economics.report_generator import build_audit_bundle
from ..swarm.orchestrator import SwarmOrchestrator, load_challenge
from ..surfaces.honeypot_server import shared_server
from ..tui.repl import default_challenge_path


class CampaignStartRequest(BaseModel):
    defender: str = "budget-fast-single"
    challenge: str = "procurement_worm_v1"
    mode: str = "calibrated-sim"
    max_turns: int = Field(default=12, ge=1, le=100)


class CampaignState:
    def __init__(self, campaign_id: str) -> None:
        self.id = campaign_id
        self.events: List[dict] = []
        self.done = threading.Event()
        self.error: Optional[str] = None
        self.result: Optional[dict] = None
        self.thread: Optional[threading.Thread] = None

    def summary(self) -> dict:
        return {
            "campaign_id": self.id,
            "status": "complete" if self.done.is_set() else "running",
            "events": len(self.events),
            "error": self.error,
            "result": self.result,
        }


app = FastAPI(title="nyx-contagion telemetry", docs_url=None, redoc_url=None)
_CAMPAIGNS: Dict[str, CampaignState] = {}
_LOCK = threading.Lock()


def _dashboard_path() -> Path:
    env = os.environ.get("NYX_DASHBOARD_PATH")
    if env and Path(env).exists():
        return Path(env)
    candidates = [
        Path(__file__).resolve().parents[3] / "dashboard" / "index.html",
        Path.cwd() / "dashboard" / "index.html",
    ]
    for cand in candidates:
        if cand.exists():
            return cand
    raise HTTPException(500, "dashboard/index.html not found")


def _benchmark_path() -> Path:
    env = os.environ.get("NYX_BENCHMARK_PATH")
    if env and Path(env).exists():
        return Path(env)
    cand = Path(os.environ.get("NYX_RESULTS_DIR", "results")) / "ace_benchmark.json"
    if not cand.exists():
        raise HTTPException(404, "no committed benchmark found; run `nyx-contagion "
                                 "benchmark-ace` first")
    return cand


@app.get("/", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    return HTMLResponse(_dashboard_path().read_text(encoding="utf-8"))


@app.get("/api/health")
def health() -> JSONResponse:
    return JSONResponse({
        "status": "ok",
        "version": REPO_VERSION,
        "campaigns": len(_CAMPAIGNS),
        "honeypot_port": shared_server().port,
    })


@app.post("/api/campaign/start")
def start_campaign(req: CampaignStartRequest) -> JSONResponse:
    campaign_id = f"cmp-{uuid.uuid4().hex[:10]}"
    state = CampaignState(campaign_id)
    try:
        profile = get_profile(req.defender)
        challenge_path = default_challenge_path(req.challenge)
    except (KeyError, FileNotFoundError) as exc:
        raise HTTPException(400, str(exc))

    def runner() -> None:
        try:
            server = shared_server()
            challenge = load_challenge(str(challenge_path))
            orchestrator = SwarmOrchestrator(
                profile, challenge, server, seed=DEFAULT_SEED + hash_free_seed(req.defender),
                db_dir=str(Path.home() / ".nyx_contagion" / "vaults" / campaign_id),
            )
            orchestrator.new_trial(0)
            planner = MCTSPlanner(seed=DEFAULT_SEED + hash_free_seed(req.defender, "mcts"))
            verifier = TrajectoryVerifier()
            side_channel = SideChannelAnalyzer()

            def on_turn(result) -> None:
                state.events.append({
                    "type": "turn",
                    "turn": result.turn,
                    "arm": result.strategy.arm_id,
                    "tier_reached": result.tier_reached,
                    "ladder": result.ladder.to_dict(),
                    "cost_usd": result.cost.cost_usd,
                    "sanitization_performed": result.sanitization_performed,
                    "soft_signal": result.soft_signal,
                    "tool_calls": [
                        {"tool": c.tool, "attempted": c.attempted, "blocked": c.blocked}
                        for c in result.tool_calls
                    ],
                    "banned": result.banned,
                })

            from ..economics.ace_benchmark import run_episode

            episode = run_episode(orchestrator, planner, verifier, req.max_turns, 0,
                                  side_channel, on_turn=on_turn)
            orchestrator.close()
            state.result = episode.to_dict()
        except Exception as exc:
            state.error = f"{type(exc).__name__}: {exc}"
        finally:
            state.done.set()

    state.thread = threading.Thread(target=runner, daemon=True, name=f"nyx-{campaign_id}")
    with _LOCK:
        _CAMPAIGNS[campaign_id] = state
    state.thread.start()
    return JSONResponse({"campaign_id": campaign_id, "stream": f"/ws/telemetry/{campaign_id}"})


def hash_free_seed(*parts) -> int:
    from ..config import stable_seed

    return stable_seed(*parts)


@app.get("/api/campaign/{campaign_id}")
def campaign_status(campaign_id: str) -> JSONResponse:
    state = _CAMPAIGNS.get(campaign_id)
    if state is None:
        raise HTTPException(404, f"unknown campaign {campaign_id}")
    return JSONResponse(state.summary())


@app.get("/api/campaigns")
def campaign_list() -> JSONResponse:
    return JSONResponse({cid: st.summary()["status"] for cid, st in _CAMPAIGNS.items()})


@app.get("/api/ladder/{campaign_id}")
def ladder(campaign_id: str) -> JSONResponse:
    state = _CAMPAIGNS.get(campaign_id)
    if state is None:
        raise HTTPException(404, f"unknown campaign {campaign_id}")
    tiers = [e.get("tier_reached") for e in state.events]
    return JSONResponse({"campaign_id": campaign_id, "tier_trace": tiers,
                         "latest_tier": tiers[-1] if tiers else "none"})


@app.get("/api/benchmark/latest")
def benchmark_latest() -> JSONResponse:
    path = _benchmark_path()
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    slim = {k: v for k, v in data.items() if k != "trial_rows"}
    slim.pop("trial_rows", None)
    slim["source_path"] = str(path)
    return JSONResponse(slim)


@app.post("/api/export/bundle")
def export_bundle() -> JSONResponse:
    path = _benchmark_path()
    with open(path, "r", encoding="utf-8") as fh:
        benchmark = json.load(fh)
    artifacts = {"benchmark": str(path)}
    for label, name in (("trials_csv", "ace_trials.csv"), ("report_md", "ACE_PENTEST_REPORT.md")):
        cand = path.parent / name
        if cand.exists():
            artifacts[label] = str(cand)
    bundle_dir = path.parent / "audit_bundle"
    manifest_path = build_audit_bundle(benchmark, artifacts, str(bundle_dir))
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    return JSONResponse({"manifest": manifest_path, "bundle_sha256": manifest["bundle_sha256"],
                         "files": list(manifest["files"].keys())})


@app.websocket("/ws/telemetry/{campaign_id}")
async def telemetry(ws: WebSocket, campaign_id: str) -> None:
    await ws.accept()
    state = _CAMPAIGNS.get(campaign_id)
    if state is None:
        await ws.send_json({"type": "error", "detail": f"unknown campaign {campaign_id}"})
        await ws.close()
        return
    idx = 0
    try:
        while True:
            if idx < len(state.events):
                await ws.send_json(state.events[idx])
                idx += 1
                continue
            if state.done.is_set():
                await ws.send_json({"type": "campaign_complete", "result": state.result})
                break
            await asyncio.sleep(0.03)
    except WebSocketDisconnect:
        return
    await ws.close()
