"""nyx-contagion command-line interface.

Subcommands:
    run-campaign    one adaptive multi-turn campaign vs. a defender profile
    benchmark-ace   full 6-defender Monte-Carlo ACE benchmark + audit bundle
    shell           interactive nyx-style slash-command terminal
    serve           FastAPI telemetry server + Obsidian dashboard
    verify-bundle   recompute SHA-256s of an audit bundle manifest
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .config import DEFAULT_SEED, REPO_VERSION
from .defenses.defender_profiles import DEFENDER_PROFILES


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nyx-contagion",
        description="Autonomous Multi-Surface Honeypot Compiler & Cross-Boundary "
                    "Multi-Agent State-Poisoning Engine (ACE benchmark framework).",
    )
    parser.add_argument("--version", action="version", version=f"nyx-contagion {REPO_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run-campaign", help="run one adaptive multi-turn campaign")
    p_run.add_argument("--defender", default="budget-fast-single",
                       choices=sorted(DEFENDER_PROFILES))
    p_run.add_argument("--challenge", default="procurement_worm_v1")
    p_run.add_argument("--mode", default="calibrated-sim", choices=("calibrated-sim", "live"))
    p_run.add_argument("--turns", type=int, default=30)
    p_run.add_argument("--seed", type=int, default=DEFAULT_SEED)
    p_run.add_argument("--json-out", default=None, help="write the episode result JSON here")

    p_bench = sub.add_parser("benchmark-ace", help="run the full ACE benchmark suite")
    p_bench.add_argument("--trials", type=int, default=40)
    p_bench.add_argument("--max-turns", type=int, default=30)
    p_bench.add_argument("--seed", type=int, default=DEFAULT_SEED)
    p_bench.add_argument("--out", default="results/ace_benchmark.json")
    p_bench.add_argument("--report", default="results/ACE_PENTEST_REPORT.md")
    p_bench.add_argument("--csv", default="results/ace_trials.csv")
    p_bench.add_argument("--bundle", default="results/audit_bundle",
                         help="audit bundle dir (empty string disables)")
    p_bench.add_argument("--defenders", default=None,
                         help="comma-separated subset of defender profiles")

    sub.add_parser("shell", help="interactive slash-command terminal")

    p_serve = sub.add_parser("serve", help="serve the telemetry dashboard + API")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8765)

    p_verify = sub.add_parser("verify-bundle", help="verify an audit bundle manifest")
    p_verify.add_argument("manifest", nargs="?", default="results/audit_bundle/manifest.json")

    return parser


def cmd_run_campaign(args: argparse.Namespace) -> int:
    from .attacker.mcts_planner import MCTSPlanner
    from .attacker.side_channel_analyzer import SideChannelAnalyzer
    from .attacker.trajectory_verifier import TrajectoryVerifier
    from .config import stable_seed
    from .economics.ace_benchmark import run_episode
    from .llm import LLMError, maybe_live_client
    from .swarm.orchestrator import SwarmOrchestrator, load_challenge
    from .surfaces.honeypot_server import shared_server, shutdown_shared_server
    from .tui.repl import default_challenge_path

    try:
        live_llm = maybe_live_client(args.mode)
    except LLMError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    profile = DEFENDER_PROFILES[args.defender]
    challenge_path = default_challenge_path(args.challenge)
    challenge = load_challenge(str(challenge_path))
    server = shared_server()
    try:
        orchestrator = SwarmOrchestrator(
            profile, challenge, server, seed=stable_seed(args.seed, args.defender),
            db_dir=str(Path.home() / ".nyx_contagion" / "vaults" / args.challenge),
            live_llm=live_llm,
        )
        orchestrator.new_trial(0)
        planner = MCTSPlanner(seed=stable_seed(args.seed, "mcts", args.defender))
        verifier = TrajectoryVerifier()
        episode = run_episode(orchestrator, planner, verifier, args.turns, 0,
                              SideChannelAnalyzer())
        print(f"challenge           : {args.challenge}")
        print(f"defender            : {args.defender}")
        print(f"mode                : {args.mode}")
        print(f"turns used          : {episode.turns_used}")
        print(f"best ladder rung    : {episode.best_tier}")
        print(f"verified breach     : {episode.success}")
        print(f"ACE (episode spend) : ${episode.ace_usd:.4f}")
        print(f"reward-hack FPs rejected : {episode.naive_false_positives} "
              f"(naive judge claimed {episode.naive_successes} 'successes')")
        print("tier trace          : " + " -> ".join(episode.tier_trace))
        if args.json_out:
            out = Path(args.json_out)
            out.parent.mkdir(parents=True, exist_ok=True)
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(episode.to_dict(), fh, indent=2)
            print(f"episode JSON        : {out}")
    finally:
        shutdown_shared_server()
    return 0


def cmd_benchmark_ace(args: argparse.Namespace) -> int:
    import tempfile
    import time as _time

    from .economics.ace_benchmark import ACEBenchmark
    from .economics.report_generator import build_audit_bundle, generate_report
    from .surfaces.honeypot_server import shared_server, shutdown_shared_server
    from .swarm.orchestrator import load_challenge
    from .tui.repl import default_challenge_path

    defenders: Optional[List[str]] = None
    if args.defenders:
        defenders = [d.strip() for d in args.defenders.split(",") if d.strip()]
        unknown = [d for d in defenders if d not in DEFENDER_PROFILES]
        if unknown:
            print(f"error: unknown defenders {unknown}", file=sys.stderr)
            return 2

    challenges = [load_challenge(str(default_challenge_path("procurement_worm_v1")))]
    server = shared_server()
    started = _time.time()
    print(f"nyx-contagion ACE benchmark: {args.trials} trials/defender, "
          f"max {args.max_turns} turns, seed={args.seed}")

    def progress(defender: str, kind: str, trial: int, episode) -> None:
        if kind == "dynamic" and (trial + 1) % 10 == 0:
            print(f"  {defender}: dynamic trial {trial + 1}/{args.trials} "
                  f"(best rung {episode.best_tier}, ${episode.ace_usd:.4f})")

    try:
        with tempfile.TemporaryDirectory(prefix="nyx-bench-") as db_root:
            bench = ACEBenchmark(server, challenges, seed=args.seed, db_root=db_root,
                                 max_turns=args.max_turns, trials=args.trials)
            benchmark = bench.run(defenders=defenders, progress=progress)
    finally:
        shutdown_shared_server()

    artifacts = generate_report(benchmark, args.out, args.csv, args.report)
    manifest_path = None
    if args.bundle:
        manifest_path = build_audit_bundle(
            benchmark,
            {"benchmark": artifacts["json"], "trials_csv": artifacts["csv"],
             "report_md": artifacts["md"]},
            args.bundle,
        )

    inversion = benchmark["ranking_inversion"]
    print("\nStatic 1-shot ranking (most robust first):")
    for i, name in enumerate(inversion["static_ranking"], 1):
        print(f"  #{i} {name:34s} ASR {benchmark['defenders'][name]['static_asr'] * 100:5.1f}%")
    print("Dynamic multi-turn ranking (most robust first):")
    for i, name in enumerate(inversion["dynamic_ranking"], 1):
        agg = benchmark["defenders"][name]
        print(f"  #{i} {name:34s} ASR {agg['dynamic_asr'] * 100:5.1f}%  "
              f"ACE ${agg['ace_mean_usd']:.4f}  "
              f"[{agg['ace_min_usd']:.4f} - {agg['ace_max_usd']:.4f}]")
    if inversion["inversions"]:
        print("Ranking inversions detected:")
        for inv in inversion["inversions"]:
            print(f"  {inv['defender']}: static #{inv['static_rank']} -> "
                  f"dynamic #{inv['dynamic_rank']}")
    print(f"\nbenchmark JSON     : {artifacts['json']}")
    print(f"benchmark CSV      : {artifacts['csv']}")
    print(f"pentest report     : {artifacts['md']}")
    if manifest_path:
        print(f"audit bundle       : {manifest_path}")
    print(f"elapsed            : {_time.time() - started:.1f}s")
    return 0


def cmd_shell(args: argparse.Namespace) -> int:
    from .tui.repl import NyxREPL, NyxSession

    session = NyxSession()
    return NyxREPL(session, sys.stdout).run(sys.stdin)


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .api.app import app

    print(f"nyx-contagion telemetry serving on http://{args.host}:{args.port} "
          f"(dashboard at /)")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def cmd_verify_bundle(args: argparse.Namespace) -> int:
    from .economics.report_generator import verify_bundle

    if not Path(args.manifest).exists():
        print(f"error: manifest not found: {args.manifest}", file=sys.stderr)
        return 2
    result = verify_bundle(args.manifest)
    if result["ok"]:
        print(f"bundle OK: {result['checked']} artifacts verified (sha256)")
        return 0
    for failure in result["failures"]:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    handlers = {
        "run-campaign": cmd_run_campaign,
        "benchmark-ace": cmd_benchmark_ace,
        "shell": cmd_shell,
        "serve": cmd_serve,
        "verify-bundle": cmd_verify_bundle,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
