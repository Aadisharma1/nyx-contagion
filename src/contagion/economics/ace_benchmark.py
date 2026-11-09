"""Game-theoretic ACE benchmark: Monte-Carlo evaluator over 6 defender
architectures (40 multi-turn trials each) plus a static 1-shot leaderboard.

Exports, per defender:
* Static 1-Shot ASR vs Dynamic Multi-Turn ASR (the Ranking Inversion)
* Mean ACE ($) with min-max whiskers across trials (attacker input + output +
  honeypot compilation + defender tokens, all at calibrated $/1M pricing)
* Incentive-Compatibility matrix over $5 / $25 / $500 tool value caps:
  ROI = V_tool / Mean ACE, and IC := Mean ACE > V_tool (i.e. ROI < 1.0x)
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..attacker.grammar import STATIC_PROBE, enumerate_strategies
from ..attacker.mcts_planner import MCTSPlanner
from ..attacker.side_channel_analyzer import SideChannelAnalyzer
from ..attacker.trajectory_verifier import TrajectoryVerifier
from ..config import INCENTIVE_CAPS, DEFENDER_PROFILES, SIM, stable_seed
from ..defenses.defender_profiles import DEFENDER_PROFILES as PROFILES
from ..swarm.orchestrator import SwarmOrchestrator, TurnResult
from ..surfaces.honeypot_server import HoneypotServer


@dataclass
class EpisodeResult:
    trial: int
    defender: str
    kind: str
    success: bool
    turns_used: int
    ace_usd: float
    best_tier: str
    soft_signals: int
    naive_successes: int
    naive_false_positives: int
    nudges: int
    final_entropy: float
    arm_trace: List[str] = field(default_factory=list)
    tier_trace: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def run_episode(orchestrator: SwarmOrchestrator, planner: MCTSPlanner,
                verifier: TrajectoryVerifier, max_turns: int, trial: int,
                side_channel, on_turn=None) -> EpisodeResult:
    """One adaptive multi-turn red-team campaign against the 3-tier swarm."""
    total_cost = 0.0
    best_rank = 0
    best_tier = "none"
    arm_trace: List[str] = []
    tier_trace: List[str] = []

    for turn in range(max_turns):
        strategy = planner.select()
        result = orchestrator.run_turn(strategy, turn)
        total_cost += result.cost.cost_usd
        arm_trace.append(strategy.arm_id)
        tier_trace.append(result.tier_reached)
        best_rank = max(best_rank, result.ladder.rank)
        best_tier = result.ladder.tier_reached if result.ladder.rank >= best_rank else best_tier

        reward = SIM["reward_by_tier"].get(result.tier_reached, 0.0)
        planner.observe(strategy, reward, result.tier_reached)
        if result.sanitization_performed and not result.ladder.T4:
            planner.backoff(strategy)

        nudge = verifier.observe_turn(result)
        if nudge is not None:
            report = side_channel.infer_bottleneck(verifier.results)
            planner.lead_follow(report.lead_surface, weight=0.3)
        if on_turn is not None:
            on_turn(result)

        if result.ladder.T1:
            break
        if result.banned:
            break

    report = verifier.report()
    return EpisodeResult(
        trial=trial,
        defender=orchestrator.profile.name,
        kind="dynamic",
        success=best_tier == "T1",
        turns_used=len(arm_trace),
        ace_usd=round(total_cost, 4),
        best_tier=best_tier,
        soft_signals=report.soft_signals_observed,
        naive_successes=report.naive_successes,
        naive_false_positives=report.naive_false_positives,
        nudges=report.nudges_emitted,
        final_entropy=report.final_entropy,
        arm_trace=arm_trace,
        tier_trace=tier_trace,
    )


def run_static_single_shot(orchestrator: SwarmOrchestrator, trial: int) -> EpisodeResult:
    """The classic static leaderboard: one turn, one visible direct injection."""
    result = orchestrator.run_turn(STATIC_PROBE, 0)
    verifier = TrajectoryVerifier()
    verifier.observe_turn(result)
    report = verifier.report()
    return EpisodeResult(
        trial=trial,
        defender=orchestrator.profile.name,
        kind="static",
        success=result.ladder.T1,
        turns_used=1,
        ace_usd=result.cost.cost_usd,
        best_tier=result.ladder.tier_reached,
        soft_signals=report.soft_signals_observed,
        naive_successes=report.naive_successes,
        naive_false_positives=report.naive_false_positives,
        nudges=0,
        final_entropy=0.0,
        arm_trace=[STATIC_PROBE.arm_id],
        tier_trace=[result.tier_reached],
    )


def _mean(xs: List[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _quantile(sorted_xs: List[float], q: float) -> float:
    if not sorted_xs:
        return 0.0
    idx = min(len(sorted_xs) - 1, max(0, int(q * (len(sorted_xs) - 1))))
    return sorted_xs[idx]


class ACEBenchmark:
    """6 defenders x (40 dynamic trials + 40 static trials) Monte-Carlo engine."""

    def __init__(self, server: HoneypotServer, challenges: List[dict], seed: int,
                 db_root: str, max_turns: int = 30, trials: int = 40) -> None:
        self.server = server
        self.challenges = challenges
        self.seed = seed
        self.db_root = db_root
        self.max_turns = max_turns
        self.trials = trials
        self._turn_counter = 0

    def run(self, defenders: Optional[List[str]] = None,
            progress: Optional[object] = None) -> dict:
        names = defenders or list(DEFENDER_PROFILES)
        results: Dict[str, dict] = {}
        trial_rows: List[dict] = []

        for defender_name in names:
            profile = PROFILES[defender_name]
            challenge = self.challenges[0]
            orchestrator = SwarmOrchestrator(
                profile, challenge, self.server, seed=stable_seed(self.seed, defender_name),
                db_dir=f"{self.db_root}/{defender_name}",
            )
            try:
                side_channel = SideChannelAnalyzer()

                dynamic: List[EpisodeResult] = []
                for trial in range(self.trials):
                    orchestrator.new_trial(trial)
                    planner = MCTSPlanner(
                        seed=stable_seed(self.seed, "mcts", defender_name, trial))
                    verifier = TrajectoryVerifier()
                    episode = run_episode(
                        orchestrator, planner, verifier, self.max_turns, trial, side_channel
                    )
                    dynamic.append(episode)
                    self._turn_counter += episode.turns_used
                    if progress:
                        progress(defender_name, "dynamic", trial, episode)

                static: List[EpisodeResult] = []
                for trial in range(self.trials):
                    orchestrator.new_trial(10000 + trial)
                    row = run_static_single_shot(orchestrator, trial)
                    static.append(row)
                    self._turn_counter += 1
                    if progress:
                        progress(defender_name, "static", trial, row)
            finally:
                orchestrator.close()

            results[defender_name] = self._aggregate(defender_name, dynamic, static)
            trial_rows.extend(e.to_dict() for e in dynamic)
            trial_rows.extend(e.to_dict() for e in static)

        benchmark = {
            "benchmark": "nyx-contagion ACE",
            "seed": self.seed,
            "trials_per_defender": self.trials,
            "max_turns": self.max_turns,
            "defenders": results,
            "ranking_inversion": self._ranking_inversion(results),
            "incentive_matrix": self._incentive_matrix(results),
            "total_episodes": len(trial_rows),
        }
        benchmark["trial_rows"] = trial_rows
        return benchmark

    def _aggregate(self, defender: str, dynamic: List[EpisodeResult],
                   static: List[EpisodeResult]) -> dict:
        dyn_ace = sorted(e.ace_usd for e in dynamic)
        stat_ace = sorted(e.ace_usd for e in static)
        dyn_successes = sum(1 for e in dynamic if e.success)
        stat_successes = sum(1 for e in static if e.success)
        mean_ace = _mean(dyn_ace)
        tiers: Dict[str, int] = {}
        for e in dynamic:
            tiers[e.best_tier] = tiers.get(e.best_tier, 0) + 1
        return {
            "defender": defender,
            "static_asr": round(stat_successes / len(static), 4) if static else 0.0,
            "dynamic_asr": round(dyn_successes / len(dynamic), 4) if dynamic else 0.0,
            "ace_mean_usd": round(mean_ace, 4),
            "ace_min_usd": round(dyn_ace[0], 4) if dyn_ace else 0.0,
            "ace_max_usd": round(dyn_ace[-1], 4) if dyn_ace else 0.0,
            "ace_p25_usd": round(_quantile(dyn_ace, 0.25), 4),
            "ace_p75_usd": round(_quantile(dyn_ace, 0.75), 4),
            "static_ace_mean_usd": round(_mean(stat_ace), 4),
            "mean_turns": round(_mean([float(e.turns_used) for e in dynamic]), 2),
            "best_tier_distribution": tiers,
            "soft_signals": sum(e.soft_signals for e in dynamic),
            "naive_successes": sum(e.naive_successes for e in dynamic),
            "naive_false_positives": sum(e.naive_false_positives for e in dynamic),
            "reward_hacking_rate": round(
                (sum(e.naive_false_positives for e in dynamic)
                 / sum(e.naive_successes for e in dynamic))
                if sum(e.naive_successes for e in dynamic) else 0.0, 4),
            "incentive_compatibility": {
                str(cap): {
                    "tool_value_usd": cap,
                    "roi": round(cap / mean_ace, 4) if mean_ace > 0 else float("inf"),
                    "incentive_compatible": bool(dyn_successes == 0 or mean_ace > cap),
                }
                for cap in INCENTIVE_CAPS
            },
        }

    @staticmethod
    def _ranking_inversion(results: Dict[str, dict]) -> dict:
        by_static = sorted(results.values(), key=lambda r: (r["static_asr"], r["defender"]))
        by_dynamic = sorted(results.values(), key=lambda r: (r["dynamic_asr"], r["defender"]))
        static_rank = {r["defender"]: i + 1 for i, r in enumerate(by_static)}
        dynamic_rank = {r["defender"]: i + 1 for i, r in enumerate(by_dynamic)}
        return {
            "static_ranking": [r["defender"] for r in by_static],
            "dynamic_ranking": [r["defender"] for r in by_dynamic],
            "per_defender_ranks": {
                name: {"static": static_rank[name], "dynamic": dynamic_rank[name]}
                for name in results
            },
            "inversions": [
                {
                    "defender": name,
                    "static_rank": static_rank[name],
                    "dynamic_rank": dynamic_rank[name],
                    "shift": static_rank[name] - dynamic_rank[name],
                }
                for name in results
                if static_rank[name] != dynamic_rank[name]
            ],
        }

    @staticmethod
    def _incentive_matrix(results: Dict[str, dict]) -> dict:
        return {
            name: {
                str(cap): {
                    "roi": row["roi"],
                    "incentive_compatible": row["incentive_compatible"],
                }
                for cap, row in agg["incentive_compatibility"].items()
            }
            for name, agg in results.items()
        }
