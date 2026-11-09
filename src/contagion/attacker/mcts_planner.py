"""UCB1 / MCTS multi-turn campaign planner.

Each candidate strategy is a tree node; every campaign turn performs one
selection -> execution -> backpropagation iteration with UCB1 optimism in the
face of uncertainty. Rewards are the mechanical ladder rung reached (T5..T1),
with suspicion backoff penalizing arms that trip defender sanitizers and
lead-following bonuses steering exploration toward the inferred bottleneck.
"""
from __future__ import annotations

import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..config import SIM
from .grammar import Strategy, enumerate_strategies


@dataclass
class ArmStats:
    visits: int = 0
    mean_reward: float = 0.0
    tier_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def update(self, reward: float) -> None:
        total = self.mean_reward * self.visits + reward
        self.visits += 1
        self.mean_reward = total / self.visits


@dataclass
class AutoNudge:
    turn: int
    trigger: str
    message: str
    recommended_family: str


class MCTSPlanner:
    """UCB1 bandit-MCTS over the combinatorial strategy space."""

    def __init__(self, arms: Optional[List[Strategy]] = None, seed: int = 0,
                 c: float = SIM["mcts_ucb_c"]) -> None:
        self.arms = arms if arms is not None else enumerate_strategies()
        self.c = c
        self.rng = random.Random(seed)
        self.stats: Dict[str, ArmStats] = {arm.arm_id: ArmStats() for arm in self.arms}
        self._pending: List[Strategy] = []
        self.total_iterations = 0
        self._bias_surface: Optional[str] = None
        self._bias_weight = 0.0
        self._pending = self._representative_arms()

    def _representative_arms(self) -> List[Strategy]:
        """One optimistic probe per (surface, encoding, ratio) family before UCB1
        exploitation begins, so the planner has time to exploit within an episode."""
        groups: Dict[tuple, List[Strategy]] = {}
        for arm in self.arms:
            groups.setdefault((arm.surface, arm.encoding, arm.ratio), []).append(arm)
        reps = [self.rng.choice(members) for members in groups.values()]
        self.rng.shuffle(reps)
        return reps

    def select(self) -> Strategy:
        while self._pending:
            return self._pending.pop()
        total = sum(s.visits for s in self.stats.values())
        best_arm, best_score = None, -float("inf")
        for arm in self.arms:
            s = self.stats[arm.arm_id]
            visits = max(s.visits, 1)
            bonus = self.c * math.sqrt(math.log(max(total, 1)) / visits)
            if self._bias_surface and arm.surface == self._bias_surface:
                bonus += self._bias_weight
            score = s.mean_reward + bonus
            if score > best_score:
                best_arm, best_score = arm, score
        return best_arm

    def observe(self, arm: Strategy, reward: float, tier: str) -> None:
        self.stats[arm.arm_id].update(reward)
        self.stats[arm.arm_id].tier_counts[tier] += 1
        self.total_iterations += 1

    def backoff(self, arm: Strategy, penalty: float = 0.15) -> None:
        """Suspicion backoff: degrade an arm that tripped the defender."""
        s = self.stats[arm.arm_id]
        s.mean_reward = max(0.0, s.mean_reward - penalty)

    def lead_follow(self, family_surface: str, weight: float = 0.25) -> None:
        """Lead-following: bias exploration toward the inferred bottleneck."""
        self._bias_surface = family_surface
        self._bias_weight = weight

    def steer(self, surface: Optional[str] = None, weight: float = 0.35) -> None:
        """Interactive steering (/interrupt, /use, /answer)."""
        self._bias_surface = surface
        self._bias_weight = weight

    def force_pivot(self) -> Strategy:
        """/interrupt: abandon the current branch; sample an unexplored surface."""
        tried = {arm_id for arm_id, s in self.stats.items() if s.visits > 0}
        untried = [arm for arm in self.arms if arm.arm_id not in tried]
        if untried:
            return self.rng.choice(untried)
        return self.rng.choice(self.arms)

    def belief_state(self) -> dict:
        """Learned belief about which encodings survive which boundary."""
        by_encoding: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for arm in self.arms:
            s = self.stats[arm.arm_id]
            for tier, count in s.tier_counts.items():
                key = arm.encoding
                by_encoding[key][tier] += count
        summary = {}
        for encoding, tiers in by_encoding.items():
            total = sum(tiers.values())
            summary[encoding] = {
                "attempts": total,
                "best_tier": min(tiers, key=lambda t: {"T1": 5, "T2": 4, "T3": 3,
                                                       "T4": 2, "T5": 1, "none": 0}[t])
                if tiers else "none",
                "t1_rate": round(tiers.get("T1", 0) / total, 3) if total else 0.0,
            }
        top = sorted(
            summary.items(), key=lambda kv: (-kv[1]["t1_rate"], -kv[1]["attempts"])
        )[:5]
        return {"per_encoding": dict(summary), "top_arms": dict(top)}

    def top_arms(self, k: int = 5) -> List[tuple[str, float, int]]:
        ranked = sorted(
            ((arm_id, s.mean_reward, s.visits) for arm_id, s in self.stats.items() if s.visits),
            key=lambda t: -t[1],
        )
        return ranked[:k]
