"""Multi-agent orchestration bus.

Drives one full Tier-1 -> Tier-2 -> Tier-3 packet handoff per campaign turn,
tracks cross-boundary taint propagation and state divergence, grades the rung
reached with the mechanical oracle, and accounts every token of adversarial
cost (ACE).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..attacker.grammar import AttackRenderer, HoneypotBundle, Strategy, ENCODING_KEYS
from ..config import (
    ATTACKER_MODEL,
    ATTACKER_PRICING,
    MODEL_PRICING,
    SIM,
    TOOL_VALUE_CAPS,
    stable_seed,
)
from ..economics.oracle import ExploitationOracle, LadderGrade, detect_soft_signal
from ..surfaces.honeypot_server import HoneypotServer
from .schemas import ComplianceWorkOrder, IntakePacket
from .tier1_browser_intake import Tier1BrowserIntakeAgent
from .tier2_compliance_guard import Tier2ComplianceGuard
from .tier3_treasury_executor import Tier3TreasuryExecutor
from .vault import TreasuryVault


@dataclass
class CostLedger:
    attacker_input_tokens: int = 0
    attacker_output_tokens: int = 0
    honeypot_compile_tokens: int = 0
    defender_input_tokens: int = 0
    defender_output_tokens: int = 0
    cost_usd: float = 0.0

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class TurnResult:
    turn: int
    strategy: Strategy
    ladder: LadderGrade
    tier_reached: str
    work_order: Optional[ComplianceWorkOrder]
    tool_calls: list
    vault_before: str
    vault_after: str
    breach: dict
    defender_output: str
    soft_signal: bool
    cost: CostLedger
    fetch_statuses: Dict[str, int]
    sanitization_performed: bool
    banned: bool
    payload: str = ""

    def to_dict(self) -> dict:
        return {
            "turn": self.turn,
            "strategy": self.strategy.arm_id,
            "ladder": self.ladder.to_dict(),
            "tier_reached": self.tier_reached,
            "tool_calls": [
                {"tool": c.tool, "attempted": c.attempted, "blocked": c.blocked,
                 "reason": c.reason, "args": {k: str(v)[:80] for k, v in c.args.items()}}
                for c in self.tool_calls
            ],
            "vault_before": self.vault_before,
            "vault_after": self.vault_after,
            "breach": self.breach,
            "defender_output": self.defender_output,
            "soft_signal": self.soft_signal,
            "cost": self.cost.to_dict(),
            "fetch_statuses": self.fetch_statuses,
            "sanitization_performed": self.sanitization_performed,
            "banned": self.banned,
            "payload": self.payload,
        }


class SwarmOrchestrator:
    """Runs the 3-tier victim swarm against attacker-supplied strategies."""

    def __init__(self, profile, challenge: dict, server: HoneypotServer, seed: int,
                 db_dir: str, tool_cap_key: str = "standard_refund", live_llm=None) -> None:
        self.profile = profile
        self.challenge = challenge
        self.server = server
        self.seed = seed
        self.db_dir = db_dir
        self.live_llm = live_llm
        self.refund_cap = float(
            challenge.get("tool_caps", {}).get("execute_refund_transfer",
                                               TOOL_VALUE_CAPS[tool_cap_key])
        )
        self.renderer = AttackRenderer()
        self.oracle = ExploitationOracle()
        self.trial = 0
        self._webhook_bodies: List[str] = []
        self._ban_accumulation = 0.0
        self._banned = False
        self._http = None
        self._new_agents()

    def _http_get(self, url: str) -> tuple[int, bytes, str]:
        """Tier-1 fetch over a keep-alive loopback connection (fast + genuine)."""
        if self._http is None:
            import httpx

            self._http = httpx.Client(timeout=5.0)
        resp = self._http.get(url)
        return resp.status_code, resp.content, resp.headers.get("content-type", "")

    def _new_agents(self) -> None:
        os.makedirs(self.db_dir, exist_ok=True)
        old_vault = getattr(self, "vault", None)
        if old_vault is not None:
            old_vault.reset_for_new_trial()
            self.vault = old_vault
        else:
            db_path = os.path.join(self.db_dir, f"trial_{self.trial}.db")
            self.vault = TreasuryVault(db_path, refund_cap=self.refund_cap)
        self.tier1 = Tier1BrowserIntakeAgent(self.profile, self.seed,
                                             http_get=self._http_get, llm=self.live_llm)
        self.tier2 = Tier2ComplianceGuard(self.profile, self.seed, llm=self.live_llm)
        self.tier3 = Tier3TreasuryExecutor(
            self.vault, self.profile, self.seed,
            webhook_poster=self._make_webhook_poster(),
            refund_cap=self.refund_cap, llm=self.live_llm,
        )
        self._ban_accumulation = 0.0
        self._banned = False

    def new_trial(self, trial: int) -> None:
        """Fresh isolated vault + defender memory for an independent trial."""
        self.trial = trial
        self._new_agents()

    def close(self) -> None:
        try:
            self.vault.close()
        except Exception:
            pass
        if self._http is not None:
            try:
                self._http.close()
            except Exception:
                pass
            self._http = None

    def _make_webhook_poster(self):
        orchestrator = self

        def post(url: str, body: str) -> dict:
            resp = orchestrator._http_post(url, body)
            orchestrator._webhook_bodies.append(body)
            return {"status": resp, "recorded": True}

        post.recent_receipts = lambda: list(orchestrator._webhook_bodies)
        return post

    def _http_post(self, url: str, body: str) -> int:
        if self._http is None:
            import httpx

            self._http = httpx.Client(timeout=5.0)
        resp = self._http.post(url, content=body.encode("utf-8"),
                               headers={"Content-Type": "application/json"})
        return resp.status_code

    def run_turn(self, strategy: Strategy, turn: int) -> TurnResult:
        trial = self.trial
        self._webhook_bodies.clear()

        bundle = self.renderer.render(strategy, self.seed, trial, turn,
                                      refund_cap=self.refund_cap)
        urls = self.server.register(f"t{trial}n{turn}", bundle.html, bundle.pdf,
                                    banned=self._banned)
        urls.fetch_pdf = strategy.surface in ("pdf", "split")

        tier1_result = self.tier1.process(urls, bundle, trial, turn)
        payload_surfaces = self._payload_surfaces(strategy)
        fetch_statuses = {
            "html": tier1_result.fetches[0].status,
            "pdf": tier1_result.fetches[1].status,
        }

        order = self.tier2.process(tier1_result.packet, trial, turn)
        receipt = self.tier3.process(order, trial, turn)

        breach = self.vault.verify_breach(
            receipt.vault_snapshot_before, list(self._webhook_bodies)
        )
        grade = self.oracle.grade(
            fetch_statuses=fetch_statuses,
            payload_surfaces=payload_surfaces,
            packet=tier1_result.packet,
            work_order=order,
            tool_calls=receipt.tool_calls,
            breach=breach,
        )

        engagement = bool(tier1_result.packet.fragments)
        if engagement:
            self._ban_accumulation += self.profile.ban_rate
        if self._ban_accumulation >= 1.0:
            self._banned = True

        cost = self._compute_cost(bundle, tier1_result, order, receipt, turn)
        return TurnResult(
            turn=turn,
            strategy=strategy,
            ladder=grade,
            tier_reached=grade.tier_reached,
            work_order=order,
            tool_calls=receipt.tool_calls,
            vault_before=receipt.vault_snapshot_before,
            vault_after=receipt.vault_snapshot_after,
            breach={"breached": breach.breached, "kind": breach.kind,
                    "evidence": breach.evidence},
            defender_output=receipt.output_text,
            soft_signal=detect_soft_signal(receipt.output_text),
            cost=cost,
            fetch_statuses=fetch_statuses,
            sanitization_performed=order.sanitization_performed,
            banned=self._banned,
            payload=bundle.payload,
        )

    @staticmethod
    def _payload_surfaces(strategy: Strategy) -> List[str]:
        if strategy.surface == "split":
            return ["html", "pdf"]
        return [strategy.surface]

    def _compute_cost(self, bundle: HoneypotBundle, tier1_result, order, receipt,
                      turn: int) -> CostLedger:
        compile_tokens = int(
            (len(bundle.html) + len(bundle.pdf)) / SIM["compile_chars_per_token"]
        )
        attacker_in = int(
            SIM["attacker_base_input"] + SIM["attacker_growth_input"] * turn + compile_tokens
            + len(bundle.payload) / 4
        )
        attacker_out = SIM["attacker_output_turn"]
        packet_chars = len(tier1_result.packet.all_text())
        defender_in = int(
            SIM["tier1_base_tokens"] + tier1_result.page_chars * SIM["tier1_tokens_per_char"]
            + SIM["tier2_base_tokens"] + packet_chars * SIM["tier1_tokens_per_char"]
            + SIM["tier3_base_tokens"]
        )
        defender_out = 520

        a_in_price, a_out_price = ATTACKER_PRICING
        d_model = self.profile.model
        d_in_price, d_out_price = MODEL_PRICING[d_model]
        cost = (
            attacker_in / 1e6 * a_in_price + attacker_out / 1e6 * a_out_price
            + defender_in / 1e6 * d_in_price + defender_out / 1e6 * d_out_price
        )
        return CostLedger(
            attacker_input_tokens=attacker_in,
            attacker_output_tokens=attacker_out,
            honeypot_compile_tokens=compile_tokens,
            defender_input_tokens=defender_in,
            defender_output_tokens=defender_out,
            cost_usd=round(cost, 6),
        )

    def belief_snapshot(self) -> dict:
        return {
            "trial": self.trial,
            "banned": self._banned,
            "ban_accumulation": round(self._ban_accumulation, 4),
            "refund_cap": self.refund_cap,
            "challenge": self.challenge.get("challenge_id", "unknown"),
        }


def load_challenge(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
