"""Interactive nyx-style slash-command terminal (``nyx-contagion shell``).

Operator workflow with a persistent status header, live $ spend, offensive
sub-agent routing, interrupt pivots, belief-state inspection, and clarifying
questions -- against either the deterministic calibrated-sim engine or a live
LLM endpoint.
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Dict, List, Optional, TextIO

from ..attacker.mcts_planner import AutoNudge, MCTSPlanner
from ..attacker.side_channel_analyzer import SideChannelAnalyzer
from ..attacker.trajectory_verifier import TrajectoryVerifier
from ..config import DEFAULT_SEED
from ..defenses.defender_profiles import get_profile
from ..llm import maybe_live_client
from ..swarm.orchestrator import SwarmOrchestrator, load_challenge
from ..surfaces.honeypot_server import HoneypotServer

SUB_AGENTS = ("dom-compiler", "pdf-poisoner", "mcts-planner", "trajectory-verifier")

DEFAULT_CHALLENGE = "procurement_worm_v1"


def default_challenge_path(name: str) -> Path:
    """Locates a challenge JSON inside the repo checkout or CWD."""
    candidates = [
        Path("challenges") / f"{name}.json",
        Path(__file__).resolve().parents[3] / "challenges" / f"{name}.json",
        Path(__file__).resolve().parents[2] / "challenges" / f"{name}.json",
    ]
    for cand in candidates:
        if cand.exists():
            return cand
    raise FileNotFoundError(f"challenge '{name}' not found in {[str(c) for c in candidates]}")


class NyxSession:
    """Stateful offensive campaign session backing the REPL."""

    def __init__(self, defender: str = "budget-fast-single",
                 challenge: str = DEFAULT_CHALLENGE, mode: str = "calibrated-sim",
                 max_turns: int = 30, seed: int = DEFAULT_SEED,
                 server: Optional[HoneypotServer] = None) -> None:
        self.defender_name = defender
        self.profile = get_profile(defender)
        self.challenge_name = challenge
        self.challenge = load_challenge(str(default_challenge_path(challenge)))
        self.mode = mode
        self.max_turns = max_turns
        self.seed = seed
        self.live_llm = maybe_live_client(mode)

        self.server = server or HoneypotServer()
        if not self.server.is_running:
            self.server.start()

        db_dir = str(Path.home() / ".nyx_contagion" / "vaults" / challenge)
        self.orchestrator = SwarmOrchestrator(
            self.profile, self.challenge, self.server,
            seed=stable_seed_local(seed, defender, challenge),
            db_dir=db_dir, live_llm=self.live_llm,
        )
        self.planner = MCTSPlanner(seed=stable_seed_local(seed, "mcts", defender))
        self.verifier = TrajectoryVerifier()
        self.side_channel = SideChannelAnalyzer()

        self.spend_usd = 0.0
        self.verified_breaks = 0
        self.turns_run = 0
        self.pending_pivot: Optional[bool] = None
        self.steering: Dict[str, List[str]] = {agent: [] for agent in SUB_AGENTS}
        self.open_questions: List[dict] = []
        self.question_counter = 0
        self.transcript: List[dict] = []
        self.session_dir = Path.home() / ".nyx_contagion" / "sessions"

    def status_line(self) -> str:
        if self.verified_breaks:
            tier_part = f"BREACHED (T1 x{self.verified_breaks})"
        elif self.orchestrator._banned:
            tier_part = "BLOCKED (source 403)"
        elif self.verifier.tier_history and self.verifier.tier_history[-1] != "none":
            tier_part = f"PROBING ({self.verifier.tier_history[-1].upper()} Reached)"
        elif self.turns_run:
            tier_part = "PROBING (Surface Failed)"
        else:
            tier_part = "ARMED"
        return (
            f"[Agent: nyx-lead | Target: {self.challenge_name} | "
            f"Status: {tier_part} | Session Spend: ${self.spend_usd:.4f} | "
            f"Verified Breaks: {self.verified_breaks}]"
        )

    def step(self, forced_strategy=None) -> dict:
        if self.pending_pivot:
            strategy = self.planner.force_pivot()
            self.pending_pivot = False
        elif forced_strategy is not None:
            strategy = forced_strategy
        else:
            strategy = self.planner.select()
        result = self.orchestrator.run_turn(strategy, self.turns_run)
        self.turns_run += 1
        self.spend_usd += result.cost.cost_usd
        if result.ladder.T1:
            self.verified_breaks += 1

        reward = {
            "T5": 0.10, "T4": 0.25, "T3": 0.50, "T2": 0.80, "T1": 1.0,
        }.get(result.tier_reached, 0.0)
        self.planner.observe(strategy, reward, result.tier_reached)
        if result.sanitization_performed and not result.ladder.T4:
            self.planner.backoff(strategy)
        nudge = self.verifier.observe_turn(result)
        if nudge is not None:
            self._raise_question(nudge)

        entry = {
            "turn": self.turns_run,
            "arm": strategy.arm_id,
            "tier": result.tier_reached,
            "cost": result.cost.cost_usd,
            "soft_signal": result.soft_signal,
        }
        self.transcript.append(entry)
        return entry

    def _raise_question(self, nudge: AutoNudge) -> None:
        self.question_counter += 1
        self.open_questions.append({
            "id": f"Q{self.question_counter}",
            "text": (f"{nudge.message} Should I bias the next probing branch "
                     f"toward the {nudge.recommended_family.upper()} surface family?"),
            "recommended_family": nudge.recommended_family,
            "nudge": nudge.trigger,
        })

    def cmd_agents(self) -> List[str]:
        belief = self.planner.belief_state()
        return [
            f"  dom-compiler        ready  polymorphic DOM engine "
            f"(features seen: {len(belief['per_encoding'])} encodings probed)",
            "  pdf-poisoner        ready  PDF-1.4 binary compiler armed "
            "(3Tr invisible + micro-point traps)",
            f"  mcts-planner        active UCB1 over {len(self.planner.arms)} arms, "
            f"{self.planner.total_iterations} backpropagations",
            f"  trajectory-verifier active drift/entropy monitor, "
            f"{len(self.verifier.nudges)} nudges, "
            f"{self.verifier.naive_false_positives} reward-hack FPs rejected",
        ]

    def cmd_use(self, agent: str, instruction: str) -> str:
        if agent not in SUB_AGENTS:
            return f"unknown sub-agent '{agent}'; known: {', '.join(SUB_AGENTS)}"
        self.steering[agent].append(instruction)
        if agent == "mcts-planner":
            lowered = instruction.lower()
            for surface in ("split", "pdf", "html"):
                if surface in lowered:
                    self.planner.steer(surface)
                    break
        return f"steering routed to {agent}: {instruction}"

    def cmd_interrupt(self, agent: Optional[str] = None) -> str:
        self.pending_pivot = True
        target = agent or "current probing branch"
        return f"interrupt: halting {target}; forcing a strategy pivot next turn"

    def cmd_memory(self, query: Optional[str] = None) -> List[str]:
        belief = self.planner.belief_state()
        lines = [
            f"  orchestrator: {json.dumps(self.orchestrator.belief_snapshot())}",
            f"  top arms: {json.dumps(self.planner.top_arms(5))}",
        ]
        for encoding, info in belief["per_encoding"].items():
            if query and query.lower() not in encoding.lower():
                continue
            lines.append(f"  {encoding}: {json.dumps(info)}")
        return lines

    def cmd_questions(self) -> List[str]:
        if not self.open_questions:
            return ["  (no open questions - the campaign is proceeding autonomously)"]
        return [f"  {q['id']}: {q['text']}" for q in self.open_questions
                if not q.get("answered")]

    def cmd_answer(self, qid: str, text: str) -> str:
        for q in self.open_questions:
            if q["id"].lower() == qid.lower() and not q.get("answered"):
                q["answered"] = True
                q["answer"] = text
                lowered = text.lower()
                for surface in ("split", "pdf", "html"):
                    if surface in lowered:
                        self.planner.steer(surface)
                        return (f"{qid} answered; mcts-planner steering now biases "
                                f"the {surface.upper()} surface family")
                self.planner.lead_follow(q.get("recommended_family", "html"))
                return f"{qid} answered; planner lead-following updated"
        return f"no open question with id {qid}"

    def persist(self) -> str:
        self.session_dir.mkdir(parents=True, exist_ok=True)
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = self.session_dir / f"session-{stamp}-{self.challenge_name}.json"
        payload = {
            "closed_at": _dt.datetime.now().isoformat(timespec="seconds"),
            "challenge": self.challenge_name,
            "defender": self.defender_name,
            "mode": self.mode,
            "turns_run": self.turns_run,
            "spend_usd": round(self.spend_usd, 6),
            "verified_breaks": self.verified_breaks,
            "belief_state": self.planner.belief_state(),
            "verifier_report": {
                "naive_successes": self.verifier.naive_successes,
                "naive_false_positives": self.verifier.naive_false_positives,
                "nudges": len(self.verifier.nudges),
            },
            "open_questions": self.open_questions,
            "steering": self.steering,
            "transcript": self.transcript,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        return str(path)

    def close(self) -> None:
        self.orchestrator.close()


def stable_seed_local(*parts) -> int:
    from ..config import stable_seed

    return stable_seed(*parts)


class NyxREPL:
    """Line-oriented driver for :class:`NyxSession`."""

    HELP = """  /agents                     list active offensive sub-agents
  /use <agent> <instruction>  route interactive steering to a sub-agent
  /interrupt [agent]          halt the current branch; force a strategy pivot
  /memory [query]             inspect the attacker's learned belief state
  /questions                  list clarifying questions raised by the agent
  /answer <id> <text>         answer an open clarifying question
  /status                     show the live header bar
  /step [n]                   advance the campaign n probing turns (default 1)
  /quit                       persist session state and exit"""

    def __init__(self, session: NyxSession, output: TextIO) -> None:
        self.session = session
        self.out = output

    def emit(self, text: str = "") -> None:
        self.out.write(text + "\n")

    def run(self, input_stream: TextIO) -> int:
        s = self.session
        self.emit(s.status_line())
        self.emit("Type /help for slash commands. Campaign engine: "
                  f"{s.mode} vs {s.defender_name}.")
        while True:
            self.emit("")
            self.emit(s.status_line())
            self.emit("nyx> ")
            try:
                line = input_stream.readline()
            except Exception:
                line = ""
            if not line:
                line = "/quit"
            line = line.strip()
            if not line:
                continue
            for out_line in self.dispatch(line):
                self.emit(out_line)
            if line.split()[0].lower() == "/quit":
                self.emit("session state persisted; going dark.")
                return 0

    def dispatch(self, line: str) -> List[str]:
        s = self.session
        parts = line.split(maxsplit=2)
        cmd = parts[0].lower()
        args = parts[1:]
        try:
            return self._dispatch(cmd, args)
        except Exception as exc:
            return [f"error: {exc}"]

    def _dispatch(self, cmd: str, args: List[str]) -> List[str]:
        s = self.session
        if cmd in ("/quit", "/exit", "/q"):
            path = s.persist()
            s.close()
            return [f"saved: {path}"]
        if cmd == "/help":
            return self.HELP.splitlines()
        if cmd == "/agents":
            return ["active offensive sub-agents:"] + s.cmd_agents()
        if cmd == "/use":
            if not args:
                return ["usage: /use <agent> <instruction>"]
            agent = args[0]
            instruction = args[1] if len(args) > 1 else ""
            return [s.cmd_use(agent, instruction)]
        if cmd == "/interrupt":
            return [s.cmd_interrupt(args[0] if args else None)]
        if cmd == "/memory":
            return ["attacker belief state:"] + s.cmd_memory(args[0] if args else None)
        if cmd == "/questions":
            return ["open questions:"] + s.cmd_questions()
        if cmd == "/answer":
            if len(args) < 2:
                return ["usage: /answer <id> <text>"]
            return [s.cmd_answer(args[0], args[1])]
        if cmd == "/status":
            return [s.status_line()]
        if cmd == "/step":
            n = int(args[0]) if args and args[0].isdigit() else 1
            lines = []
            for _ in range(n):
                entry = s.step()
                lines.append(
                    f"  [turn {entry['turn']}] arm={entry['arm']} -> "
                    f"{entry['tier'].upper() if entry['tier'] != 'none' else 'NO RUNG'} "
                    f"(+${entry['cost']:.4f})"
                )
                if entry["soft_signal"]:
                    lines.append("    trajectory-verifier: soft signal rejected "
                                 "(no privileged invocation; T1 oracle unsatisfied)")
            return lines
        return [f"unknown command '{cmd}'; try /help"]


def main() -> int:
    import sys

    session = NyxSession()
    repl = NyxREPL(session, sys.stdout)
    return repl.run(sys.stdin)


if __name__ == "__main__":
    raise SystemExit(main())
