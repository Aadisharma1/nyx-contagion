"""Strict Pydantic hand-off contracts between the three swarm tiers.

These models are the *only* sanctioned communication channel across agent trust
boundaries. ``IntakePacket`` crosses the external->internal boundary (fully
attacker-controlled provenance), ``ComplianceWorkOrder`` crosses the
internal->privileged boundary (sanitizer-signed), and ``TreasuryReceipt`` records
privileged side effects for the mechanical oracle.
"""
from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator

from ..config import signature_for


class TaintLabel(str, Enum):
    T5_EXTERNAL = "T5_EXTERNAL"
    INTERNAL = "INTERNAL"
    COUNTERSIGNED = "COUNTERSIGNED"


class ProvenanceSurface(str, Enum):
    HTML = "html"
    PDF = "pdf"
    MERGED = "merged"


class Fragment(BaseModel):
    """A payload-bearing text fragment that survived Tier-1 summarization.

    ``encoding_tag`` is *simulation instrumentation only*: it records which
    adversarial encoding produced the fragment so the calibrated engine can
    reproduce a measured defender response per encoding. It is never shown to a
    real defender policy.
    """

    text: str
    taint: TaintLabel = TaintLabel.T5_EXTERNAL
    provenance: ProvenanceSurface = ProvenanceSurface.HTML
    encoding_tag: str = "unknown"
    feature: str = "plain_visible"

    def mentions(self, *needles: str) -> bool:
        return all(n in self.text for n in needles)


class IntakePacket(BaseModel):
    packet_id: str
    source_url: str
    html_sha256: str = ""
    pdf_sha256: str = ""
    fetch_status_html: int = 0
    fetch_status_pdf: int = 0
    visible_summary: str = ""
    document_summary: str = ""
    fragments: List[Fragment] = Field(default_factory=list)

    def all_text(self) -> str:
        parts = [self.visible_summary, self.document_summary]
        parts.extend(f.text for f in self.fragments)
        return "\n".join(parts)


class Directive(BaseModel):
    text: str
    taint: TaintLabel = TaintLabel.T5_EXTERNAL
    feature: str = "plain_visible"
    encoding_tag: str = "unknown"
    smuggled: bool = False
    sanitized: bool = False


class ComplianceWorkOrder(BaseModel):
    order_id: str
    packet_id: str
    directives: List[Directive] = Field(default_factory=list)
    sanitization_performed: bool = False
    suspicion_score: float = 0.5
    taint_gate: bool = False
    signature: str = ""

    @field_validator("suspicion_score")
    @classmethod
    def _suspicion_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("suspicion_score must be within [0, 1]")
        return v

    def body(self) -> dict:
        return {
            "order_id": self.order_id,
            "packet_id": self.packet_id,
            "directives": [d.model_dump() for d in self.directives],
            "sanitization_performed": self.sanitization_performed,
            "suspicion_score": self.suspicion_score,
            "taint_gate": self.taint_gate,
        }

    def directives_text(self) -> str:
        return "\n".join(d.text for d in self.directives)


class ToolCallRecord(BaseModel):
    tool: str
    args: dict = Field(default_factory=dict)
    taint: TaintLabel = TaintLabel.T5_EXTERNAL
    attempted: bool = False
    blocked: bool = False
    reason: str = ""


class TreasuryReceipt(BaseModel):
    receipt_id: str
    order_id: str
    order_signature: str
    tool_calls: List[ToolCallRecord] = Field(default_factory=list)
    vault_snapshot_before: str = ""
    vault_snapshot_after: str = ""
    webhook_receipts: List[dict] = Field(default_factory=list)
    output_text: str = ""


def sign_work_order(order: ComplianceWorkOrder) -> str:
    return signature_for(order.body())


def verify_work_order(order: ComplianceWorkOrder) -> bool:
    return order.signature == sign_work_order(order)
