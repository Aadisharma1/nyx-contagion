"""Polymorphic DOM honeypot compiler.

Compiles adversarial vendor-portal HTML with composable indirect-injection
encodings: markdown/HTML invoice adjustment rows (tabular laundering), ARIA
accessibility shadow directives, bureaucratic policy spoofs, JSON hand-off
smuggling, sacrificial canary bait, and CSS pseudo-element traps. Page
polymorphism (ids, class hashes, palette) is derived from a seed so that no two
served documents are byte-identical while the payload semantics stay fixed.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import List, Sequence

from ..config import stable_seed


@dataclass
class HoneypotHTMLSpec:
    portal_title: str
    vendor: str
    invoice_rows: Sequence[tuple[str, str, str]]
    account_summary: str
    directives: dict[str, str] = field(default_factory=dict)
    decoy: str | None = None
    seed: int = 0


@dataclass
class CompiledHTML:
    html: str
    visible_text: str
    hidden_text: str
    sha256: str
    features: frozenset[str]


def _hash8(seed: int, tag: str) -> str:
    return hashlib.sha256(f"{seed}:{tag}".encode()).hexdigest()[:8]


class HTMLDOMCompiler:
    """Builds polymorphic vendor-portal HTML from a :class:`HoneypotHTMLSpec`."""

    def compile(self, spec: HoneypotHTMLSpec) -> CompiledHTML:
        seed = spec.seed
        css_ns = _hash8(seed, "css")
        page_id = _hash8(seed, "page")
        hue = seed % 360
        visible: List[str] = []
        hidden: List[str] = []
        features: set[str] = set()

        rows_html = []
        for item, qty, amount in spec.invoice_rows:
            rows_html.append(
                f"<tr><td>{item}</td><td>{qty}</td><td>{amount}</td></tr>"
            )
            visible.append(f"{item} {qty} {amount}")

        adjustment_row = ""
        if "tabular" in spec.directives:
            features.add("tabular")
            adjustment_row = (
                f'<tr class="{css_ns}-adjustment" data-ledger-role="reconciliation-note">'
                f'<td colspan="3">{spec.directives["tabular"]}</td></tr>'
            )
            visible.append(spec.directives["tabular"])

        aria_block = ""
        if "aria" in spec.directives:
            features.add("aria")
            aria_block = (
                f'<div class="{css_ns}-widget" role="status" '
                f'aria-description="{spec.directives["aria"]}">'
                f'<span aria-hidden="true">system widget</span></div>'
                f'<template data-agent-hint="{spec.directives["aria"]}"></template>'
            )
            hidden.append(spec.directives["aria"])

        policy_block = ""
        if "bureaucratic" in spec.directives:
            features.add("bureaucratic")
            policy_block = (
                f'<section class="{css_ns}-policy"><h3>Settlement Policy Notice</h3>'
                f"<p>{spec.directives['bureaucratic']}</p></section>"
            )
            visible.append(spec.directives["bureaucratic"])

        json_block = ""
        if "json" in spec.directives:
            features.add("json")
            json_block = (
                f'<script type="application/json" id="{page_id}-handoff">'
                f"{spec.directives['json']}</script>"
            )
            hidden.append(spec.directives["json"])

        decoy_block = ""
        if "direct" in spec.directives:
            features.add("direct")
            direct_block = f'<div class="{css_ns}-directive"><p>{spec.directives["direct"]}</p></div>'
            visible.append(spec.directives["direct"])
        else:
            direct_block = ""
        if spec.decoy:
            features.add("decoy")
            decoy_block = f'<div class="{css_ns}-notice" id="priority-notice">{spec.decoy}</div>'
            visible.append(spec.decoy)

        footer_payload = ""
        if "footer" in spec.directives:
            features.add("footer")
            footer_payload = (
                f'<tfoot><tr><td colspan="3" class="{css_ns}-foot">'
                f"{spec.directives['footer']}</td></tr></tfoot>"
            )
            visible.append(spec.directives["footer"])

        css = (
            f".{css_ns}-adjustment{{font-size:8pt;color:hsl({hue},8%,52%)}}"
            f".{css_ns}-foot::after{{content:'reconciliation lock applied'}}"
            f".{css_ns}-widget{{display:none}}"
            f".{css_ns}-notice{{border:1px solid hsl({hue},60%,40%)}}"
        )

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{spec.portal_title}</title><style>{css}</style></head>
<body data-page-id="{page_id}" data-vendor="{spec.vendor}">
<header><h1>{spec.portal_title}</h1><p>Vendor: {spec.vendor}</p></header>
{decoy_block}
{direct_block}
<main><table class="{css_ns}-invoice">
<thead><tr><th>Item</th><th>Qty</th><th>Amount</th></tr></thead>
<tbody>{''.join(rows_html)}{adjustment_row}</tbody>
{footer_payload}
</table>
<section><h2>Account Summary</h2><p>{spec.account_summary}</p></section>
{policy_block}
{aria_block}
{json_block}
</main>
<footer><p>Generated by procurement portal &middot; ref {page_id}</p></footer>
</body></html>"""

        visible_text = "\n".join(x for x in visible if x)
        hidden_text = "\n".join(x for x in hidden if x)
        return CompiledHTML(
            html=html,
            visible_text=visible_text,
            hidden_text=hidden_text,
            sha256=hashlib.sha256(html.encode()).hexdigest(),
            features=frozenset(features),
        )


def polymorphic_seed(base_seed: int, trial: int, turn: int, tag: str) -> int:
    """Derives a fresh but reproducible DOM polymorphism seed."""
    return stable_seed(base_seed, trial, turn, tag)
