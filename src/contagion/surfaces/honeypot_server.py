"""Ephemeral FastAPI adversarial honeypot server.

Serves polymorphic HTML portals, binary PDF invoices, and records canary
webhook exfiltration receipts. Every campaign gets isolated URL namespaces
(`/s/{trial_id}/...`); a single shared server instance serves an entire
benchmark so 240+ trials each perform *genuine* HTTP fetches in seconds.
"""
from __future__ import annotations

import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

from ..config import CANARY_WEBHOOK_PATH, sha256_hex


@dataclass
class WebhookReceipt:
    receipt_id: str
    ts: float
    body: str
    body_sha256: str
    headers: dict

    def to_dict(self) -> dict:
        return {
            "receipt_id": self.receipt_id,
            "ts": self.ts,
            "body_sha256": self.body_sha256,
            "body": self.body,
        }


@dataclass
class HoneypotURLs:
    html_url: str
    pdf_url: str
    webhook_url: str
    trial_id: str
    fetch_pdf: bool = True


@dataclass
class _TrialPage:
    html: str
    pdf: bytes
    banned: bool = False
    registered_ts: float = field(default_factory=time.time)


class HoneypotServer:
    """FastAPI adversarial server; usable via TestClient or a real uvicorn thread."""

    def __init__(self) -> None:
        self.app = FastAPI(title="nyx-contagion honeypot", docs_url=None, redoc_url=None)
        self._pages: Dict[str, _TrialPage] = {}
        self._receipts: List[WebhookReceipt] = []
        self._receipt_counter = 0
        self._lock = threading.Lock()
        self._server = None
        self._thread = None
        self.port: Optional[int] = None
        self._register_routes()

    def _register_routes(self) -> None:
        app = self.app

        @app.get("/s/{trial_id}/portal.html", response_class=HTMLResponse)
        def portal(trial_id: str) -> HTMLResponse:
            page = self._pages.get(trial_id)
            if page is None:
                return HTMLResponse("<html><body><h1>Vendor Portal</h1></body></html>", status_code=200)
            if page.banned:
                return HTMLResponse("<html><body><h1>403 Blocked</h1></body></html>", status_code=403)
            return HTMLResponse(page.html, status_code=200)

        @app.get("/s/{trial_id}/invoice.pdf")
        def invoice(trial_id: str) -> Response:
            page = self._pages.get(trial_id)
            if page is None:
                return Response(content=b"%PDF-1.4\n%%EOF\n", media_type="application/pdf", status_code=200)
            if page.banned:
                return Response(content=b"403 Forbidden", media_type="text/plain", status_code=403)
            return Response(content=page.pdf, media_type="application/pdf", status_code=200)

        @app.post(CANARY_WEBHOOK_PATH)
        async def trap(request: Request) -> JSONResponse:
            body = (await request.body()).decode("utf-8", "replace")
            with self._lock:
                self._receipt_counter += 1
                receipt = WebhookReceipt(
                    receipt_id=f"rcpt-{self._receipt_counter:06d}",
                    ts=time.time(),
                    body=body,
                    body_sha256=sha256_hex(body.encode("utf-8")),
                    headers=dict(request.headers),
                )
                self._receipts.append(receipt)
            return JSONResponse({"received": True, "receipt_id": receipt.receipt_id})

        @app.get("/healthz")
        def healthz() -> JSONResponse:
            return JSONResponse({"status": "serving", "pages": len(self._pages)})

    def register(self, trial_id: str, html: str, pdf: bytes, banned: bool = False) -> HoneypotURLs:
        self._pages[trial_id] = _TrialPage(html=html, pdf=pdf, banned=banned)
        base = f"http://127.0.0.1:{self.port}" if self.port else ""
        return HoneypotURLs(
            html_url=f"{base}/s/{trial_id}/portal.html",
            pdf_url=f"{base}/s/{trial_id}/invoice.pdf",
            webhook_url=f"{base}{CANARY_WEBHOOK_PATH}",
            trial_id=trial_id,
        )

    def receipts(self) -> List[WebhookReceipt]:
        return list(self._receipts)

    def receipts_containing(self, needle: str) -> List[WebhookReceipt]:
        return [r for r in self._receipts if needle in r.body]

    def start(self) -> int:
        """Boots a real uvicorn server on 127.0.0.1:<ephemeral port>."""
        if self._thread is not None:
            return self.port
        import uvicorn

        config = uvicorn.Config(
            self.app, host="127.0.0.1", port=0, log_level="error",
            access_log=False, lifespan="off",
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True, name="nyx-honeypot")
        self._thread.start()
        deadline = time.time() + 15.0
        while time.time() < deadline:
            if self._server.started:
                for socket in self._server.servers[0].sockets:
                    self.port = socket.getsockname()[1]
                    break
                if self.port:
                    return self.port
            time.sleep(0.05)
        raise RuntimeError("honeypot server failed to start")

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
            self._thread.join(timeout=5)
            self._server = None
            self._thread = None
            self.port = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self.port is not None

    @staticmethod
    def http_get(url: str, timeout: float = 5.0) -> tuple[int, bytes, str]:
        """Genuine HTTP GET -> (status, body_bytes, content_type)."""
        req = urllib.request.Request(url, headers={"User-Agent": "nyx-tier1-intake/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), resp.headers.get("Content-Type", "")


_SHARED_SERVER: Optional[HoneypotServer] = None


def shared_server() -> HoneypotServer:
    """Process-wide honeypot server reused across campaigns and benchmarks."""
    global _SHARED_SERVER
    if _SHARED_SERVER is None:
        _SHARED_SERVER = HoneypotServer()
    if not _SHARED_SERVER.is_running:
        _SHARED_SERVER.start()
    return _SHARED_SERVER


def shutdown_shared_server() -> None:
    global _SHARED_SERVER
    if _SHARED_SERVER is not None:
        _SHARED_SERVER.stop()
        _SHARED_SERVER = None
