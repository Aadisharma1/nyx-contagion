"""Live LLM endpoint client (OpenAI / Anthropic / vLLM / LiteLLM).

Selected purely from environment variables; returns ``None``-equivalent errors
when no key is configured so the deterministic ``calibrated-sim`` engine stays
usable on any machine without credentials.

    OPENAI_API_KEY      (+ optional OPENAI_BASE_URL, OPENAI_MODEL)
    ANTHROPIC_API_KEY   (+ optional ANTHROPIC_MODEL)
    LITELLM_MODEL       (+ optional LITELLM_BASE_URL, LITELLM_API_KEY)
"""
from __future__ import annotations

import os
from typing import Optional


class LLMError(RuntimeError):
    pass


class LLMClient:
    """Minimal, dependency-light chat client used by live-mode tier agents."""

    def __init__(self, provider: str, base_url: str, model: str, api_key: str) -> None:
        self.provider = provider
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key

    @classmethod
    def from_env(cls) -> "LLMClient":
        if os.environ.get("ANTHROPIC_API_KEY"):
            return cls(
                provider="anthropic",
                base_url=os.environ.get("ANTHROPIC_BASE_URL",
                                        "https://api.anthropic.com/v1"),
                model=os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest"),
                api_key=os.environ["ANTHROPIC_API_KEY"],
            )
        if os.environ.get("OPENAI_API_KEY"):
            return cls(
                provider="openai",
                base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
                model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
                api_key=os.environ["OPENAI_API_KEY"],
            )
        if os.environ.get("LITELLM_MODEL"):
            return cls(
                provider="litellm",
                base_url=os.environ.get("LITELLM_BASE_URL", "http://localhost:4000"),
                model=os.environ["LITELLM_MODEL"],
                api_key=os.environ.get("LITELLM_API_KEY", "sk-no-key"),
            )
        raise LLMError(
            "No live LLM credentials found. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, "
            "or LITELLM_MODEL (or run with --mode calibrated-sim, which needs no keys)."
        )

    def complete(self, system: str, user: str, max_tokens: int = 512) -> str:
        import httpx

        if self.provider == "anthropic":
            resp = httpx.post(
                f"{self.base_url}/messages",
                headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
                json={
                    "model": self.model, "max_tokens": max_tokens,
                    "system": system,
                    "messages": [{"role": "user", "content": user}],
                },
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            return "".join(block.get("text", "") for block in data.get("content", []))

        resp = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": self.model, "max_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


def maybe_live_client(mode: str) -> Optional[LLMClient]:
    if mode != "live":
        return None
    return LLMClient.from_env()
