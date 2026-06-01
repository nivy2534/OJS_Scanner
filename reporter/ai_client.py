"""
reporter/ai_client.py

Revolver API client — seperti silinder revolver, kalau satu provider
gagal/rate-limit, otomatis pindah ke berikutnya.

Sekarang: Claude (Anthropic) saja.
Nanti: tambah provider baru ke PROVIDERS list.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Optional

import requests

log = logging.getLogger("ai_client")


# ── Provider definitions ──────────────────────────────────────────────────────

PROVIDERS = [
    {
        "name": "claude",
        "url": "https://api.anthropic.com/v1/messages",
        "model": "claude-sonnet-4-20250514",
        "auth_header": "x-api-key",
        "auth_env": "ANTHROPIC_API_KEY",
        "extra_headers": {
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        "build_body": lambda prompt, system: {
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 4096,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        },
        "extract_text": lambda data: data["content"][0]["text"],
    },
    # Tambah provider lain di sini nanti:
    # {
    #     "name": "openai",
    #     "url": "https://api.openai.com/v1/chat/completions",
    #     "model": "gpt-4o",
    #     "auth_header": "Authorization",
    #     "auth_env": "OPENAI_API_KEY",
    #     "extra_headers": {"content-type": "application/json"},
    #     "build_body": lambda prompt, system: {
    #         "model": "gpt-4o",
    #         "max_tokens": 4096,
    #         "messages": [
    #             {"role": "system", "content": system},
    #             {"role": "user", "content": prompt},
    #         ],
    #     },
    #     "extract_text": lambda data: data["choices"][0]["message"]["content"],
    # },
]


# ── Revolver Client ───────────────────────────────────────────────────────────

class RevolverClient:
    """
    Iterate melalui providers seperti silinder revolver.
    Kalau satu gagal → putar ke berikutnya secara otomatis.
    """

    def __init__(self, providers: list = PROVIDERS, timeout: int = 60):
        self.providers = providers
        self.timeout   = timeout
        self._cylinder = 0  # index provider aktif sekarang

    def complete(self, prompt: str, system: str = "") -> Optional[str]:
        """
        Kirim prompt ke provider aktif.
        Kalau gagal → coba provider berikutnya.
        Return: response text atau None kalau semua gagal.
        """
        attempts = len(self.providers)

        for _ in range(attempts):
            provider = self.providers[self._cylinder]
            try:
                result = self._call(provider, prompt, system)
                if result:
                    log.info(f"[Revolver] Response dari {provider['name']}")
                    return result
            except Exception as e:
                log.warning(f"[Revolver] {provider['name']} gagal: {e}")

            # Putar silinder ke provider berikutnya
            self._cylinder = (self._cylinder + 1) % len(self.providers)
            time.sleep(1)

        log.error("[Revolver] Semua provider gagal")
        return None

    def _call(self, provider: dict, prompt: str, system: str) -> Optional[str]:
        api_key = os.environ.get(provider["auth_env"], "")
        if not api_key:
            raise ValueError(f"API key {provider['auth_env']} tidak ditemukan di environment")

        # Auth header — Claude pakai x-api-key, OpenAI pakai Bearer
        auth_value = api_key if provider["name"] == "claude" else f"Bearer {api_key}"

        headers = {
            **provider["extra_headers"],
            provider["auth_header"]: auth_value,
        }

        body = provider["build_body"](prompt, system)

        resp = requests.post(
            provider["url"],
            headers=headers,
            json=body,
            timeout=self.timeout,
        )

        if resp.status_code == 429:
            raise RuntimeError(f"Rate limited by {provider['name']}")
        if resp.status_code != 200:
            raise RuntimeError(f"{provider['name']} error {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        return provider["extract_text"](data)


# ── Singleton ─────────────────────────────────────────────────────────────────

_client: Optional[RevolverClient] = None


def get_client() -> RevolverClient:
    global _client
    if _client is None:
        _client = RevolverClient()
    return _client
