"""Hermes DingTalk adapter hook for Ops Guard approval cards.

Deterministic transport glue: this code does not call the LLM and does not expose an MCP
approval tool. It forwards only authenticated Ops Guard card callbacks to the local approval
service using HMAC, timestamp and a one-use nonce.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any

import dingtalk_stream
import httpx
from dingtalk_stream.frames import AckMessage

CARD_ID_PREFIX = "ops-guard-"
APPROVE_ACTION = "ops_guard_approve"
REJECT_ACTION = "ops_guard_reject"
DEFAULT_BRIDGE_URL = "http://127.0.0.1:8765/integrations/dingtalk/decision"


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


class OpsGuardCardCallbackHandler(dingtalk_stream.CallbackHandler):
    def __init__(self, bridge_url: str, secret: bytes, timeout_seconds: float = 5.0) -> None:
        self.bridge_url = bridge_url
        self.secret = secret
        self.timeout_seconds = timeout_seconds

    @classmethod
    def from_env(cls) -> "OpsGuardCardCallbackHandler | None":
        enabled = os.getenv("OPS_GUARD_DINGTALK_BRIDGE_ENABLED", "true").lower()
        if enabled not in {"1", "true", "yes", "on"}:
            return None
        secret_text = os.environ.pop("OPS_GUARD_HERMES_BRIDGE_SECRET", "")
        if not secret_text:
            return None
        if len(secret_text) < 32:
            raise RuntimeError("OPS_GUARD_HERMES_BRIDGE_SECRET must be at least 32 characters")
        bridge_url = os.getenv("OPS_GUARD_DINGTALK_BRIDGE_URL", DEFAULT_BRIDGE_URL).strip()
        if not bridge_url.startswith(("http://127.0.0.1:", "http://localhost:", "https://")):
            raise RuntimeError("OPS_GUARD_DINGTALK_BRIDGE_URL must be localhost HTTP or HTTPS")
        return cls(bridge_url, secret_text.encode("utf-8"))

    async def process(self, callback: Any) -> tuple[int, Any]:
        try:
            incoming = dingtalk_stream.CardCallbackMessage.from_dict(callback.data)
            out_track_id = str(incoming.card_instance_id or "").strip()
            if not out_track_id.startswith(CARD_ID_PREFIX):
                return AckMessage.STATUS_OK, "OK"
            content = incoming.content if isinstance(incoming.content, dict) else {}
            private = content.get("cardPrivateData", {})
            params = private.get("params", {}) if isinstance(private, dict) else {}
            action = str(params.get("action", "")).strip()
            if action not in {APPROVE_ACTION, REJECT_ACTION}:
                return AckMessage.STATUS_OK, "OK"
            payload = {
                "version": 1,
                "timestamp": int(time.time()),
                "nonce": secrets.token_urlsafe(24),
                "user_id": str(incoming.user_id or "").strip(),
                "out_track_id": out_track_id,
                "action": action,
            }
            signature = hmac.new(self.secret, _canonical_json(payload), hashlib.sha256).hexdigest()
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(self.bridge_url, json=payload, headers={"X-Ops-Guard-Signature": signature})
                response.raise_for_status()
                result = response.json()
            card_response = result.get("card_callback_response")
            if not isinstance(card_response, dict):
                raise RuntimeError("Ops Guard bridge returned an invalid card callback response")
            return AckMessage.STATUS_OK, card_response
        except Exception as exc:
            return AckMessage.STATUS_SYSTEM_EXCEPTION, f"Ops Guard approval bridge failed: {exc}"
