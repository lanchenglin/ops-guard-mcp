from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from .canonical import hmac_hex, secure_compare
from .config import DingTalkConfig
from .models import OperationRequest, PolicyDecision


class ApprovalLinkError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ApprovalLinks:
    approve_url: str
    reject_url: str
    expires_at: int


class ApprovalLinkSigner:
    def __init__(self, base_url: str, secret: bytes) -> None:
        self.base_url = base_url.rstrip("/")
        self.secret = secret

    def _payload(
        self,
        request_id: str,
        request_digest: str,
        decision: str,
        expires_at: int,
    ) -> dict[str, object]:
        return {
            "version": 1,
            "request_id": request_id,
            "request_digest": request_digest,
            "decision": decision,
            "expires_at": expires_at,
        }

    def make_url(
        self,
        request_id: str,
        request_digest: str,
        decision: str,
        expires_at: int,
    ) -> str:
        if decision not in {"approve", "reject"}:
            raise ApprovalLinkError("unsupported decision")
        payload = self._payload(request_id, request_digest, decision, expires_at)
        token = hmac_hex(self.secret, payload)
        query = urllib.parse.urlencode({**payload, "token": token})
        return f"{self.base_url}/decision?{query}"

    def links(self, request_id: str, request_digest: str, expires_at: int) -> ApprovalLinks:
        return ApprovalLinks(
            approve_url=self.make_url(request_id, request_digest, "approve", expires_at),
            reject_url=self.make_url(request_id, request_digest, "reject", expires_at),
            expires_at=expires_at,
        )

    def verify(self, params: dict[str, str], *, now: int | None = None) -> dict[str, object]:
        required = {"request_id", "request_digest", "decision", "expires_at", "token"}
        if not required.issubset(params):
            raise ApprovalLinkError("approval link is missing required fields")
        try:
            expires_at = int(params["expires_at"])
        except ValueError as exc:
            raise ApprovalLinkError("invalid expires_at") from exc
        current = int(time.time()) if now is None else now
        if expires_at < current:
            raise ApprovalLinkError("approval link has expired")
        payload = self._payload(
            params["request_id"],
            params["request_digest"],
            params["decision"],
            expires_at,
        )
        expected = hmac_hex(self.secret, payload)
        if not secure_compare(expected, params["token"]):
            raise ApprovalLinkError("invalid approval link signature")
        return payload


class ApprovalNotifier(Protocol):
    def notify(
        self,
        request: OperationRequest,
        request_digest: str,
        decision: PolicyDecision,
        links: ApprovalLinks,
    ) -> None: ...


class NullNotifier:
    def notify(
        self,
        request: OperationRequest,
        request_digest: str,
        decision: PolicyDecision,
        links: ApprovalLinks,
    ) -> None:
        del request, request_digest, decision, links


class DingTalkNotifier:
    """DingTalk custom-robot notifier using an ActionCard.

    The card links to the local approval service. The link is signed and single-use at the
    request state-machine level. For verified human identity, deploy the approval service
    behind corporate SSO or replace this adapter with a DingTalk app/interactive-card callback.
    """

    def __init__(self, config: DingTalkConfig) -> None:
        self.config = config

    def _signed_webhook(self, webhook: str, secret: str | None) -> str:
        if not secret:
            return webhook
        timestamp = str(int(time.time() * 1000))
        string_to_sign = f"{timestamp}\n{secret}".encode("utf-8")
        signature = base64.b64encode(
            hmac.new(secret.encode("utf-8"), string_to_sign, hashlib.sha256).digest()
        ).decode("ascii")
        separator = "&" if "?" in webhook else "?"
        return (
            f"{webhook}{separator}timestamp={urllib.parse.quote(timestamp)}"
            f"&sign={urllib.parse.quote(signature)}"
        )

    @staticmethod
    def _safe_card_text(value: str, limit: int = 800) -> str:
        # All request fields are untrusted model input. Neutralize Markdown links, headings,
        # blockquotes and inline-code delimiters so the model cannot forge UI inside the card.
        compact = " ".join(str(value).replace("\x00", "").splitlines())
        translation = str.maketrans(
            {
                "`": "'",
                "[": "［",
                "]": "］",
                "(": "（",
                ")": "）",
                "<": "＜",
                ">": "＞",
                "*": "＊",
                "_": "＿",
                "#": "＃",
                "!": "！",
                "|": "｜",
            }
        )
        safe = compact.translate(translation)
        return safe if len(safe) <= limit else safe[: limit - 3] + "..."

    def notify(
        self,
        request: OperationRequest,
        request_digest: str,
        decision: PolicyDecision,
        links: ApprovalLinks,
    ) -> None:
        webhook = os.environ.get(self.config.webhook_url_env)
        if not webhook:
            raise RuntimeError(
                f"DingTalk is enabled but {self.config.webhook_url_env} is not set"
            )
        secret = os.environ.get(self.config.secret_env)
        command = (
            "SCRIPT " + (request.script_language or "unknown") + f" sha256={request.artifact_sha256}"
            if request.kind.value == "script"
            else " ".join(request.argv)
        )
        findings = request.metadata.get("script_findings") or []
        finding_text = ""
        if findings:
            preview = "; ".join(
                self._safe_card_text(
                    f"{item.get('severity')}:{item.get('rule_id')}@{item.get('line')}",
                    120,
                )
                for item in findings[:8]
                if isinstance(item, dict)
            )
            finding_text = f"\n\n**脚本扫描：** {self._safe_card_text(preview, 500)}"
        text = (
            "### 🚨 Ops Guard 高风险操作审批\n\n"
            f"**目标主机：** `{self._safe_card_text(request.host_id, 120)}`\n\n"
            f"**风险等级：** `{request.risk.value}`\n\n"
            f"**策略规则：** `{decision.rule_id}`\n\n"
            f"**申请人：** `{self._safe_card_text(request.requester, 200)}`\n\n"
            f"**原因：** {self._safe_card_text(request.reason, 600)}\n\n"
            f"**操作：** `{self._safe_card_text(command, 1000)}`\n\n"
            f"**绑定摘要：** `{request_digest}`\n\n"
            f"**有效期至：** `{links.expires_at}`"
            f"{finding_text}\n\n"
            "> 点击按钮后仍需在确认页再次确认，避免聊天客户端预取链接导致误审批。"
        )
        body = {
            "msgtype": "actionCard",
            "actionCard": {
                "title": f"Ops Guard 审批：{request.host_id}",
                "text": text,
                "btnOrientation": "0",
                "btns": [
                    {"title": "批准执行", "actionURL": links.approve_url},
                    {"title": "拒绝", "actionURL": links.reject_url},
                ],
            },
        }
        request_obj = urllib.request.Request(
            self._signed_webhook(webhook, secret),
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        with urllib.request.urlopen(request_obj, timeout=self.config.timeout_seconds) as response:
            response_body = response.read(64 * 1024)
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"DingTalk returned HTTP {response.status}")
            if response_body:
                parsed = json.loads(response_body.decode("utf-8"))
                error_code = parsed.get("errcode", 0)
                if error_code not in {0, "0", None}:
                    raise RuntimeError(f"DingTalk error: {parsed}")
