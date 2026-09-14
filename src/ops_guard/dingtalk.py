from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any

from .approvals import ApprovalLinks, ApprovalNotifier, DingTalkNotifier, NullNotifier
from .canonical import hmac_hex, secure_compare
from .config import DingTalkConfig
from .models import OperationRequest, PolicyDecision

LOGGER = logging.getLogger("ops_guard.dingtalk")

DINGTALK_API_BASE = "https://api.dingtalk.com"
CARD_CALLBACK_TOPIC = "/v1.0/card/instances/callback"
APPROVE_ACTION = "ops_guard_approve"
REJECT_ACTION = "ops_guard_reject"
CARD_ID_PREFIX = "ops-guard-"
HERMES_BRIDGE_VERSION = 1


class DingTalkError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DingTalkApprovalContext:
    """Untrusted delivery hint supplied by the chat integration.

    Security does not rely on this object. The human identity used for approval comes from the
    authenticated DingTalk card callback. The context only decides where the card is delivered.
    """

    conversation_type: str
    sender_staff_id: str
    conversation_id: str | None = None
    sender_nick: str | None = None

    @staticmethod
    def _validate(
        conversation_type: str,
        sender_staff_id: str,
        conversation_id: str | None,
        sender_nick: str | None,
    ) -> "DingTalkApprovalContext":
        if conversation_type not in {"1", "2"}:
            raise DingTalkError("DingTalk conversation_type must be '1' or '2'")
        if not sender_staff_id:
            raise DingTalkError("DingTalk sender_staff_id is required")
        if conversation_type == "2" and not conversation_id:
            raise DingTalkError("group DingTalk target requires conversation_id")
        for name, value, limit in (
            ("sender_staff_id", sender_staff_id, 256),
            ("conversation_id", conversation_id, 512),
            ("sender_nick", sender_nick, 256),
        ):
            if value is not None and (
                len(value.encode("utf-8")) > limit or any(ch in value for ch in "\x00\r\n")
            ):
                raise DingTalkError(f"DingTalk {name} is invalid")
        return DingTalkApprovalContext(
            conversation_type=conversation_type,
            sender_staff_id=sender_staff_id,
            conversation_id=conversation_id,
            sender_nick=sender_nick,
        )

    @classmethod
    def from_request(cls, request: OperationRequest) -> "DingTalkApprovalContext | None":
        raw = request.metadata.get("approval_context")
        if not isinstance(raw, dict) or raw.get("channel") != "dingtalk":
            return None
        conversation_type = str(raw.get("conversation_type", "")).strip()
        sender_staff_id = str(raw.get("sender_staff_id", "")).strip()
        conversation_id = str(raw.get("conversation_id", "")).strip() or None
        sender_nick = str(raw.get("sender_nick", "")).strip() or None
        return cls._validate(
            conversation_type,
            sender_staff_id,
            conversation_id,
            sender_nick,
        )

    @classmethod
    def from_config(cls, config: DingTalkConfig) -> "DingTalkApprovalContext | None":
        sender_staff_id = config.default_sender_staff_id.strip()
        if not sender_staff_id:
            return None
        return cls._validate(
            config.default_conversation_type.strip(),
            sender_staff_id,
            config.default_conversation_id.strip() or None,
            config.default_sender_nick.strip() or None,
        )


def approval_context_for_request(
    request: OperationRequest, config: DingTalkConfig
) -> DingTalkApprovalContext | None:
    return DingTalkApprovalContext.from_request(request) or DingTalkApprovalContext.from_config(config)


def card_instance_id(request_id: str) -> str:
    """Create a deterministic card id that maps back without exposing approval tokens."""
    try:
        normalized = str(uuid.UUID(request_id))
    except ValueError as exc:
        raise DingTalkError("request_id is not a UUID") from exc
    return CARD_ID_PREFIX + normalized


def request_id_from_card(card_id: str) -> str:
    if not card_id.startswith(CARD_ID_PREFIX):
        raise DingTalkError("card does not belong to Ops Guard")
    raw = card_id[len(CARD_ID_PREFIX) :]
    try:
        return str(uuid.UUID(raw))
    except ValueError as exc:
        raise DingTalkError("invalid Ops Guard card id") from exc


def _card_strings(values: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in values.items():
        if isinstance(value, str):
            result[key] = value
        else:
            result[key] = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return result


def _required_secret(env_name: str) -> bytes:
    value = os.environ.get(env_name, "")
    if not value:
        raise DingTalkError(f"required environment variable is not set: {env_name}")
    if len(value) < 32:
        raise DingTalkError(f"secret in {env_name} must be at least 32 characters")
    return value.encode("utf-8")


class DingTalkOpenAPIClient:
    def __init__(self, config: DingTalkConfig) -> None:
        self.config = config
        self._access_token: str | None = None
        self._access_token_expires_at = 0.0
        self._token_lock = threading.Lock()

    def _credential(self) -> tuple[str, str]:
        client_id = os.environ.get(self.config.client_id_env, "").strip()
        client_secret = os.environ.get(self.config.client_secret_env, "").strip()
        if not client_id:
            raise DingTalkError(f"{self.config.client_id_env} is required for interactive mode")
        if not client_secret:
            raise DingTalkError(f"{self.config.client_secret_env} is required for interactive mode")
        return client_id, client_secret

    def _request_json(
        self,
        method: str,
        path: str,
        body: dict[str, Any],
        *,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        headers = {"Content-Type": "application/json; charset=utf-8"}
        if access_token:
            headers["x-acs-dingtalk-access-token"] = access_token
        request = urllib.request.Request(
            DINGTALK_API_BASE + path,
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read(512 * 1024)
                if response.status < 200 or response.status >= 300:
                    raise DingTalkError(f"DingTalk returned HTTP {response.status}")
        except urllib.error.HTTPError as exc:
            raw = exc.read(64 * 1024).decode("utf-8", errors="replace")
            raise DingTalkError(f"DingTalk HTTP {exc.code}: {raw[:2000]}") from exc
        except urllib.error.URLError as exc:
            raise DingTalkError(f"DingTalk request failed: {exc.reason}") from exc
        if not raw:
            return {}
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise DingTalkError("DingTalk response was not a JSON object")
        return value

    def access_token(self) -> str:
        with self._token_lock:
            now = time.time()
            if self._access_token and now < self._access_token_expires_at - 60:
                return self._access_token
            client_id, client_secret = self._credential()
            value = self._request_json(
                "POST",
                "/v1.0/oauth2/accessToken",
                {"appKey": client_id, "appSecret": client_secret},
            )
            token = str(value.get("accessToken", "")).strip()
            if not token:
                raise DingTalkError(f"DingTalk access token response is invalid: {value}")
            expires_in = int(value.get("expireIn", 7200))
            self._access_token = token
            self._access_token_expires_at = now + max(60, expires_in)
            return token

    def create_and_deliver_card(
        self,
        request: OperationRequest,
        request_digest: str,
        decision: PolicyDecision,
        links: ApprovalLinks,
    ) -> str:
        context = approval_context_for_request(request, self.config)
        if context is None:
            raise DingTalkError(
                "interactive approval needs approval_context or dingtalk.default_sender_staff_id"
            )
        if not self.config.card_template_id:
            raise DingTalkError("dingtalk.card_template_id is required for interactive mode")
        client_id, _ = self._credential()
        token = self.access_token()
        out_track_id = card_instance_id(request.request_id)
        command = (
            f"SCRIPT {request.script_language or 'unknown'} sha256={request.artifact_sha256}"
            if request.kind.value == "script"
            else " ".join(request.argv)
        )
        card_data = _card_strings(
            {
                "title": "🚨 Ops Guard 高风险操作审批",
                "hostId": request.host_id,
                "risk": request.risk.value,
                "ruleId": decision.rule_id,
                "requester": request.requester,
                "reason": request.reason,
                "operation": command,
                "requestDigest": request_digest,
                "requestDigestShort": request_digest[:16],
                "expiresAt": str(links.expires_at),
                "status": "pending",
                "statusText": "等待人工审批",
                "decisionUser": "",
            }
        )
        create_body: dict[str, Any] = {
            "cardTemplateId": self.config.card_template_id,
            "outTrackId": out_track_id,
            "cardData": {"cardParamMap": card_data},
            "callbackType": "STREAM",
            "imGroupOpenSpaceModel": {"supportForward": False},
            "imRobotOpenSpaceModel": {"supportForward": False},
        }
        self._request_json("POST", "/v1.0/card/instances", create_body, access_token=token)

        deliver_body: dict[str, Any] = {"outTrackId": out_track_id, "userIdType": 1}
        if context.conversation_type == "2":
            deliver_body["openSpaceId"] = f"dtv1.card//IM_GROUP.{context.conversation_id}"
            group_model: dict[str, Any] = {"robotCode": client_id}
            if self.config.at_requester:
                group_model["atUserIds"] = {
                    context.sender_staff_id: context.sender_nick or context.sender_staff_id
                }
            deliver_body["imGroupOpenDeliverModel"] = group_model
        else:
            deliver_body["openSpaceId"] = f"dtv1.card//IM_ROBOT.{context.sender_staff_id}"
            deliver_body["imRobotOpenDeliverModel"] = {"spaceType": "IM_ROBOT"}
        self._request_json(
            "POST", "/v1.0/card/instances/deliver", deliver_body, access_token=token
        )
        return out_track_id


class DingTalkInteractiveNotifier:
    """Deliver an approval card into the originating DingTalk conversation.

    The model never receives an approval token or an approve API. A deterministic card callback
    later supplies the authenticated DingTalk userId to the daemon-side approval controller.
    """

    def __init__(
        self,
        config: DingTalkConfig,
        *,
        fallback: ApprovalNotifier | None = None,
        client: DingTalkOpenAPIClient | None = None,
    ) -> None:
        self.config = config
        self.fallback = fallback
        self.client = client or DingTalkOpenAPIClient(config)

    def notify(
        self,
        request: OperationRequest,
        request_digest: str,
        decision: PolicyDecision,
        links: ApprovalLinks,
    ) -> None:
        try:
            card_id = self.client.create_and_deliver_card(request, request_digest, decision, links)
            LOGGER.info("DingTalk interactive approval delivered card=%s", card_id)
        except Exception:
            if self.fallback is None:
                raise
            LOGGER.exception("interactive approval failed; using configured webhook fallback")
            self.fallback.notify(request, request_digest, decision, links)


def build_dingtalk_notifier(config: DingTalkConfig) -> ApprovalNotifier:
    if not config.enabled:
        return NullNotifier()
    if config.mode == "webhook":
        return DingTalkNotifier(config)
    fallback: ApprovalNotifier | None = None
    if config.mode == "hybrid":
        fallback = DingTalkNotifier(config)
    if config.mode in {"interactive", "hybrid"}:
        return DingTalkInteractiveNotifier(config, fallback=fallback)
    raise DingTalkError(f"unsupported DingTalk approval mode: {config.mode}")


class DingTalkApprovalController:
    """Make a decision from an already-authenticated DingTalk card event.

    Authentication of the transport is intentionally outside the LLM/MCP surface. The controller
    requires the DingTalk userId supplied by the card callback and then enforces local approver
    policy before changing the request state.
    """

    def __init__(self, config: DingTalkConfig, service: Any) -> None:
        self.config = config
        self.service = service

    @staticmethod
    def callback_response(status: str, status_text: str, user_id: str = "") -> dict[str, Any]:
        return {
            "cardUpdateOptions": {
                "updateCardDataByKey": True,
                "updatePrivateDataByKey": False,
            },
            "cardData": {
                "cardParamMap": _card_strings(
                    {
                        "status": status,
                        "statusText": status_text,
                        "decisionUser": user_id,
                    }
                )
            },
        }

    def _authorized(self, user_id: str, request: OperationRequest) -> tuple[bool, str]:
        if not user_id:
            return False, "回调没有可验证的钉钉 userId"
        allowed = set(self.config.allowed_approver_user_ids)
        if allowed and user_id not in allowed:
            return False, "当前钉钉用户不在审批人白名单"
        if self.config.require_context_sender_match:
            try:
                context = approval_context_for_request(request, self.config)
            except DingTalkError as exc:
                return False, str(exc)
            if context is None:
                return False, "请求没有绑定原始钉钉会话或默认审批用户"
            if user_id != context.sender_staff_id:
                return False, "审批人不是发起该会话的钉钉用户"
        return True, ""

    def handle_verified_event(
        self,
        *,
        user_id: str,
        out_track_id: str,
        action: str,
        source: str,
    ) -> tuple[str, dict[str, Any]]:
        request_id = request_id_from_card(out_track_id)
        status = self.service.status(request_id)
        request = OperationRequest.from_dict(status["request"])
        ok, reason = self._authorized(user_id, request)
        if not ok:
            self.service.audit.append(
                "approval.dingtalk-denied",
                {
                    "request_id": request_id,
                    "user_id": user_id,
                    "reason": reason,
                    "source": source,
                },
            )
            return "OK", self.callback_response("denied", f"❌ 无审批权限：{reason}", user_id)

        if action not in {APPROVE_ACTION, REJECT_ACTION}:
            self.service.audit.append(
                "approval.dingtalk-ignored",
                {
                    "request_id": request_id,
                    "user_id": user_id,
                    "action": action,
                    "source": source,
                },
            )
            return "OK", self.callback_response("pending", "等待人工审批")

        allow = action == APPROVE_ACTION
        try:
            result = self.service.decide(
                request_id,
                status["request_digest"],
                allow=allow,
                decided_by=f"dingtalk:{user_id}",
                comment=f"DingTalk interactive card via {source}",
            )
        except Exception as exc:
            self.service.audit.append(
                "approval.dingtalk-failed",
                {
                    "request_id": request_id,
                    "user_id": user_id,
                    "error": str(exc),
                    "source": source,
                },
            )
            return "OK", self.callback_response("error", f"⚠️ 审批失败：{str(exc)[:160]}", user_id)

        if allow:
            text = "✅ 已批准，等待执行器领取"
            state = "approved"
        else:
            text = "❌ 已拒绝"
            state = "rejected"
        self.service.audit.append(
            "approval.dingtalk-decided",
            {
                "request_id": request_id,
                "user_id": user_id,
                "decision": state,
                "status": result["status"],
                "source": source,
            },
        )
        return "OK", self.callback_response(state, text, user_id)


class DingTalkHermesBridge:
    """Verify a deterministic Hermes adapter callback before changing approval state.

    Hermes' LLM never gets this secret. Only the DingTalk adapter callback code should possess it.
    Signed payloads are short-lived and carry a one-time nonce stored by RequestStore.
    """

    def __init__(self, config: DingTalkConfig, service: Any) -> None:
        self.config = config
        self.service = service
        self.controller = DingTalkApprovalController(config, service)

    def _secret(self) -> bytes:
        return _required_secret(self.config.bridge_secret_env)

    def verify_and_handle(
        self,
        payload: dict[str, Any],
        signature: str,
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise DingTalkError("bridge body must be a JSON object")
        if not signature or len(signature) != 64:
            raise DingTalkError("missing or invalid bridge signature")
        expected = hmac_hex(self._secret(), payload)
        try:
            valid_signature = secure_compare(expected, signature)
        except (UnicodeEncodeError, AttributeError):
            valid_signature = False
        if not valid_signature:
            raise DingTalkError("invalid Hermes bridge signature")

        try:
            version = int(payload.get("version", 0))
            timestamp = int(payload["timestamp"])
        except (KeyError, TypeError, ValueError) as exc:
            raise DingTalkError("invalid Hermes bridge version/timestamp") from exc
        if version != HERMES_BRIDGE_VERSION:
            raise DingTalkError("unsupported Hermes bridge version")
        current = int(time.time()) if now is None else now
        if abs(current - timestamp) > self.config.bridge_max_age_seconds:
            raise DingTalkError("Hermes bridge event is outside the allowed time window")

        nonce = str(payload.get("nonce", "")).strip()
        user_id = str(payload.get("user_id", "")).strip()
        out_track_id = str(payload.get("out_track_id", "")).strip()
        action = str(payload.get("action", "")).strip()
        if len(nonce) < 16 or len(nonce) > 256 or any(ch in nonce for ch in "\x00\r\n"):
            raise DingTalkError("invalid Hermes bridge nonce")
        if not user_id or len(user_id.encode("utf-8")) > 256:
            raise DingTalkError("invalid DingTalk user_id")
        if action not in {APPROVE_ACTION, REJECT_ACTION}:
            raise DingTalkError("invalid DingTalk approval action")
        request_id_from_card(out_track_id)

        self.service.store.consume_integration_nonce(
            nonce,
            seen_at=current,
            retention_seconds=max(600, self.config.bridge_max_age_seconds * 4),
        )
        ack, card_callback_response = self.controller.handle_verified_event(
            user_id=user_id,
            out_track_id=out_track_id,
            action=action,
            source="hermes-bridge",
        )
        self.service.audit.append(
            "approval.hermes-bridge-accepted",
            {
                "out_track_id": out_track_id,
                "user_id": user_id,
                "action": action,
                "timestamp": timestamp,
            },
        )
        return {
            "ok": True,
            "ack": ack,
            "card_callback_response": card_callback_response,
        }


class DingTalkApprovalStream:
    """Standalone Stream listener. Do not run alongside Hermes with the same DingTalk app."""

    def __init__(self, config: DingTalkConfig, service: Any) -> None:
        self.config = config
        self.service = service
        self.controller = DingTalkApprovalController(config, service)

    def handle_card_callback(self, callback_data: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        try:
            import dingtalk_stream  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - covered by startup validation
            raise DingTalkError(
                "standalone Stream mode requires: pip install 'ops-guard-mcp[dingtalk]'"
            ) from exc

        incoming = dingtalk_stream.CardCallbackMessage.from_dict(callback_data)
        content = incoming.content if isinstance(incoming.content, dict) else {}
        private = content.get("cardPrivateData", {})
        params = private.get("params", {}) if isinstance(private, dict) else {}
        _ack, response = self.controller.handle_verified_event(
            user_id=str(incoming.user_id or "").strip(),
            out_track_id=str(incoming.card_instance_id or "").strip(),
            action=str(params.get("action", "")).strip(),
            source="ops-guard-stream",
        )
        return dingtalk_stream.AckMessage.STATUS_OK, response

    def preflight(self) -> tuple[Any, str, str]:
        """Fail fast before the daemon reports itself healthy in standalone Stream mode."""
        try:
            import dingtalk_stream  # type: ignore[import-not-found]
        except ImportError as exc:
            raise DingTalkError(
                "standalone Stream mode requires: pip install 'ops-guard-mcp[dingtalk]'"
            ) from exc

        client_id = os.environ.get(self.config.client_id_env, "").strip()
        client_secret = os.environ.get(self.config.client_secret_env, "").strip()
        if not client_id or not client_secret:
            raise DingTalkError(
                f"{self.config.client_id_env} and {self.config.client_secret_env} are required"
            )
        return dingtalk_stream, client_id, client_secret

    def run_forever(self) -> None:
        dingtalk_stream, client_id, client_secret = self.preflight()
        stream = self

        class Handler(dingtalk_stream.CallbackHandler):  # type: ignore[misc]
            async def process(self, callback: Any) -> tuple[int, dict[str, Any]]:
                return stream.handle_card_callback(callback.data)

        credential = dingtalk_stream.Credential(client_id, client_secret)
        client = dingtalk_stream.DingTalkStreamClient(credential)
        client.register_callback_handler(
            dingtalk_stream.CallbackHandler.TOPIC_CARD_CALLBACK,
            Handler(),
        )
        LOGGER.info("DingTalk card callback Stream listener started topic=%s", CARD_CALLBACK_TOPIC)
        client.start_forever()
