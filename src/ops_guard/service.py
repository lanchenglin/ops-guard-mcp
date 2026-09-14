from __future__ import annotations

import asyncio
import posixpath
import secrets
import time
import uuid
from typing import Any

from .approvals import ApprovalLinkSigner, ApprovalNotifier, NullNotifier
from .artifacts import ArtifactStore
from .audit import HashChainAuditLog
from .canonical import request_digest, sha256_bytes
from .config import GatewayConfig
from .executor import ExecutorFactory
from .models import (
    ExecutionResult,
    OperationRequest,
    PolicyAction,
    PolicyDecision,
    RequestKind,
    RequestStatus,
)
from .policy import CommandPolicy
from .script_scan import scan_script
from .store import RequestStore, StoreError


class ServiceError(RuntimeError):
    pass


def _bounded_text(value: str, name: str, limit: int) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ServiceError(f"{name} is required")
    if "\x00" in cleaned or "\r" in cleaned:
        raise ServiceError(f"{name} contains forbidden control characters")
    if len(cleaned.encode("utf-8")) > limit:
        raise ServiceError(f"{name} exceeds {limit} bytes")
    return cleaned


def _cwd_for_host(cwd: str | None, allowed_roots: tuple[str, ...]) -> str | None:
    if cwd is None:
        return None
    if len(cwd.encode("utf-8")) > 4096 or "\x00" in cwd or "\n" in cwd or "\r" in cwd:
        raise ServiceError("cwd is invalid or too long")
    if not cwd.startswith("/"):
        raise ServiceError("cwd must be an absolute path")
    normalized = posixpath.normpath(cwd)
    if not any(
        normalized == root or normalized.startswith(root.rstrip("/") + "/")
        for root in allowed_roots
    ):
        raise ServiceError("cwd is outside the host allowed_workdirs")
    return normalized




def _approval_context(value: dict[str, Any] | None) -> dict[str, str] | None:
    """Validate a chat delivery hint without treating it as an approval credential."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ServiceError("approval_context must be an object")
    channel = str(value.get("channel", "")).strip().lower()
    if channel != "dingtalk":
        raise ServiceError("approval_context.channel must be dingtalk")
    conversation_type = str(value.get("conversation_type", "")).strip()
    if conversation_type not in {"1", "2"}:
        raise ServiceError("approval_context.conversation_type must be '1' or '2'")
    sender_staff_id = str(value.get("sender_staff_id", "")).strip()
    conversation_id = str(value.get("conversation_id", "")).strip()
    sender_nick = str(value.get("sender_nick", "")).strip()
    if not sender_staff_id:
        raise ServiceError("approval_context.sender_staff_id is required")
    if conversation_type == "2" and not conversation_id:
        raise ServiceError("group approval_context requires conversation_id")
    result = {
        "channel": "dingtalk",
        "conversation_type": conversation_type,
        "sender_staff_id": sender_staff_id,
    }
    if conversation_id:
        result["conversation_id"] = conversation_id
    if sender_nick:
        result["sender_nick"] = sender_nick
    for key, item in result.items():
        limit = 512 if key == "conversation_id" else 256
        if len(item.encode("utf-8")) > limit or any(ch in item for ch in "\x00\r\n"):
            raise ServiceError(f"approval_context.{key} is invalid")
    return result


def _execution_audit_summary(result: ExecutionResult) -> dict[str, Any]:
    stdout = result.stdout.encode("utf-8", errors="replace")
    stderr = result.stderr.encode("utf-8", errors="replace")
    return {
        "request_id": result.request_id,
        "exit_code": result.exit_code,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "truncated": result.truncated,
        "error": result.error,
        "stdout_bytes": len(stdout),
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_bytes": len(stderr),
        "stderr_sha256": sha256_bytes(stderr),
    }


class OpsGuardService:
    def __init__(
        self,
        config: GatewayConfig,
        *,
        notifier: ApprovalNotifier | None = None,
    ) -> None:
        self.config = config
        config.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.store = RequestStore(config.state_dir / "ops-guard.sqlite3")
        self.artifacts = ArtifactStore(config.state_dir / "artifacts")
        self.audit = HashChainAuditLog(config.state_dir / "audit.jsonl")
        self.policy = CommandPolicy()
        self.executors = ExecutorFactory(config)
        self.link_signer = ApprovalLinkSigner(
            config.approval_base_url,
            config.required_secret(config.approval_link_secret_env),
        )
        self.notifier = notifier or NullNotifier()

    def list_hosts(self) -> list[dict[str, Any]]:
        return [host.public_dict() for host in self.config.hosts.values()]

    def _new_request(
        self,
        *,
        host_id: str,
        kind: RequestKind,
        argv: list[str],
        reason: str,
        requester: str,
        decision: PolicyDecision,
        cwd: str | None,
        artifact_sha256: str | None = None,
        script_language: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> OperationRequest:
        now = int(time.time())
        return OperationRequest(
            request_id=str(uuid.uuid4()),
            host_id=host_id,
            kind=kind,
            argv=tuple(argv),
            reason=reason.strip(),
            requester=requester.strip() or "ai",
            risk=decision.risk,
            rule_id=decision.rule_id,
            cwd=cwd,
            created_at=now,
            expires_at=now + self.config.request_ttl_seconds,
            nonce=secrets.token_urlsafe(24),
            artifact_sha256=artifact_sha256,
            script_language=script_language,
            metadata=metadata or {},
        )

    async def submit_command(
        self,
        host_id: str,
        argv: list[str],
        reason: str,
        *,
        requester: str = "ai",
        cwd: str | None = None,
        approval_context: dict[str, Any] | None = None,
        include_approval_links: bool = False,
    ) -> dict[str, Any]:
        reason = _bounded_text(reason, "reason", 4000)
        requester = _bounded_text(requester or "ai", "requester", 256)
        host = self.config.get_host(host_id)
        cwd = _cwd_for_host(cwd, host.allowed_workdirs)
        decision = self.policy.evaluate(argv, host, kind=RequestKind.COMMAND, cwd=cwd)
        request = self._new_request(
            host_id=host_id,
            kind=RequestKind.COMMAND,
            argv=argv,
            reason=reason,
            requester=requester,
            decision=decision,
            cwd=cwd,
            metadata=(
                {"approval_context": _approval_context(approval_context)}
                if approval_context is not None
                else {}
            ),
        )
        initial_status = (
            RequestStatus.BLOCKED
            if decision.action is PolicyAction.DENY
            else RequestStatus.PENDING_APPROVAL
        )
        digest = self.store.create(request, initial_status)
        self.audit.append(
            "request.created",
            {
                "request": request.to_dict(),
                "request_digest": digest,
                "decision": decision.to_dict(),
            },
        )
        if decision.action is PolicyAction.DENY:
            return self.status(request.request_id)
        if decision.action is PolicyAction.ALLOW:
            approval = self.store.approve_automatically(request.request_id, digest)
            self.audit.append("request.auto-approved", approval.to_dict())
            result = await self.execute_approved(request.request_id)
            return result
        links = self.link_signer.links(request.request_id, digest, request.expires_at)
        notification_sent = False
        try:
            await asyncio.to_thread(self.notifier.notify, request, digest, decision, links)
            notification_sent = True
            self.audit.append(
                "approval.notified",
                {"request_id": request.request_id, "request_digest": digest},
            )
        except Exception as exc:
            # Fail closed: request remains pending and cannot execute without approval.
            self.audit.append(
                "approval.notification-failed",
                {"request_id": request.request_id, "error": str(exc)},
            )
        response = self.status(request.request_id)
        response["approval_request"] = {
            "required": True,
            "notification_sent": notification_sent,
            "expires_at": links.expires_at,
        }
        # Capability URLs are deliberately hidden from MCP/model callers. Administration-only
        # CLI paths can explicitly request them for local testing.
        if include_approval_links:
            response["approval_links"] = {
                "approve_url": links.approve_url,
                "reject_url": links.reject_url,
                "expires_at": links.expires_at,
            }
        return response

    async def stage_script(
        self,
        host_id: str,
        language: str,
        content: str,
        args: list[str],
        reason: str,
        *,
        requester: str = "ai",
        cwd: str | None = None,
        approval_context: dict[str, Any] | None = None,
        include_approval_links: bool = False,
    ) -> dict[str, Any]:
        reason = _bounded_text(reason, "reason", 4000)
        requester = _bounded_text(requester or "ai", "requester", 256)
        if len(content.encode("utf-8")) > 2 * 1024 * 1024:
            raise ServiceError("script exceeds the 2 MiB MVP limit")
        host = self.config.get_host(host_id)
        cwd = _cwd_for_host(cwd, host.allowed_workdirs)
        decision = self.policy.evaluate(
            args,
            host,
            kind=RequestKind.SCRIPT,
            cwd=cwd,
            script_language=language,
        )
        findings = [finding.to_dict() for finding in scan_script(language, content)]
        artifact_digest = self.artifacts.put(content.encode("utf-8"))
        request = self._new_request(
            host_id=host_id,
            kind=RequestKind.SCRIPT,
            argv=args,
            reason=reason,
            requester=requester,
            decision=decision,
            cwd=cwd,
            artifact_sha256=artifact_digest,
            script_language=language,
            metadata={
                "script_findings": findings,
                **(
                    {"approval_context": _approval_context(approval_context)}
                    if approval_context is not None
                    else {}
                ),
            },
        )
        initial_status = (
            RequestStatus.BLOCKED
            if decision.action is PolicyAction.DENY
            else RequestStatus.PENDING_APPROVAL
        )
        digest = self.store.create(request, initial_status)
        self.audit.append(
            "script.staged",
            {
                "request": request.to_dict(),
                "request_digest": digest,
                "decision": decision.to_dict(),
            },
        )
        if decision.action is PolicyAction.DENY:
            return self.status(request.request_id)
        links = self.link_signer.links(request.request_id, digest, request.expires_at)
        notification_sent = False
        try:
            await asyncio.to_thread(self.notifier.notify, request, digest, decision, links)
            notification_sent = True
            self.audit.append(
                "approval.notified",
                {"request_id": request.request_id, "request_digest": digest},
            )
        except Exception as exc:
            self.audit.append(
                "approval.notification-failed",
                {"request_id": request.request_id, "error": str(exc)},
            )
        response = self.status(request.request_id)
        response["approval_request"] = {
            "required": True,
            "notification_sent": notification_sent,
            "expires_at": links.expires_at,
        }
        if include_approval_links:
            response["approval_links"] = {
                "approve_url": links.approve_url,
                "reject_url": links.reject_url,
                "expires_at": links.expires_at,
            }
        return response

    def decide(
        self,
        request_id: str,
        request_digest_value: str,
        *,
        allow: bool,
        decided_by: str,
        comment: str = "",
    ) -> dict[str, Any]:
        record = self.store.decide(
            request_id,
            request_digest_value,
            allow=allow,
            decided_by=decided_by,
            comment=comment,
        )
        self.audit.append("approval.decided", record.to_dict())
        return self.status(request_id)

    async def execute_approved(self, request_id: str) -> dict[str, Any]:
        try:
            request, digest, approval = self.store.claim_for_execution(request_id)
        except StoreError:
            return self.status(request_id)
        host = self.config.get_host(request.host_id)
        # Reclassify immediately before transport. Policy may have been tightened since request time.
        current = self.policy.evaluate(
            request.argv,
            host,
            kind=request.kind,
            cwd=request.cwd,
            script_language=request.script_language,
        )
        if current.action is PolicyAction.DENY or current.risk.severity > request.risk.severity:
            error = f"policy changed before execution: {current.rule_id}"
            self.store.mark_blocked(request.request_id, error)
            self.audit.append(
                "execution.blocked-before-transport",
                {"request_id": request.request_id, "error": error},
            )
            return self.status(request_id)
        if request_digest(request) != digest or approval.request_digest != digest:
            error = "request or approval digest changed before execution"
            self.store.mark_blocked(request.request_id, error)
            self.audit.append(
                "execution.digest-mismatch",
                {"request_id": request.request_id, "error": error},
            )
            return self.status(request_id)
        started_at = int(time.time())
        try:
            artifact = None
            if request.kind is RequestKind.SCRIPT:
                if not request.artifact_sha256:
                    raise ServiceError("script request has no artifact digest")
                artifact = self.artifacts.get(request.artifact_sha256)
            self.audit.append(
                "execution.started",
                {
                    "request_id": request.request_id,
                    "request_digest": digest,
                    "host_id": request.host_id,
                },
            )
            executor = self.executors.for_host(host)
            result = await executor.execute(request, digest, approval, artifact)
        except Exception as exc:
            finished_at = int(time.time())
            result = ExecutionResult(
                request_id=request.request_id,
                exit_code=126,
                stdout="",
                stderr="",
                started_at=started_at,
                finished_at=finished_at,
                error=f"{type(exc).__name__}: {exc}",
            )
        self.store.complete(result)
        self.audit.append("execution.completed", _execution_audit_summary(result))
        return self.status(request_id)

    async def execute_pending_once(self, limit: int = 20) -> int:
        rows = self.store.list_by_status(RequestStatus.APPROVED, limit=limit)
        count = 0
        for row in rows:
            await self.execute_approved(row["request"]["request_id"])
            count += 1
        return count

    def status(self, request_id: str) -> dict[str, Any]:
        request, digest, status, error = self.store.get(request_id)
        approval = self.store.get_approval(request_id)
        result = self.store.result(request_id)
        return {
            "request": request.to_dict(),
            "request_digest": digest,
            "status": status.value,
            "last_error": error,
            "approval": approval.to_dict() if approval else None,
            "result": result.to_dict() if result else None,
        }

    def pending(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.store.list_by_status(RequestStatus.PENDING_APPROVAL, limit=limit)

    def audit_tail(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.audit.tail(limit)
