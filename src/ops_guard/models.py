from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Risk(str, Enum):
    READ = "read"
    SENSITIVE_READ = "sensitive_read"
    MUTATE = "mutate"
    PRIVILEGED = "privileged"
    FORBIDDEN = "forbidden"

    @property
    def severity(self) -> int:
        return {
            Risk.READ: 10,
            Risk.SENSITIVE_READ: 20,
            Risk.MUTATE: 30,
            Risk.PRIVILEGED: 40,
            Risk.FORBIDDEN: 100,
        }[self]


class PolicyAction(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class RequestKind(str, Enum):
    COMMAND = "command"
    SCRIPT = "script"


class RequestStatus(str, Enum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    EXPIRED = "expired"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    risk: Risk
    action: PolicyAction
    rule_id: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk": self.risk.value,
            "action": self.action.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class HostConfig:
    host_id: str
    environment: str
    transport: str
    approve_sensitive_reads: bool = False
    allow_scripts: bool = False
    allowed_read_roots: tuple[str, ...] = ()
    allowed_workdirs: tuple[str, ...] = ("/tmp",)
    default_workdir: str = "/tmp"
    timeout_seconds: int = 30
    max_output_bytes: int = 1_048_576
    ssh_host: str | None = None
    ssh_user: str | None = None
    ssh_port: int = 22
    identity_file: str | None = None
    known_hosts_file: str | None = None
    remote_command: tuple[str, ...] = ("ops-guard-agent", "execute")
    agent_secret_env: str = "OPS_GUARD_AGENT_SECRET"

    def public_dict(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "environment": self.environment,
            "transport": self.transport,
            "approve_sensitive_reads": self.approve_sensitive_reads,
            "allow_scripts": self.allow_scripts,
            "allowed_read_roots": list(self.allowed_read_roots),
            "allowed_workdirs": list(self.allowed_workdirs),
            "timeout_seconds": self.timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
        }


@dataclass(frozen=True, slots=True)
class OperationRequest:
    request_id: str
    host_id: str
    kind: RequestKind
    argv: tuple[str, ...]
    reason: str
    requester: str
    risk: Risk
    rule_id: str
    cwd: str | None
    created_at: int
    expires_at: int
    nonce: str
    artifact_sha256: str | None = None
    script_language: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def binding_dict(self) -> dict[str, Any]:
        """Fields that an approval and agent signature are bound to."""
        return {
            "version": 1,
            "request_id": self.request_id,
            "host_id": self.host_id,
            "kind": self.kind.value,
            "argv": list(self.argv),
            "reason": self.reason,
            "requester": self.requester,
            "risk": self.risk.value,
            "rule_id": self.rule_id,
            "cwd": self.cwd,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "artifact_sha256": self.artifact_sha256,
            "script_language": self.script_language,
            "metadata": self.metadata,
        }

    def to_dict(self) -> dict[str, Any]:
        return self.binding_dict()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "OperationRequest":
        return cls(
            request_id=str(value["request_id"]),
            host_id=str(value["host_id"]),
            kind=RequestKind(value["kind"]),
            argv=tuple(str(item) for item in value.get("argv", [])),
            reason=str(value.get("reason", "")),
            requester=str(value.get("requester", "unknown")),
            risk=Risk(value["risk"]),
            rule_id=str(value.get("rule_id", "unknown")),
            cwd=value.get("cwd"),
            created_at=int(value["created_at"]),
            expires_at=int(value["expires_at"]),
            nonce=str(value["nonce"]),
            artifact_sha256=value.get("artifact_sha256"),
            script_language=value.get("script_language"),
            metadata=dict(value.get("metadata") or {}),
        )


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    request_id: str
    request_digest: str
    decision: str
    decided_at: int
    decided_by: str
    comment: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    request_id: str
    exit_code: int
    stdout: str
    stderr: str
    started_at: int
    finished_at: int
    truncated: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
