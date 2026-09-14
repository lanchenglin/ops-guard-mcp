from __future__ import annotations

import base64
import json
import os
import time
from typing import Any, Protocol

from .agent import AgentRuntime
from .canonical import hmac_hex
from .config import (
    DEFAULT_TRUSTED_EXECUTABLE_DIRS,
    AgentConfig,
    ConfigError,
    GatewayConfig,
)
from .models import ApprovalRecord, ExecutionResult, HostConfig, OperationRequest, RequestKind
from .process import run_argv


class ExecutorError(RuntimeError):
    pass


class Executor(Protocol):
    async def execute(
        self,
        request: OperationRequest,
        request_digest: str,
        approval: ApprovalRecord,
        artifact: bytes | None,
    ) -> ExecutionResult: ...


def _secret_for_host(host: HostConfig) -> bytes:
    value = os.environ.get(host.agent_secret_env)
    if not value:
        raise ConfigError(f"required environment variable is not set: {host.agent_secret_env}")
    if len(value) < 32:
        raise ConfigError(f"secret in {host.agent_secret_env} must be at least 32 characters")
    return value.encode("utf-8")


def build_agent_envelope(
    request: OperationRequest,
    request_digest: str,
    approval: ApprovalRecord,
    host: HostConfig,
    artifact: bytes | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "version": 1,
        "request": request.to_dict(),
        "request_digest": request_digest,
        "approval": approval.to_dict(),
        "timeout_seconds": host.timeout_seconds,
        "max_output_bytes": host.max_output_bytes,
    }
    if request.kind is RequestKind.SCRIPT:
        if artifact is None:
            raise ExecutorError("script request has no artifact")
        body["artifact_b64"] = base64.b64encode(artifact).decode("ascii")
    signature = hmac_hex(_secret_for_host(host), body)
    return {"body": body, "signature": signature}


def _result_from_value(request_id: str, value: dict[str, Any]) -> ExecutionResult:
    return ExecutionResult(
        request_id=request_id,
        exit_code=int(value.get("exit_code", 126)),
        stdout=str(value.get("stdout", "")),
        stderr=str(value.get("stderr", "")),
        started_at=int(value.get("started_at", time.time())),
        finished_at=int(value.get("finished_at", time.time())),
        truncated=bool(value.get("truncated", False)),
        error=(str(value["error"]) if value.get("error") else None),
    )


class LocalAgentExecutor:
    def __init__(self, gateway: GatewayConfig, host: HostConfig) -> None:
        self.gateway = gateway
        self.host = host
        agent_config = AgentConfig(
            path=gateway.path,
            host_id=host.host_id,
            secret_env=host.agent_secret_env,
            secret_file=None,
            nonce_db=gateway.state_dir / f"agent-{host.host_id}-nonces.sqlite3",
            allowed_read_roots=host.allowed_read_roots,
            allowed_workdirs=host.allowed_workdirs,
            default_workdir=host.default_workdir,
            allow_scripts=host.allow_scripts,
            script_interpreters={
                "shell": ("/bin/bash", "--noprofile", "--norc"),
                "python": ("/usr/bin/python3", "-I", "-B"),
            },
            trusted_executable_dirs=DEFAULT_TRUSTED_EXECUTABLE_DIRS,
            max_timeout_seconds=host.timeout_seconds,
            max_output_bytes=host.max_output_bytes,
        )
        self.runtime = AgentRuntime(agent_config)

    async def execute(
        self,
        request: OperationRequest,
        request_digest: str,
        approval: ApprovalRecord,
        artifact: bytes | None,
    ) -> ExecutionResult:
        envelope = build_agent_envelope(request, request_digest, approval, self.host, artifact)
        try:
            value = await self.runtime.execute_envelope(envelope)
            return _result_from_value(request.request_id, value)
        except Exception as exc:
            now = int(time.time())
            return ExecutionResult(
                request_id=request.request_id,
                exit_code=126,
                stdout="",
                stderr="",
                started_at=now,
                finished_at=now,
                error=str(exc),
            )


class SshAgentExecutor:
    def __init__(self, host: HostConfig) -> None:
        self.host = host

    def _ssh_argv(self) -> list[str]:
        if not self.host.ssh_host or not self.host.ssh_user or not self.host.known_hosts_file:
            raise ExecutorError("incomplete SSH host configuration")
        argv = [
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "RequestTTY=no",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.host.known_hosts_file}",
            "-o",
            "ConnectTimeout=10",
            "-p",
            str(self.host.ssh_port),
        ]
        if self.host.identity_file:
            argv.extend(
                [
                    "-i",
                    self.host.identity_file,
                    "-o",
                    "IdentitiesOnly=yes",
                ]
            )
        argv.append(f"{self.host.ssh_user}@{self.host.ssh_host}")
        # This command is administrator-owned configuration, never model-supplied input.
        argv.extend(self.host.remote_command)
        return argv

    async def execute(
        self,
        request: OperationRequest,
        request_digest: str,
        approval: ApprovalRecord,
        artifact: bytes | None,
    ) -> ExecutionResult:
        envelope = build_agent_envelope(request, request_digest, approval, self.host, artifact)
        payload = json.dumps(envelope, ensure_ascii=False, sort_keys=True).encode("utf-8")
        started = int(time.time())
        safe_env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        try:
            output = await run_argv(
                self._ssh_argv(),
                input_bytes=payload,
                env=safe_env,
                timeout_seconds=self.host.timeout_seconds + 15,
                max_output_bytes=self.host.max_output_bytes + 64 * 1024,
            )
            if not output.stdout:
                raise ExecutorError(
                    "remote agent returned no JSON; ssh stderr="
                    + output.stderr.decode("utf-8", errors="replace")
                )
            value = json.loads(output.stdout.decode("utf-8"))
            result = _result_from_value(request.request_id, value)
            if output.exit_code != 0 and not result.error:
                return ExecutionResult(
                    **{
                        **result.to_dict(),
                        "error": output.stderr.decode("utf-8", errors="replace")
                        or f"ssh exited with {output.exit_code}",
                    }
                )
            return result
        except Exception as exc:
            finished = int(time.time())
            return ExecutionResult(
                request_id=request.request_id,
                exit_code=126,
                stdout="",
                stderr="",
                started_at=started,
                finished_at=finished,
                error=str(exc),
            )


class ExecutorFactory:
    def __init__(self, gateway: GatewayConfig) -> None:
        self.gateway = gateway
        self._local: dict[str, LocalAgentExecutor] = {}

    def for_host(self, host: HostConfig) -> Executor:
        if host.transport == "local-agent":
            if host.host_id not in self._local:
                self._local[host.host_id] = LocalAgentExecutor(self.gateway, host)
            return self._local[host.host_id]
        if host.transport == "ssh-agent":
            return SshAgentExecutor(host)
        raise ExecutorError(f"unsupported transport: {host.transport}")
