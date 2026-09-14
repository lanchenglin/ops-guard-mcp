from __future__ import annotations

import argparse
import asyncio
import base64
from contextlib import contextmanager
import json
import os
import posixpath
import sqlite3
import stat
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import hmac_hex, request_digest, secure_compare, sha256_bytes
from .config import AgentConfig, ConfigError, load_agent_config
from .models import ApprovalRecord, HostConfig, OperationRequest, RequestKind, Risk
from .policy import CommandPolicy
from .process import ProcessOutput, run_argv


class AgentError(RuntimeError):
    pass


class NonceStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._db() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS used_nonces (
                    nonce TEXT PRIMARY KEY,
                    expires_at INTEGER NOT NULL,
                    used_at INTEGER NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @contextmanager
    def _db(self):
        db = self._connect()
        try:
            yield db
        finally:
            db.close()

    def claim(self, nonce: str, expires_at: int) -> None:
        now = int(time.time())
        with self._db() as db:
            db.execute("DELETE FROM used_nonces WHERE expires_at < ?", (now - 300,))
            try:
                db.execute(
                    "INSERT INTO used_nonces(nonce, expires_at, used_at) VALUES (?, ?, ?)",
                    (nonce, expires_at, now),
                )
            except sqlite3.IntegrityError as exc:
                raise AgentError("replayed nonce") from exc


class AgentRuntime:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.policy = CommandPolicy()
        self.nonces = NonceStore(config.nonce_db)

    def _host_policy(self) -> HostConfig:
        return HostConfig(
            host_id=self.config.host_id,
            environment="agent",
            transport="local-agent",
            approve_sensitive_reads=False,
            allow_scripts=self.config.allow_scripts,
            allowed_read_roots=self.config.allowed_read_roots,
            allowed_workdirs=self.config.allowed_workdirs,
            default_workdir=self.config.default_workdir,
            timeout_seconds=self.config.max_timeout_seconds,
            max_output_bytes=self.config.max_output_bytes,
        )

    def _minimal_env(self) -> dict[str, str]:
        return {
            "PATH": ":".join(self.config.trusted_executable_dirs),
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PAGER": "/bin/cat",
            "SYSTEMD_PAGER": "/bin/cat",
            "SYSTEMD_COLORS": "0",
            "NO_COLOR": "1",
        }

    @staticmethod
    def _writable_by_agent(path: Path) -> bool:
        try:
            metadata = path.stat()
        except OSError as exc:
            raise AgentError(f"unable to stat trusted executable path: {path}") from exc
        mode = metadata.st_mode
        groups = set(os.getgroups()) | {os.getegid()}
        if mode & stat.S_IWOTH:
            return True
        if mode & stat.S_IWGRP and metadata.st_gid in groups:
            return True
        if os.geteuid() != 0 and metadata.st_uid == os.geteuid() and mode & stat.S_IWUSR:
            return True
        return False

    def _trusted_roots(self) -> tuple[Path, ...]:
        roots: list[Path] = []
        for raw in self.config.trusted_executable_dirs:
            try:
                root = Path(raw).resolve(strict=True)
            except OSError:
                continue
            if root.is_dir() and root not in roots:
                roots.append(root)
        if not roots:
            raise AgentError("no configured trusted executable directory exists")
        return tuple(roots)

    def _resolve_executable(self, value: str, *, allow_absolute: bool = False) -> str:
        if not value:
            raise AgentError("empty executable")
        if not allow_absolute and ("/" in value or "\\" in value):
            raise AgentError("model-supplied executable paths are forbidden")
        roots = self._trusted_roots()
        candidates = [Path(value)] if Path(value).is_absolute() else [root / value for root in roots]
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=True)
            except OSError:
                continue
            if not resolved.is_file() or not os.access(resolved, os.X_OK):
                continue
            if not any(resolved == root or root in resolved.parents for root in roots):
                continue
            chain = [resolved, *resolved.parents]
            if any(self._writable_by_agent(item) for item in chain):
                raise AgentError(f"executable path is writable by the Agent account: {resolved}")
            return str(resolved)
        raise AgentError(f"executable is not present in trusted directories: {value}")

    @staticmethod
    def _inside(path: Path, roots: tuple[str, ...]) -> bool:
        resolved = path.resolve(strict=False)
        for root in roots:
            root_path = Path(root).resolve(strict=False)
            if resolved == root_path or root_path in resolved.parents:
                return True
        return False

    def _workdir(self, requested: str | None) -> str:
        value = requested or self.config.default_workdir
        path = Path(value)
        if not path.is_absolute():
            raise AgentError("working directory must be absolute")
        if not self._inside(path, self.config.allowed_workdirs):
            raise AgentError("working directory is outside allowed_workdirs")
        if not path.exists() or not path.is_dir():
            raise AgentError("working directory does not exist")
        return str(path.resolve())

    def _runtime_file_paths(self, request: OperationRequest, cwd: str) -> list[Path]:
        command = PurePosixPath(request.argv[0]).name if request.argv else ""
        args = list(request.argv[1:])
        paths: list[str] = []
        if command == "find":
            for arg in args:
                if not arg.startswith("-"):
                    paths.append(arg)
                    break
        elif command == "cat":
            paths = [arg for arg in args if not arg.startswith("-")]
        elif command in {"head", "tail"}:
            value_options = {"-n", "--lines", "-c", "--bytes", "--pid", "--sleep-interval", "--max-unchanged-stats"}
            skip = False
            for arg in args:
                if skip:
                    skip = False
                    continue
                if arg in value_options:
                    skip = True
                    continue
                if arg.startswith("-"):
                    continue
                paths.append(arg)
        elif command in {"stat", "wc", "du", "ls"}:
            value_options = {"--max-depth", "-d", "--block-size"}
            skip = False
            for arg in args:
                if skip:
                    skip = False
                    continue
                if arg in value_options:
                    skip = True
                    continue
                if arg.startswith("-"):
                    continue
                paths.append(arg)
        return [Path(path if path.startswith("/") else posixpath.join(cwd, path)) for path in paths]

    def _verify_runtime_paths(self, request: OperationRequest, cwd: str) -> None:
        for path in self._runtime_file_paths(request, cwd):
            if not self._inside(path, self.config.allowed_read_roots):
                raise AgentError(f"runtime path escapes allowed_read_roots: {path}")

    def _verify_envelope(self, envelope: dict[str, Any]) -> tuple[dict[str, Any], OperationRequest, ApprovalRecord]:
        body = envelope.get("body")
        signature = envelope.get("signature")
        if not isinstance(body, dict) or not isinstance(signature, str):
            raise AgentError("invalid envelope structure")
        expected = hmac_hex(self.config.secret(), body)
        if not secure_compare(expected, signature):
            raise AgentError("invalid gateway signature")
        request_value = body.get("request")
        approval_value = body.get("approval")
        if not isinstance(request_value, dict) or not isinstance(approval_value, dict):
            raise AgentError("envelope is missing request or approval")
        request = OperationRequest.from_dict(request_value)
        approval = ApprovalRecord(**approval_value)
        supplied_digest = str(body.get("request_digest", ""))
        digest = request_digest(request)
        if supplied_digest != digest:
            raise AgentError("request digest mismatch")
        if approval.request_id != request.request_id or approval.request_digest != digest:
            raise AgentError("approval is not bound to this request")
        if approval.decision != "approved":
            raise AgentError("request is not approved")
        now = int(time.time())
        if request.expires_at < now:
            raise AgentError("request has expired")
        if request.host_id != self.config.host_id:
            raise AgentError("request targets a different host")

        local_decision = self.policy.evaluate(
            request.argv,
            self._host_policy(),
            kind=request.kind,
            cwd=request.cwd,
            script_language=request.script_language,
        )
        if local_decision.risk is Risk.FORBIDDEN:
            raise AgentError(f"agent policy denied request: {local_decision.rule_id}")
        if local_decision.risk.severity > request.risk.severity:
            raise AgentError("gateway understated the request risk")
        return body, request, approval

    async def _execute_command(self, request: OperationRequest, body: dict[str, Any]) -> ProcessOutput:
        cwd = self._workdir(request.cwd)
        self._verify_runtime_paths(request, cwd)
        timeout = min(int(body.get("timeout_seconds", 30)), self.config.max_timeout_seconds)
        output_limit = min(int(body.get("max_output_bytes", self.config.max_output_bytes)), self.config.max_output_bytes)
        argv = [self._resolve_executable(request.argv[0]), *request.argv[1:]]
        return await run_argv(
            argv,
            cwd=cwd,
            env=self._minimal_env(),
            timeout_seconds=max(1, timeout),
            max_output_bytes=max(1024, output_limit),
        )

    async def _execute_script(self, request: OperationRequest, body: dict[str, Any]) -> ProcessOutput:
        if not self.config.allow_scripts:
            raise AgentError("scripts are disabled on this agent")
        language = request.script_language or ""
        interpreter = self.config.script_interpreters.get(language)
        if not interpreter:
            raise AgentError(f"unsupported script language: {language}")
        encoded = body.get("artifact_b64")
        if not isinstance(encoded, str):
            raise AgentError("script artifact is missing")
        try:
            content = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise AgentError("invalid base64 script artifact") from exc
        if sha256_bytes(content) != request.artifact_sha256:
            raise AgentError("script artifact hash does not match approved SHA-256")
        cwd = self._workdir(request.cwd)
        timeout = min(int(body.get("timeout_seconds", 30)), self.config.max_timeout_seconds)
        output_limit = min(int(body.get("max_output_bytes", self.config.max_output_bytes)), self.config.max_output_bytes)
        with tempfile.TemporaryDirectory(prefix="ops-guard-script-") as temp_dir:
            suffix = ".sh" if language == "shell" else ".py"
            path = Path(temp_dir) / f"approved{suffix}"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
            with os.fdopen(fd, "wb", closefd=True) as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            if sha256_bytes(path.read_bytes()) != request.artifact_sha256:
                raise AgentError("script changed after materialization")
            interpreter_argv = [
                self._resolve_executable(interpreter[0], allow_absolute=True),
                *interpreter[1:],
            ]
            argv = [*interpreter_argv, str(path), *request.argv]
            return await run_argv(
                argv,
                cwd=cwd,
                env=self._minimal_env(),
                timeout_seconds=max(1, timeout),
                max_output_bytes=max(1024, output_limit),
            )

    async def execute_envelope(self, envelope: dict[str, Any]) -> dict[str, Any]:
        started = int(time.time())
        body, request, _approval = self._verify_envelope(envelope)
        self.nonces.claim(request.nonce, request.expires_at)
        if request.kind is RequestKind.SCRIPT:
            output = await self._execute_script(request, body)
        else:
            output = await self._execute_command(request, body)
        finished = int(time.time())
        return {
            "request_id": request.request_id,
            "exit_code": output.exit_code,
            "stdout": output.stdout.decode("utf-8", errors="replace"),
            "stderr": output.stderr.decode("utf-8", errors="replace"),
            "started_at": started,
            "finished_at": finished,
            "truncated": output.truncated,
            "error": None,
        }


async def _run_once(config_path: str) -> int:
    try:
        config = load_agent_config(config_path)
        raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise AgentError("agent envelope exceeds 8 MiB")
        envelope = json.loads(raw.decode("utf-8"))
        if not isinstance(envelope, dict):
            raise AgentError("agent envelope must be a JSON object")
        result = await AgentRuntime(config).execute_envelope(envelope)
        sys.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True))
        sys.stdout.flush()
        return 0
    except (AgentError, ConfigError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        error = {
            "request_id": "unknown",
            "exit_code": 126,
            "stdout": "",
            "stderr": "",
            "started_at": int(time.time()),
            "finished_at": int(time.time()),
            "truncated": False,
            "error": str(exc),
        }
        sys.stdout.write(json.dumps(error, ensure_ascii=False, sort_keys=True))
        sys.stdout.flush()
        return 126


def main() -> None:
    parser = argparse.ArgumentParser(description="Ops Guard remote execution agent")
    parser.add_argument("command", choices=["execute"])
    parser.add_argument(
        "--config",
        default=os.environ.get("OPS_GUARD_AGENT_CONFIG", "/etc/ops-guard/agent.toml"),
    )
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_run_once(args.config)))


if __name__ == "__main__":
    main()
