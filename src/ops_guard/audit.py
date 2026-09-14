from __future__ import annotations

import json
import os
import threading
import time

try:
    import fcntl
except ImportError:  # pragma: no cover - Linux is the production target.
    fcntl = None  # type: ignore[assignment]
from pathlib import Path
from typing import Any

from .canonical import canonical_json, sha256_bytes


SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "private_key",
    "credential",
}


def _redact(value: Any, key: str | None = None) -> Any:
    if key and key.lower() in SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, tuple):
        return [_redact(v) for v in value]
    return value


class AuditError(RuntimeError):
    pass


class HashChainAuditLog:
    """Append-only JSONL hash chain.

    This is tamper-evident, not tamper-proof. Production deployments should anchor the latest
    hash in an external immutable log or SIEM.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.Lock()
        if not self.path.exists():
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(fd)
    @staticmethod
    def _last_hash_from_lines(lines: list[str]) -> str:
        for line in reversed(lines):
            if line.strip():
                return str(json.loads(line)["hash"])
        return "0" * 64

    def append(self, event: str, data: dict[str, Any]) -> str:
        # The gateway MCP and approval daemon are separate processes. A process-local mutex is
        # not enough, so Linux deployments also take an advisory file lock and reread the chain
        # tail while holding it.
        with self._lock, self.path.open("a+", encoding="utf-8") as handle:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                handle.seek(0)
                previous_hash = self._last_hash_from_lines(handle.read().splitlines())
                body = {
                    "version": 1,
                    "timestamp": int(time.time()),
                    "event": event,
                    "data": _redact(data),
                    "previous_hash": previous_hash,
                }
                digest = sha256_bytes(canonical_json(body))
                record = {**body, "hash": digest}
                handle.seek(0, os.SEEK_END)
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
                return digest
            finally:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def verify(self) -> tuple[bool, int, str]:
        previous = "0" * 64
        count = 0
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    return False, count, f"invalid JSON at line {line_number}: {exc}"
                supplied = str(record.pop("hash", ""))
                if record.get("previous_hash") != previous:
                    return False, count, f"previous_hash mismatch at line {line_number}"
                expected = sha256_bytes(canonical_json(record))
                if supplied != expected:
                    return False, count, f"hash mismatch at line {line_number}"
                previous = supplied
                count += 1
        return True, count, previous

    def tail(self, limit: int = 50) -> list[dict[str, Any]]:
        if limit <= 0:
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()[-limit:]
        return [json.loads(line) for line in lines if line.strip()]
