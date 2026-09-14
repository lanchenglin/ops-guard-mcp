from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
import time
from pathlib import Path
from typing import Any

from .canonical import request_digest
from .models import ApprovalRecord, ExecutionResult, OperationRequest, RequestStatus


class StoreError(RuntimeError):
    pass


class RequestStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    @contextmanager
    def _db(self):
        db = self._connect()
        try:
            yield db
        finally:
            db.close()

    def _initialize(self) -> None:
        with self._db() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS requests (
                    request_id TEXT PRIMARY KEY,
                    request_json TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    last_error TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status, expires_at);

                CREATE TABLE IF NOT EXISTS approvals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    decided_at INTEGER NOT NULL,
                    decided_by TEXT NOT NULL,
                    comment TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY(request_id) REFERENCES requests(request_id)
                );

                CREATE TABLE IF NOT EXISTS executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY(request_id) REFERENCES requests(request_id)
                );

                CREATE TABLE IF NOT EXISTS integration_nonces (
                    nonce TEXT PRIMARY KEY,
                    seen_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_integration_nonces_seen_at
                    ON integration_nonces(seen_at);
                """
            )

    def create(self, request: OperationRequest, status: RequestStatus) -> str:
        digest = request_digest(request)
        now = int(time.time())
        with self._db() as db:
            try:
                db.execute(
                    """
                    INSERT INTO requests(
                        request_id, request_json, request_digest, status,
                        created_at, expires_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request.request_id,
                        json.dumps(request.to_dict(), ensure_ascii=False, sort_keys=True),
                        digest,
                        status.value,
                        request.created_at,
                        request.expires_at,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise StoreError(f"request already exists: {request.request_id}") from exc
        return digest

    def get(self, request_id: str) -> tuple[OperationRequest, str, RequestStatus, str | None]:
        with self._db() as db:
            row = db.execute(
                "SELECT request_json, request_digest, status, last_error FROM requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
        if row is None:
            raise StoreError(f"request not found: {request_id}")
        request = OperationRequest.from_dict(json.loads(row["request_json"]))
        digest = str(row["request_digest"])
        if request_digest(request) != digest:
            raise StoreError("stored request digest mismatch")
        return request, digest, RequestStatus(row["status"]), row["last_error"]

    def list_by_status(self, *statuses: RequestStatus, limit: int = 100) -> list[dict[str, Any]]:
        if not statuses:
            return []
        placeholders = ",".join("?" for _ in statuses)
        with self._db() as db:
            rows = db.execute(
                f"""
                SELECT request_id, request_json, request_digest, status, updated_at, last_error
                FROM requests
                WHERE status IN ({placeholders})
                ORDER BY created_at ASC
                LIMIT ?
                """,  # noqa: S608 - placeholders are generated, values stay parameterized.
                (*[status.value for status in statuses], limit),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            request = OperationRequest.from_dict(json.loads(row["request_json"]))
            digest = str(row["request_digest"])
            if request_digest(request) != digest:
                self.mark_blocked(request.request_id, "stored request digest mismatch")
                continue
            result.append(
                {
                    "request": request.to_dict(),
                    "request_digest": digest,
                    "status": row["status"],
                    "updated_at": row["updated_at"],
                    "last_error": row["last_error"],
                }
            )
        return result

    def approve_automatically(self, request_id: str, digest: str) -> ApprovalRecord:
        return self.decide(
            request_id,
            digest,
            allow=True,
            decided_by="policy:auto",
            comment="automatically allowed by local policy",
        )

    def decide(
        self,
        request_id: str,
        digest: str,
        *,
        allow: bool,
        decided_by: str,
        comment: str = "",
    ) -> ApprovalRecord:
        now = int(time.time())
        decision = "approved" if allow else "rejected"
        new_status = RequestStatus.APPROVED if allow else RequestStatus.REJECTED
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT request_digest, status, expires_at FROM requests WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                if row is None:
                    raise StoreError(f"request not found: {request_id}")
                if str(row["request_digest"]) != digest:
                    raise StoreError("approval digest does not match request")
                status = RequestStatus(row["status"])
                if status not in {
                    RequestStatus.PENDING_APPROVAL,
                    RequestStatus.APPROVED,
                    RequestStatus.REJECTED,
                }:
                    raise StoreError(f"request cannot be decided from status {status.value}")
                if int(row["expires_at"]) < now:
                    db.execute(
                        "UPDATE requests SET status = ?, updated_at = ? WHERE request_id = ?",
                        (RequestStatus.EXPIRED.value, now, request_id),
                    )
                    db.execute("COMMIT")
                    raise StoreError("request has expired")
                if status in {RequestStatus.APPROVED, RequestStatus.REJECTED}:
                    expected_status = RequestStatus.APPROVED if allow else RequestStatus.REJECTED
                    if status is not expected_status:
                        raise StoreError(
                            f"request already has final decision {status.value}; decision cannot be changed"
                        )
                    existing = db.execute(
                        """
                        SELECT request_id, request_digest, decision, decided_at, decided_by, comment
                        FROM approvals
                        WHERE request_id = ?
                        ORDER BY id DESC LIMIT 1
                        """,
                        (request_id,),
                    ).fetchone()
                    if existing:
                        db.execute("COMMIT")
                        return ApprovalRecord(**dict(existing))
                    raise StoreError(f"{status.value} request has no approval record")
                db.execute(
                    "UPDATE requests SET status = ?, updated_at = ?, last_error = NULL WHERE request_id = ?",
                    (new_status.value, now, request_id),
                )
                db.execute(
                    """
                    INSERT INTO approvals(
                        request_id, request_digest, decision, decided_at, decided_by, comment
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (request_id, digest, decision, now, decided_by, comment),
                )
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        return ApprovalRecord(request_id, digest, decision, now, decided_by, comment)

    def consume_integration_nonce(
        self,
        nonce: str,
        *,
        seen_at: int | None = None,
        retention_seconds: int = 600,
    ) -> None:
        """Atomically accept an integration nonce once and reject replays."""
        now = int(time.time()) if seen_at is None else int(seen_at)
        cutoff = now - max(60, int(retention_seconds))
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("DELETE FROM integration_nonces WHERE seen_at < ?", (cutoff,))
                try:
                    db.execute(
                        "INSERT INTO integration_nonces(nonce, seen_at) VALUES (?, ?)",
                        (nonce, now),
                    )
                except sqlite3.IntegrityError as exc:
                    raise StoreError("integration nonce has already been used") from exc
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise

    def get_approval(self, request_id: str) -> ApprovalRecord | None:
        with self._db() as db:
            row = db.execute(
                """
                SELECT request_id, request_digest, decision, decided_at, decided_by, comment
                FROM approvals
                WHERE request_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (request_id,),
            ).fetchone()
        return ApprovalRecord(**dict(row)) if row else None

    def claim_for_execution(self, request_id: str) -> tuple[OperationRequest, str, ApprovalRecord]:
        now = int(time.time())
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT request_json, request_digest, status, expires_at FROM requests WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                if row is None:
                    raise StoreError(f"request not found: {request_id}")
                digest = str(row["request_digest"])
                try:
                    request = OperationRequest.from_dict(json.loads(row["request_json"]))
                except Exception as exc:
                    db.execute(
                        "UPDATE requests SET status = ?, updated_at = ?, last_error = ? WHERE request_id = ?",
                        (
                            RequestStatus.BLOCKED.value,
                            now,
                            "stored request JSON is invalid",
                            request_id,
                        ),
                    )
                    db.execute("COMMIT")
                    raise StoreError("stored request JSON is invalid") from exc
                if request_digest(request) != digest:
                    db.execute(
                        "UPDATE requests SET status = ?, updated_at = ?, last_error = ? WHERE request_id = ?",
                        (
                            RequestStatus.BLOCKED.value,
                            now,
                            "stored request digest mismatch",
                            request_id,
                        ),
                    )
                    db.execute("COMMIT")
                    raise StoreError("stored request was modified after approval")
                status = RequestStatus(row["status"])
                if int(row["expires_at"]) < now:
                    db.execute(
                        "UPDATE requests SET status = ?, updated_at = ? WHERE request_id = ?",
                        (RequestStatus.EXPIRED.value, now, request_id),
                    )
                    db.execute("COMMIT")
                    raise StoreError("request has expired")
                if status is not RequestStatus.APPROVED:
                    raise StoreError(f"request is not approved; current status is {status.value}")
                approval_row = db.execute(
                    """
                    SELECT request_id, request_digest, decision, decided_at, decided_by, comment
                    FROM approvals
                    WHERE request_id = ? AND decision = 'approved'
                    ORDER BY id DESC LIMIT 1
                    """,
                    (request_id,),
                ).fetchone()
                if approval_row is None:
                    raise StoreError("approved request has no approval record")
                if str(approval_row["request_digest"]) != digest:
                    raise StoreError("approval is bound to a different request digest")
                changed = db.execute(
                    """
                    UPDATE requests SET status = ?, updated_at = ?
                    WHERE request_id = ? AND status = ?
                    """,
                    (
                        RequestStatus.EXECUTING.value,
                        now,
                        request_id,
                        RequestStatus.APPROVED.value,
                    ),
                ).rowcount
                if changed != 1:
                    raise StoreError("request was claimed by another executor")
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        return request, digest, ApprovalRecord(**dict(approval_row))

    def complete(self, result: ExecutionResult) -> None:
        status = RequestStatus.SUCCEEDED if result.exit_code == 0 and not result.error else RequestStatus.FAILED
        now = int(time.time())
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT status FROM requests WHERE request_id = ?", (result.request_id,)
                ).fetchone()
                if row is None:
                    raise StoreError(f"request not found: {result.request_id}")
                if RequestStatus(row["status"]) is not RequestStatus.EXECUTING:
                    raise StoreError("only an executing request can be completed")
                db.execute(
                    """
                    INSERT INTO executions(request_id, result_json, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (
                        result.request_id,
                        json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True),
                        now,
                    ),
                )
                db.execute(
                    """
                    UPDATE requests SET status = ?, updated_at = ?, last_error = ?
                    WHERE request_id = ?
                    """,
                    (status.value, now, result.error, result.request_id),
                )
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise

    def mark_blocked(self, request_id: str, error: str) -> None:
        now = int(time.time())
        with self._db() as db:
            db.execute(
                "UPDATE requests SET status = ?, updated_at = ?, last_error = ? WHERE request_id = ?",
                (RequestStatus.BLOCKED.value, now, error, request_id),
            )

    def result(self, request_id: str) -> ExecutionResult | None:
        with self._db() as db:
            row = db.execute(
                "SELECT result_json FROM executions WHERE request_id = ? ORDER BY id DESC LIMIT 1",
                (request_id,),
            ).fetchone()
        if row is None:
            return None
        value = json.loads(row["result_json"])
        return ExecutionResult(**value)
