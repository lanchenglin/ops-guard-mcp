from __future__ import annotations

import sqlite3, tempfile, time, unittest
from dataclasses import replace
from pathlib import Path
from ops_guard.canonical import request_digest
from ops_guard.models import OperationRequest, RequestKind, RequestStatus, Risk
from ops_guard.store import RequestStore, StoreError


def make_request(*, expires_at: int | None = None) -> OperationRequest:
    now = int(time.time()); return OperationRequest(request_id="req-1", host_id="host-1", kind=RequestKind.COMMAND, argv=("systemctl", "restart", "nginx"), reason="test", requester="tester", risk=Risk.MUTATE, rule_id="systemctl.mutate", cwd="/tmp", created_at=now, expires_at=expires_at if expires_at is not None else now + 300, nonce="nonce-1")


class StoreTests(unittest.TestCase):
    def setUp(self): self.temp = tempfile.TemporaryDirectory(); self.store = RequestStore(Path(self.temp.name) / "store.sqlite3")
    def tearDown(self): self.temp.cleanup()

    def test_digest_changes_for_every_security_field(self):
        r = make_request(); base = request_digest(r); self.assertNotEqual(base, request_digest(replace(r, host_id="host-2"))); self.assertNotEqual(base, request_digest(replace(r, argv=("uptime",)))); self.assertNotEqual(base, request_digest(replace(r, expires_at=r.expires_at + 1))); self.assertNotEqual(base, request_digest(replace(r, nonce="nonce-2")))

    def test_approval_is_bound_to_digest_and_claim_is_once(self):
        r = make_request(); d = self.store.create(r, RequestStatus.PENDING_APPROVAL)
        with self.assertRaises(StoreError): self.store.decide(r.request_id, "0" * 64, allow=True, decided_by="alice")
        self.store.decide(r.request_id, d, allow=True, decided_by="alice"); claimed, cd, approval = self.store.claim_for_execution(r.request_id); self.assertEqual(claimed, r); self.assertEqual(cd, d); self.assertEqual(approval.decided_by, "alice")
        with self.assertRaises(StoreError): self.store.claim_for_execution(r.request_id)

    def test_final_approval_decision_cannot_be_flipped(self):
        r = make_request(); d = self.store.create(r, RequestStatus.PENDING_APPROVAL); self.store.decide(r.request_id, d, allow=True, decided_by="alice")
        with self.assertRaisesRegex(StoreError, "cannot be changed"): self.store.decide(r.request_id, d, allow=False, decided_by="mallory")

    def test_integration_nonce_is_single_use(self):
        self.store.consume_integration_nonce("n" * 24)
        with self.assertRaisesRegex(StoreError, "already been used"): self.store.consume_integration_nonce("n" * 24)

    def test_expired_request_cannot_be_approved(self):
        r = make_request(expires_at=int(time.time()) - 1); d = self.store.create(r, RequestStatus.PENDING_APPROVAL)
        with self.assertRaises(StoreError): self.store.decide(r.request_id, d, allow=True, decided_by="alice")
        self.assertEqual(self.store.get(r.request_id)[2], RequestStatus.EXPIRED)

    def test_tampered_request_is_blocked_before_claim(self):
        r = make_request(); d = self.store.create(r, RequestStatus.PENDING_APPROVAL); self.store.decide(r.request_id, d, allow=True, decided_by="alice")
        with sqlite3.connect(self.store.path) as db: db.execute("UPDATE requests SET request_json = replace(request_json, 'nginx', 'sshd') WHERE request_id = ?", (r.request_id,))
        with self.assertRaisesRegex(StoreError, "modified after approval"): self.store.claim_for_execution(r.request_id)


if __name__ == "__main__": unittest.main()
