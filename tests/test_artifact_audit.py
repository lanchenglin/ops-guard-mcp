from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from ops_guard.artifacts import ArtifactError, ArtifactStore
from ops_guard.audit import HashChainAuditLog


class ArtifactAndAuditTests(unittest.TestCase):
    def test_artifact_is_content_addressed_and_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp) / "artifacts")
            digest = store.put(b"hello")
            self.assertEqual(store.put(b"hello"), digest)
            self.assertEqual(store.get(digest), b"hello")
            (store.root / f"{digest}.blob").write_bytes(b"tampered")
            with self.assertRaises(ArtifactError): store.get(digest)

    def test_audit_chain_verifies_and_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit.jsonl"; audit = HashChainAuditLog(path)
            audit.append("one", {"token": "secret-value", "value": 1}); audit.append("two", {"value": 2})
            ok, count, _ = audit.verify(); self.assertTrue(ok); self.assertEqual(count, 2)
            records = audit.tail(2); self.assertEqual(records[0]["data"]["token"], "[REDACTED]")
            lines = path.read_text().splitlines(); record = json.loads(lines[0]); record["data"]["value"] = 999; lines[0] = json.dumps(record); path.write_text("\n".join(lines) + "\n")
            ok, _, detail = audit.verify(); self.assertFalse(ok); self.assertIn("hash mismatch", detail)

    def test_concurrent_threads_keep_one_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            audit = HashChainAuditLog(Path(temp) / "audit.jsonl")
            threads = [threading.Thread(target=lambda i=i: audit.append("thread", {"i": i})) for i in range(20)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            ok, count, _ = audit.verify(); self.assertTrue(ok); self.assertEqual(count, 20)


if __name__ == "__main__": unittest.main()
