from __future__ import annotations

import base64
import os
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from ops_guard.agent import AgentError, AgentRuntime
from ops_guard.canonical import hmac_hex, request_digest, sha256_bytes
from ops_guard.config import AgentConfig, DEFAULT_TRUSTED_EXECUTABLE_DIRS
from ops_guard.models import ApprovalRecord, OperationRequest, RequestKind, Risk


class AgentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        os.environ["TEST_AGENT_SECRET"] = "s" * 64
        self.config = AgentConfig(path=Path(self.temp.name) / "agent.toml", host_id="host-1", secret_env="TEST_AGENT_SECRET", secret_file=None, nonce_db=Path(self.temp.name) / "nonces.sqlite3", allowed_read_roots=("/tmp",), allowed_workdirs=("/tmp",), default_workdir="/tmp", allow_scripts=True, script_interpreters={"shell": ("/bin/bash", "--noprofile", "--norc"), "python": ("/usr/bin/python3", "-I", "-B")}, trusted_executable_dirs=DEFAULT_TRUSTED_EXECUTABLE_DIRS, max_timeout_seconds=10, max_output_bytes=128 * 1024)
        self.runtime = AgentRuntime(self.config)

    def tearDown(self) -> None:
        os.environ.pop("TEST_AGENT_SECRET", None)
        self.temp.cleanup()

    def request(self, *, request_id: str, argv: tuple[str, ...], kind: RequestKind = RequestKind.COMMAND, risk: Risk = Risk.READ, artifact_sha256: str | None = None, language: str | None = None) -> OperationRequest:
        now = int(time.time())
        return OperationRequest(request_id=request_id, host_id="host-1", kind=kind, argv=argv, reason="test", requester="tester", risk=risk, rule_id="test.rule", cwd="/tmp", created_at=now, expires_at=now + 60, nonce=f"nonce-{request_id}", artifact_sha256=artifact_sha256, script_language=language)

    def envelope(self, request: OperationRequest, *, artifact: bytes | None = None) -> dict[str, object]:
        digest = request_digest(request)
        approval = ApprovalRecord(request_id=request.request_id, request_digest=digest, decision="approved", decided_at=int(time.time()), decided_by="alice")
        body: dict[str, object] = {"version": 1, "request": request.to_dict(), "request_digest": digest, "approval": approval.to_dict(), "timeout_seconds": 5, "max_output_bytes": 65536}
        if artifact is not None:
            body["artifact_b64"] = base64.b64encode(artifact).decode()
        return {"body": body, "signature": hmac_hex(b"s" * 64, body)}

    async def test_executes_argv_and_rejects_replay(self) -> None:
        request = self.request(request_id="uptime", argv=("uptime",))
        envelope = self.envelope(request)
        result = await self.runtime.execute_envelope(envelope)
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["stdout"].strip())
        with self.assertRaises(AgentError):
            await self.runtime.execute_envelope(envelope)

    async def test_rejects_gateway_risk_downgrade(self) -> None:
        request = self.request(request_id="downgrade", argv=("systemctl", "restart", "nginx"), risk=Risk.READ)
        with self.assertRaisesRegex(AgentError, "understated"):
            await self.runtime.execute_envelope(self.envelope(request))

    async def test_rejects_tampered_signature(self) -> None:
        request = self.request(request_id="bad-signature", argv=("uptime",))
        envelope = self.envelope(request)
        envelope["signature"] = "0" * 64
        with self.assertRaisesRegex(AgentError, "signature"):
            await self.runtime.execute_envelope(envelope)

    async def test_script_hash_is_checked(self) -> None:
        approved = b'print("approved")\n'
        request = self.request(request_id="script-hash", argv=(), kind=RequestKind.SCRIPT, risk=Risk.PRIVILEGED, artifact_sha256=sha256_bytes(approved), language="python")
        with self.assertRaisesRegex(AgentError, "hash"):
            await self.runtime.execute_envelope(self.envelope(request, artifact=b'print("changed")\n'))

    async def test_exact_python_script_executes(self) -> None:
        content = b'print("ops-guard-ok")\n'
        request = self.request(request_id="script-ok", argv=(), kind=RequestKind.SCRIPT, risk=Risk.PRIVILEGED, artifact_sha256=sha256_bytes(content), language="python")
        result = await self.runtime.execute_envelope(self.envelope(request, artifact=content))
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("ops-guard-ok", result["stdout"])

    async def test_model_supplied_executable_path_is_denied(self) -> None:
        request = self.request(request_id="path-spoof", argv=("/tmp/uptime",))
        with self.assertRaisesRegex(AgentError, "agent policy denied"):
            await self.runtime.execute_envelope(self.envelope(request))

    async def test_writable_shadow_binary_is_fail_closed(self) -> None:
        writable_bin = Path(self.temp.name) / "bin"
        writable_bin.mkdir()
        fake = writable_bin / "uptime"
        fake.write_text("#!/bin/sh\necho fake\n", encoding="utf-8")
        fake.chmod(0o777)
        runtime = AgentRuntime(replace(self.config, nonce_db=Path(self.temp.name) / "shadow-nonces.sqlite3", trusted_executable_dirs=(str(writable_bin), "/usr/bin", "/bin")))
        request = self.request(request_id="shadow", argv=("uptime",))
        with self.assertRaisesRegex(AgentError, "writable by the Agent account"):
            await runtime.execute_envelope(self.envelope(request))


if __name__ == "__main__":
    unittest.main()
