from __future__ import annotations

import asyncio, os, tempfile, unittest
from pathlib import Path
from ops_guard.approvals import NullNotifier
from ops_guard.config import load_gateway_config
from ops_guard.service import OpsGuardService


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(); root = Path(self.temp.name); self.config_path = root / "ops-guard.toml"
        self.config_path.write_text(f'''[server]\nstate_dir = "{root / 'state'}"\napproval_base_url = "http://127.0.0.1:8765"\napproval_link_secret_env = "TEST_APPROVAL_SECRET"\nrequest_ttl_seconds = 300\nauto_execute_on_approval = true\nbind_host = "127.0.0.1"\nbind_port = 8765\n\n[dingtalk]\nenabled = false\n\n[[hosts]]\nid = "local"\nenvironment = "dev"\ntransport = "local-agent"\napprove_sensitive_reads = false\nallow_scripts = true\nallowed_read_roots = ["/tmp"]\nallowed_workdirs = ["/tmp"]\ndefault_workdir = "/tmp"\ntimeout_seconds = 10\nmax_output_bytes = 131072\nagent_secret_env = "TEST_LOCAL_AGENT_SECRET"\n''', encoding="utf-8")
        os.environ["TEST_APPROVAL_SECRET"] = "a" * 64; os.environ["TEST_LOCAL_AGENT_SECRET"] = "b" * 64; self.service = OpsGuardService(load_gateway_config(self.config_path), notifier=NullNotifier())

    def tearDown(self) -> None:
        os.environ.pop("TEST_APPROVAL_SECRET", None); os.environ.pop("TEST_LOCAL_AGENT_SECRET", None); self.temp.cleanup()

    async def test_read_command_auto_executes(self):
        r = await self.service.submit_command("local", ["uptime"], "check host health", requester="test"); self.assertEqual(r["status"], "succeeded"); self.assertEqual(r["result"]["exit_code"], 0)

    async def test_mutation_waits_for_approval(self):
        r = await self.service.submit_command("local", ["systemctl", "restart", "nginx"], "restart after diagnostics", requester="test"); self.assertEqual(r["status"], "pending_approval"); self.assertNotIn("approval_links", r); self.assertTrue(r["approval_request"]["required"])

    async def test_forbidden_command_is_blocked(self):
        r = await self.service.submit_command("local", ["bash", "-c", "id"], "attempt bypass", requester="test"); self.assertEqual(r["status"], "blocked")

    async def test_script_is_immutable_and_pending(self):
        r = await self.service.stage_script("local", "python", "import subprocess\nsubprocess.run(['id'])\n", [], "diagnostic script", requester="test"); self.assertEqual(r["status"], "pending_approval"); self.assertEqual(len(r["request"]["artifact_sha256"]), 64); self.assertTrue(r["request"]["metadata"]["script_findings"])

    async def test_admin_can_explicitly_request_links_but_default_cannot(self):
        hidden = await self.service.submit_command("local", ["systemctl", "restart", "nginx"], "hidden", requester="test"); self.assertNotIn("approval_links", hidden)
        shown = await self.service.submit_command("local", ["systemctl", "restart", "nginx"], "admin", requester="test", include_approval_links=True); self.assertIn("approval_links", shown)

    async def test_executor_configuration_failure_finishes_request(self):
        r = await self.service.submit_command("local", ["systemctl", "restart", "nginx"], "fail closed", requester="test"); rid = r["request"]["request_id"]; self.service.decide(rid, r["request_digest"], allow=True, decided_by="tester"); os.environ.pop("TEST_LOCAL_AGENT_SECRET", None); result = await self.service.execute_approved(rid); self.assertEqual(result["status"], "failed")

    async def test_audit_does_not_store_command_output(self):
        await self.service.submit_command("local", ["uptime"], "audit", requester="test"); completed = [row for row in self.service.audit_tail(20) if row["event"] == "execution.completed"][-1]; self.assertNotIn("stdout", completed["data"]); self.assertIn("stdout_sha256", completed["data"])


if __name__ == "__main__": unittest.main()
