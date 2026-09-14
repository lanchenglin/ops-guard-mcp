from __future__ import annotations

import asyncio, os, tempfile, threading, unittest, urllib.parse, urllib.request
from pathlib import Path
from ops_guard.approvals import NullNotifier
from ops_guard.config import load_gateway_config
from ops_guard.daemon import ApprovalHTTPServer
from ops_guard.service import OpsGuardService


class ApprovalHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(); root = Path(self.temp.name); config_path = root / "ops-guard.toml"
        config_path.write_text(f'''[server]\nstate_dir = "{root / 'state'}"\napproval_base_url = "http://approval.invalid"\napproval_link_secret_env = "HTTP_TEST_APPROVAL_SECRET"\nrequest_ttl_seconds = 300\nauto_execute_on_approval = false\nbind_host = "127.0.0.1"\nbind_port = 0\n\n[dingtalk]\nenabled = false\n\n[[hosts]]\nid = "local"\nenvironment = "dev"\ntransport = "local-agent"\nallow_scripts = false\nallowed_read_roots = ["/tmp"]\nallowed_workdirs = ["/tmp"]\ndefault_workdir = "/tmp"\nagent_secret_env = "HTTP_TEST_AGENT_SECRET"\n''', encoding="utf-8")
        os.environ["HTTP_TEST_APPROVAL_SECRET"] = "a" * 64; os.environ["HTTP_TEST_AGENT_SECRET"] = "b" * 64
        self.service = OpsGuardService(load_gateway_config(config_path), notifier=NullNotifier()); self.server = ApprovalHTTPServer(("127.0.0.1", 0), self.service); self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=3); os.environ.pop("HTTP_TEST_APPROVAL_SECRET", None); os.environ.pop("HTTP_TEST_AGENT_SECRET", None); self.temp.cleanup()

    def test_get_is_confirmation_only_and_post_approves(self) -> None:
        response = asyncio.run(self.service.submit_command("local", ["systemctl", "restart", "nginx"], "integration approval", requester="test", include_approval_links=True)); request_id = response["request"]["request_id"]
        parsed = urllib.parse.urlparse(response["approval_links"]["approve_url"]); approve_url = f"http://127.0.0.1:{self.server.server_address[1]}{parsed.path}?{parsed.query}"
        with urllib.request.urlopen(approve_url, timeout=3) as http_response: self.assertIn("确认批准", http_response.read().decode("utf-8"))
        self.assertEqual(self.service.status(request_id)["status"], "pending_approval")
        form = {key: values[-1] for key, values in urllib.parse.parse_qs(parsed.query).items()}; form["comment"] = "approved in integration test"
        request = urllib.request.Request(approve_url.split("/decision?", 1)[0] + "/decision", data=urllib.parse.urlencode(form).encode(), headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
        with urllib.request.urlopen(request, timeout=3) as http_response: self.assertIn("审批完成", http_response.read().decode("utf-8"))
        status = self.service.status(request_id); self.assertEqual(status["status"], "approved"); self.assertIn("signed-link:", status["approval"]["decided_by"])


if __name__ == "__main__": unittest.main()
