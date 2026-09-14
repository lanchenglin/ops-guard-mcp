from __future__ import annotations

import asyncio, json, os, tempfile, threading, time, unittest, urllib.error, urllib.request
from pathlib import Path

from ops_guard.approvals import NullNotifier
from ops_guard.canonical import hmac_hex
from ops_guard.config import load_gateway_config
from ops_guard.daemon import ApprovalHTTPServer
from ops_guard.dingtalk import APPROVE_ACTION, REJECT_ACTION, DingTalkApprovalContext, DingTalkApprovalController, DingTalkHermesBridge, DingTalkOpenAPIClient, card_instance_id, request_id_from_card
from ops_guard.models import OperationRequest, PolicyAction, PolicyDecision, Risk
from ops_guard.service import OpsGuardService


class FakeDingTalkClient(DingTalkOpenAPIClient):
    def __init__(self, config): super().__init__(config); self.calls = []
    def _credential(self): return "client-id", "client-secret"
    def access_token(self): return "token"
    def _request_json(self, method, path, body, *, access_token=None): self.calls.append((method, path, body, access_token)); return {}


class DingTalkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(); root = Path(self.temp.name); self.config_path = root / "ops-guard.toml"
        self.config_path.write_text(f'''[server]\nstate_dir = "{root / 'state'}"\napproval_base_url = "http://127.0.0.1:8765"\napproval_link_secret_env = "DT_TEST_APPROVAL_SECRET"\nrequest_ttl_seconds = 300\nauto_execute_on_approval = false\nbind_host = "127.0.0.1"\nbind_port = 0\n\n[dingtalk]\nenabled = true\nmode = "interactive"\nclient_id_env = "DT_TEST_CLIENT_ID"\nclient_secret_env = "DT_TEST_CLIENT_SECRET"\ncard_template_id = "tpl-1"\ncallback_owner = "hermes"\nbridge_secret_env = "DT_TEST_BRIDGE_SECRET"\nbridge_max_age_seconds = 60\nallowed_approver_user_ids = ["user-1"]\nrequire_context_sender_match = true\ndefault_conversation_type = "1"\ndefault_sender_staff_id = "user-1"\ndefault_sender_nick = "管理员"\n\n[[hosts]]\nid = "local"\nenvironment = "dev"\ntransport = "local-agent"\napprove_sensitive_reads = false\nallow_scripts = false\nallowed_read_roots = ["/tmp"]\nallowed_workdirs = ["/tmp"]\ndefault_workdir = "/tmp"\ntimeout_seconds = 10\nmax_output_bytes = 131072\nagent_secret_env = "DT_TEST_AGENT_SECRET"\n''', encoding="utf-8")
        os.environ["DT_TEST_APPROVAL_SECRET"] = "a" * 64; os.environ["DT_TEST_AGENT_SECRET"] = "b" * 64; os.environ["DT_TEST_BRIDGE_SECRET"] = "c" * 64
        self.config = load_gateway_config(self.config_path); self.service = OpsGuardService(self.config, notifier=NullNotifier())

    def tearDown(self) -> None:
        for name in ("DT_TEST_APPROVAL_SECRET", "DT_TEST_AGENT_SECRET", "DT_TEST_BRIDGE_SECRET"): os.environ.pop(name, None)
        self.temp.cleanup()

    def _pending(self): return asyncio.run(self.service.submit_command("local", ["systemctl", "restart", "nginx"], "test interactive approval", requester="hermes"))

    def test_card_id_round_trip(self):
        r = self._pending(); rid = r["request"]["request_id"]; self.assertEqual(request_id_from_card(card_instance_id(rid)), rid)

    def test_default_dm_target_is_used_without_model_context(self):
        r = self._pending(); request = OperationRequest.from_dict(r["request"]); context = DingTalkApprovalContext.from_config(self.config.dingtalk); self.assertEqual(context.sender_staff_id, "user-1")
        client = FakeDingTalkClient(self.config.dingtalk); links = self.service.link_signer.links(request.request_id, r["request_digest"], request.expires_at); decision = PolicyDecision(Risk.MUTATE, PolicyAction.REQUIRE_APPROVAL, "systemctl.mutate", "test"); client.create_and_deliver_card(request, r["request_digest"], decision, links)
        deliver = [call for call in client.calls if call[1].endswith("/deliver")][0][2]; self.assertEqual(deliver["openSpaceId"], "dtv1.card//IM_ROBOT.user-1")

    def test_verified_card_user_can_approve(self):
        r = self._pending(); controller = DingTalkApprovalController(self.config.dingtalk, self.service); ack, card = controller.handle_verified_event(user_id="user-1", out_track_id=card_instance_id(r["request"]["request_id"]), action=APPROVE_ACTION, source="test"); self.assertEqual(ack, "OK"); self.assertEqual(card["cardData"]["cardParamMap"]["status"], "approved"); self.assertEqual(self.service.status(r["request"]["request_id"])["status"], "approved")

    def test_wrong_dingtalk_user_cannot_approve(self):
        r = self._pending(); controller = DingTalkApprovalController(self.config.dingtalk, self.service); _, card = controller.handle_verified_event(user_id="attacker", out_track_id=card_instance_id(r["request"]["request_id"]), action=APPROVE_ACTION, source="test"); self.assertEqual(card["cardData"]["cardParamMap"]["status"], "denied"); self.assertEqual(self.service.status(r["request"]["request_id"])["status"], "pending_approval")

    def test_hermes_bridge_signature_and_nonce_are_enforced(self):
        r = self._pending(); rid = r["request"]["request_id"]; bridge = DingTalkHermesBridge(self.config.dingtalk, self.service); payload = {"version": 1, "timestamp": int(time.time()), "nonce": "nonce-0123456789abcdef", "user_id": "user-1", "out_track_id": card_instance_id(rid), "action": REJECT_ACTION}; signature = hmac_hex(b"c" * 64, payload); result = bridge.verify_and_handle(payload, signature); self.assertTrue(result["ok"]); self.assertEqual(self.service.status(rid)["status"], "rejected")
        with self.assertRaisesRegex(Exception, "nonce"): bridge.verify_and_handle(payload, signature)

    def test_http_bridge_changes_state_only_with_valid_signature(self):
        r = self._pending(); rid = r["request"]["request_id"]; payload = {"version": 1, "timestamp": int(time.time()), "nonce": "http-nonce-0123456789abcdef", "user_id": "user-1", "out_track_id": card_instance_id(rid), "action": APPROVE_ACTION}; signature = hmac_hex(b"c" * 64, payload)
        server = ApprovalHTTPServer(("127.0.0.1", 0), self.service); thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/integrations/dingtalk/decision"; request = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", "X-Ops-Guard-Signature": signature}, method="POST")
            with urllib.request.urlopen(request, timeout=3) as response: self.assertTrue(json.loads(response.read().decode())["ok"])
            self.assertEqual(self.service.status(rid)["status"], "approved")
            with self.assertRaises(urllib.error.HTTPError): urllib.request.urlopen(request, timeout=3)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=3)

    def test_hermes_bridge_rejects_tampered_payload(self):
        r = self._pending(); payload = {"version": 1, "timestamp": int(time.time()), "nonce": "nonce-0123456789abcdef", "user_id": "user-1", "out_track_id": card_instance_id(r["request"]["request_id"]), "action": APPROVE_ACTION}; signature = hmac_hex(b"c" * 64, payload); payload["action"] = REJECT_ACTION
        with self.assertRaisesRegex(Exception, "signature"): DingTalkHermesBridge(self.config.dingtalk, self.service).verify_and_handle(payload, signature)


if __name__ == "__main__": unittest.main()
