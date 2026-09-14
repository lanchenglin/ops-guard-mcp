from __future__ import annotations

import time
import unittest
import urllib.parse

from ops_guard.approvals import ApprovalLinkError, ApprovalLinkSigner, DingTalkNotifier


class ApprovalLinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = ApprovalLinkSigner("https://approval.example.com", b"x" * 32)

    @staticmethod
    def params(url: str) -> dict[str, str]:
        parsed = urllib.parse.urlparse(url)
        return {key: values[-1] for key, values in urllib.parse.parse_qs(parsed.query).items()}

    def test_signed_link_verifies(self) -> None:
        expires = int(time.time()) + 60
        url = self.signer.make_url("req", "a" * 64, "approve", expires)
        payload = self.signer.verify(self.params(url))
        self.assertEqual(payload["request_id"], "req")
        self.assertEqual(payload["decision"], "approve")

    def test_modified_decision_fails(self) -> None:
        expires = int(time.time()) + 60
        params = self.params(self.signer.make_url("req", "a" * 64, "approve", expires))
        params["decision"] = "reject"
        with self.assertRaises(ApprovalLinkError):
            self.signer.verify(params)

    def test_expired_link_fails(self) -> None:
        expires = int(time.time()) - 1
        params = self.params(self.signer.make_url("req", "a" * 64, "approve", expires))
        with self.assertRaises(ApprovalLinkError):
            self.signer.verify(params)

    def test_untrusted_card_text_cannot_create_markdown_link(self) -> None:
        value = DingTalkNotifier._safe_card_text("[批准](https://evil.example)\n### forged")
        self.assertNotIn("[", value)
        self.assertNotIn("](", value)
        self.assertNotIn("###", value)


if __name__ == "__main__":
    unittest.main()
