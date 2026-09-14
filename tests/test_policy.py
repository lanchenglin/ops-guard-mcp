from __future__ import annotations

import unittest
from dataclasses import replace

from ops_guard.models import HostConfig, PolicyAction, RequestKind, Risk
from ops_guard.policy import CommandPolicy


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = CommandPolicy()
        self.host = HostConfig(host_id="test", environment="prod", transport="local-agent", allow_scripts=True, allowed_read_roots=("/var/log", "/tmp"), allowed_workdirs=("/tmp",))

    def assert_decision(self, argv: list[str], risk: Risk, action: PolicyAction, *, cwd: str | None = "/tmp") -> None:
        decision = self.policy.evaluate(argv, self.host, cwd=cwd)
        self.assertEqual(decision.risk, risk, decision); self.assertEqual(decision.action, action, decision)

    def test_read_only_diagnostic_is_allowed(self) -> None:
        self.assert_decision(["uptime"], Risk.READ, PolicyAction.ALLOW)
        self.assert_decision(["ss", "-lntp"], Risk.READ, PolicyAction.ALLOW)
        self.assert_decision(["journalctl", "-u", "nginx", "-n", "200", "--no-pager"], Risk.SENSITIVE_READ, PolicyAction.ALLOW)

    def test_mutation_requires_approval(self) -> None:
        self.assert_decision(["systemctl", "restart", "nginx"], Risk.MUTATE, PolicyAction.REQUIRE_APPROVAL)
        self.assert_decision(["kill", "123"], Risk.MUTATE, PolicyAction.REQUIRE_APPROVAL)
        self.assert_decision(["rm", "/tmp/a"], Risk.MUTATE, PolicyAction.REQUIRE_APPROVAL)

    def test_shells_interpreters_and_wrappers_are_denied(self) -> None:
        for argv in (["bash", "-c", "id"], ["python3", "-c", "import os"], ["env", "bash", "-c", "id"], ["nohup", "systemctl", "restart", "nginx"], ["xargs", "rm"], ["ssh", "other-host", "id"]):
            with self.subTest(argv=argv): self.assert_decision(argv, Risk.FORBIDDEN, PolicyAction.DENY)

    def test_argument_level_escape_rules(self) -> None:
        for argv in (["find", "/tmp", "-exec", "sh", "-c", "id", ";"], ["awk", "BEGIN { system(\"id\") }"], ["tar", "--checkpoint-action=exec=sh shell.sh", "-cf", "x.tar", "/tmp"], ["git", "-c", "alias.x=!sh -c id", "x"], ["docker", "exec", "container", "id"], ["kubectl", "exec", "pod", "--", "id"], ["kubectl", "port-forward", "pod/x", "8080:80"]):
            with self.subTest(argv=argv): self.assert_decision(argv, Risk.FORBIDDEN, PolicyAction.DENY)

    def test_recent_allowlist_bypass_vectors_are_not_read_only(self) -> None:
        cases = ((["env", "sudo", "id"], Risk.FORBIDDEN, PolicyAction.DENY), (["sed", "1e id", "/var/log/syslog"], Risk.FORBIDDEN, PolicyAction.DENY), (["find", "/var/log", "-fprintf", "/tmp/result", "x"], Risk.MUTATE, PolicyAction.REQUIRE_APPROVAL), (["find", "/var/log", "-delete"], Risk.MUTATE, PolicyAction.REQUIRE_APPROVAL))
        for argv, risk, action in cases:
            with self.subTest(argv=argv): self.assert_decision(argv, risk, action)

    def test_command_specific_edge_cases(self) -> None:
        self.assert_decision(["hostname", "-F", "/tmp/name"], Risk.PRIVILEGED, PolicyAction.REQUIRE_APPROVAL)
        self.assert_decision(["loginctl", "terminate-user", "alice"], Risk.PRIVILEGED, PolicyAction.REQUIRE_APPROVAL)
        self.assert_decision(["docker", "stats"], Risk.FORBIDDEN, PolicyAction.DENY)
        self.assert_decision(["docker", "stats", "--no-stream"], Risk.SENSITIVE_READ, PolicyAction.ALLOW)
        self.assert_decision(["kubectl", "get", "--raw=/api"], Risk.FORBIDDEN, PolicyAction.DENY)
        self.assert_decision(["nginx", "-t"], Risk.READ, PolicyAction.ALLOW)
        self.assert_decision(["nginx", "-c", "/tmp/evil.conf", "-t"], Risk.FORBIDDEN, PolicyAction.DENY)

    def test_permanently_blocks_root_deletion(self) -> None:
        self.assert_decision(["rm", "-rf", "/"], Risk.FORBIDDEN, PolicyAction.DENY)
        self.assert_decision(["rm", "--no-preserve-root", "-rf", "/"], Risk.FORBIDDEN, PolicyAction.DENY)

    def test_unknown_command_is_denied(self) -> None:
        self.assert_decision(["my-custom-helper", "--safe"], Risk.FORBIDDEN, PolicyAction.DENY)

    def test_file_reads_must_stay_in_roots(self) -> None:
        self.assert_decision(["cat", "/var/log/syslog"], Risk.SENSITIVE_READ, PolicyAction.ALLOW)
        self.assert_decision(["cat", "/root/.ssh/id_rsa"], Risk.FORBIDDEN, PolicyAction.DENY)
        self.assert_decision(["cat", "../etc/shadow"], Risk.FORBIDDEN, PolicyAction.DENY, cwd="/tmp")

    def test_sensitive_reads_can_require_approval(self) -> None:
        host = replace(self.host, approve_sensitive_reads=True)
        self.assertEqual(self.policy.evaluate(["dmesg"], host).action, PolicyAction.REQUIRE_APPROVAL)

    def test_script_is_exact_content_approval_only(self) -> None:
        decision = self.policy.evaluate(["--flag"], self.host, kind=RequestKind.SCRIPT, script_language="python")
        self.assertEqual(decision.risk, Risk.PRIVILEGED); self.assertEqual(decision.action, PolicyAction.REQUIRE_APPROVAL)
        denied = self.policy.evaluate(["&&"], self.host, kind=RequestKind.SCRIPT, script_language="shell")
        self.assertEqual(denied.action, PolicyAction.DENY)

    def test_executable_path_spoofing_is_denied(self) -> None:
        for argv in (["/tmp/uptime"], ["./uptime"], ["../bin/uptime"]):
            with self.subTest(argv=argv): self.assert_decision(argv, Risk.FORBIDDEN, PolicyAction.DENY)

    def test_high_risk_option_edge_cases(self) -> None:
        self.assert_decision(["dmesg"], Risk.SENSITIVE_READ, PolicyAction.ALLOW)
        self.assert_decision(["dmesg", "--clear"], Risk.PRIVILEGED, PolicyAction.REQUIRE_APPROVAL)
        self.assert_decision(["dmesg", "--file=/etc/shadow"], Risk.FORBIDDEN, PolicyAction.DENY)
        self.assert_decision(["pgrep", "--signal=KILL", "nginx"], Risk.MUTATE, PolicyAction.REQUIRE_APPROVAL)
        self.assert_decision(["top", "-b", "-n1"], Risk.SENSITIVE_READ, PolicyAction.ALLOW)
        self.assert_decision(["top", "-b", "-n", "2"], Risk.FORBIDDEN, PolicyAction.DENY)
        self.assert_decision(["systemctl", "-Hprod-2", "status", "nginx"], Risk.FORBIDDEN, PolicyAction.DENY)
        self.assert_decision(["loginctl", "--host=prod-2", "list-users"], Risk.FORBIDDEN, PolicyAction.DENY)
        self.assert_decision(["kubectl", "get", "secrets"], Risk.PRIVILEGED, PolicyAction.REQUIRE_APPROVAL)
        self.assert_decision(["kubectl", "cluster-info", "dump"], Risk.FORBIDDEN, PolicyAction.DENY)
        self.assert_decision(["nginx", "-c/tmp/evil.conf", "-t"], Risk.FORBIDDEN, PolicyAction.DENY)
        self.assert_decision(["date", "010112002026"], Risk.PRIVILEGED, PolicyAction.REQUIRE_APPROVAL)
        self.assert_decision(["rm", "-rf", "//"], Risk.FORBIDDEN, PolicyAction.DENY)


if __name__ == "__main__": unittest.main()
