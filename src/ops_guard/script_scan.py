from __future__ import annotations

import ast
import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScriptFinding:
    severity: str
    rule_id: str
    message: str
    line: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "severity": self.severity,
            "rule_id": self.rule_id,
            "message": self.message,
            "line": self.line,
        }


SHELL_RULES: tuple[tuple[str, re.Pattern[str], str, str], ...] = (
    ("critical", re.compile(r"\brm\s+[^\n]*-[^\n]*r[^\n]*\s+/(?:\s|$|\*)"), "shell.rm-root", "recursive removal of a root path"),
    ("critical", re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), "shell.fork-bomb", "fork bomb pattern"),
    ("high", re.compile(r"(?:curl|wget)[^\n|]*\|\s*(?:sh|bash|zsh)\b", re.I), "shell.download-pipe", "download piped directly to a shell"),
    ("high", re.compile(r"\b(?:eval|source|\.)\s+\$", re.I), "shell.dynamic-eval", "dynamic shell evaluation/source"),
    ("high", re.compile(r"authorized_keys|/etc/(?:cron|systemd)|crontab\b", re.I), "shell.persistence", "persistence or SSH trust modification"),
    ("high", re.compile(r"\b(?:nc|netcat|socat)\b[^\n]*(?:-e|exec:)", re.I), "shell.reverse-shell", "network command execution primitive"),
    ("medium", re.compile(r"\b(?:base64|xxd)\b[^\n]*\|\s*(?:sh|bash|python|perl)\b", re.I), "shell.encoded-exec", "encoded payload decoded into an interpreter"),
    ("medium", re.compile(r"\b(?:sudo|su|doas|pkexec)\b", re.I), "shell.privilege", "privilege escalation command"),
)


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[ScriptFinding] = []

    def _add(self, node: ast.AST, severity: str, rule_id: str, message: str) -> None:
        self.findings.append(
            ScriptFinding(severity, rule_id, message, getattr(node, "lineno", None))
        )

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        names = {alias.name.split(".", 1)[0] for alias in node.names}
        for name in names & {"subprocess", "socket", "ctypes", "pty"}:
            self._add(node, "high", f"python.import-{name}", f"imports execution/escape-capable module {name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        name = (node.module or "").split(".", 1)[0]
        if name in {"subprocess", "socket", "ctypes", "pty"}:
            self._add(node, "high", f"python.import-{name}", f"imports execution/escape-capable module {name}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        qualified = ""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            qualified = f"{node.func.value.id}.{node.func.attr}"
        elif isinstance(node.func, ast.Name):
            qualified = node.func.id
        high_calls = {
            "os.system",
            "os.popen",
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_call",
            "subprocess.check_output",
            "shutil.rmtree",
            "eval",
            "exec",
            "compile",
            "__import__",
        }
        if qualified in high_calls:
            self._add(node, "high", "python.dynamic-exec", f"calls {qualified}")
        if qualified == "open" and len(node.args) >= 2:
            mode = node.args[1]
            if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(
                flag in mode.value for flag in "wax+"
            ):
                self._add(node, "medium", "python.file-write", "opens a file in write/append/update mode")
        self.generic_visit(node)


def scan_script(language: str, content: str) -> list[ScriptFinding]:
    if language == "shell":
        findings: list[ScriptFinding] = []
        for severity, pattern, rule_id, message in SHELL_RULES:
            for match in pattern.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                findings.append(ScriptFinding(severity, rule_id, message, line))
        return findings
    if language == "python":
        try:
            tree = ast.parse(content)
        except SyntaxError as exc:
            return [ScriptFinding("high", "python.syntax", str(exc), exc.lineno)]
        visitor = _PythonVisitor()
        visitor.visit(tree)
        return visitor.findings
    return [ScriptFinding("high", "script.unsupported", "unsupported script language")]
