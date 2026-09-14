from __future__ import annotations

import posixpath
import re
from pathlib import PurePosixPath
from typing import Iterable

from .models import HostConfig, PolicyAction, PolicyDecision, RequestKind, Risk


class PolicyError(ValueError):
    pass


FORBIDDEN_EXECUTABLES = {
    "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish",
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs",
    "php", "lua", "tclsh", "sudo", "su", "doas", "pkexec", "run0",
    "env", "nohup", "nice", "ionice", "setsid", "stdbuf", "timeout",
    "chrt", "taskset", "xargs", "watch", "command", "exec", "ssh",
    "scp", "sftp", "rsync", "nsenter", "unshare", "chroot", "screen",
    "tmux", "socat", "nc", "netcat", "vi", "vim", "nvim", "emacs",
    "less", "more", "gdb", "lldb", "make", "cmake",
}

SHELL_OPERATORS = {";", "&&", "||", "|", "&", ">", ">>", "<", "<<", "<<<"}
READ_ONLY_SIMPLE = {"uptime", "uname", "whoami", "id", "who", "w", "free", "df", "vmstat", "iostat", "mpstat", "lsblk"}
SENSITIVE_SIMPLE = {"lsof", "last", "lastlog", "ps", "pidof"}
MUTATING_FILE_COMMANDS = {"cp", "mv", "mkdir", "rmdir", "touch", "truncate", "chmod", "chown", "chgrp", "ln", "install"}
PACKAGE_MANAGERS = {"apt", "apt-get", "apk", "dnf", "yum", "zypper", "pacman", "rpm", "dpkg", "snap", "flatpak", "pip", "pip3", "npm", "pnpm", "yarn"}
PRIVILEGED_SYSTEM_COMMANDS = {"reboot", "poweroff", "halt", "shutdown", "mount", "umount", "swapon", "swapoff", "iptables", "ip6tables", "nft", "firewall-cmd", "modprobe", "rmmod"}
CONTROL_CHARACTER_RE = re.compile(r"[\x00\r\n]")
EXECUTABLE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
ROOT_DESTRUCTIVE_RE = re.compile(r"^/(?:\*|\.)?$|^/(?:bin|boot|dev|etc|home|lib|lib64|opt|proc|root|run|sbin|sys|usr|var)(?:/|$)")


def _decision(host: HostConfig, risk: Risk, rule_id: str, reason: str) -> PolicyDecision:
    if risk is Risk.FORBIDDEN:
        action = PolicyAction.DENY
    elif risk is Risk.READ:
        action = PolicyAction.ALLOW
    elif risk is Risk.SENSITIVE_READ and not host.approve_sensitive_reads:
        action = PolicyAction.ALLOW
    else:
        action = PolicyAction.REQUIRE_APPROVAL
    return PolicyDecision(risk, action, rule_id, reason)


def _normalize(argv: Iterable[str]) -> tuple[str, ...]:
    value = tuple(str(item) for item in argv)
    if not value or not value[0]:
        raise PolicyError("argv must contain an executable")
    exe = value[0]
    if exe != PurePosixPath(exe).name or "/" in exe or "\\" in exe or not EXECUTABLE_NAME_RE.fullmatch(exe):
        raise PolicyError("executable must be a bare trusted command name, not a path")
    if len(value) > 128:
        raise PolicyError("argv contains too many arguments")
    total = 0
    for item in value:
        encoded = item.encode("utf-8")
        total += len(encoded)
        if len(encoded) > 8192:
            raise PolicyError("an argument exceeds 8192 bytes")
        if CONTROL_CHARACTER_RE.search(item):
            raise PolicyError("NUL and newline characters are forbidden in argv")
    if total > 65536:
        raise PolicyError("argv exceeds 65536 bytes")
    return value


def _under(path: str, roots: tuple[str, ...], cwd: str | None) -> bool:
    normalized = posixpath.normpath(path if path.startswith("/") else posixpath.join(cwd or "/tmp", path))
    return any(normalized == root or normalized.startswith(root.rstrip("/") + "/") for root in roots)


def _systemctl(argv: tuple[str, ...]) -> tuple[Risk, str, str]:
    dangerous = {"--root", "--image", "--machine", "-H", "--host", "-M"}
    for arg in argv[1:]:
        if arg in dangerous or any(arg.startswith(v + "=") for v in dangerous if v.startswith("--")) or (arg.startswith("-H") and len(arg) > 2) or (arg.startswith("-M") and len(arg) > 2):
            return Risk.FORBIDDEN, "systemctl.remote-or-root", "systemctl remote/root targeting is forbidden"
    sub = next((arg for arg in argv[1:] if not arg.startswith("-")), "")
    if sub in {"status", "show", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files", "list-dependencies", "cat", "help"}:
        risk = Risk.SENSITIVE_READ if sub in {"status", "show", "cat"} else Risk.READ
        return risk, "systemctl.read", f"systemctl {sub} is read-only"
    if sub in {"start", "stop", "restart", "reload", "try-restart", "reload-or-restart", "reload-or-try-restart", "enable", "disable", "reenable", "mask", "unmask", "preset", "preset-all", "reset-failed", "daemon-reload"}:
        return Risk.MUTATE, "systemctl.mutate", f"systemctl {sub} changes service state"
    if sub in {"edit", "set-property", "link", "revert", "import-environment", "set-environment", "unset-environment", "kill"}:
        return Risk.PRIVILEGED, "systemctl.privileged", f"systemctl {sub} changes system configuration"
    return Risk.FORBIDDEN, "systemctl.unknown", "unrecognized systemctl subcommand"


def _journalctl(argv: tuple[str, ...]) -> tuple[Risk, str, str]:
    for i, arg in enumerate(argv[1:], start=1):
        if arg in {"--rotate", "--flush", "--sync", "--relinquish-var", "--setup-keys", "--update-catalog"} or arg.startswith("--vacuum-"):
            return Risk.PRIVILEGED, "journalctl.mutate", "journal maintenance changes stored journals"
        if arg in {"--file", "--directory", "--root", "--image", "--machine", "--namespace", "-D", "-M"} or arg.startswith(("--file=", "--directory=", "--root=", "--image=", "--machine=", "--namespace=")):
            return Risk.FORBIDDEN, "journalctl.external-source", "external journal sources are forbidden"
        if arg in {"-f", "--follow"}:
            return Risk.FORBIDDEN, "journalctl.follow", "unbounded follow is forbidden"
        value = None
        if arg in {"-n", "--lines"} and i + 1 < len(argv): value = argv[i + 1]
        elif arg.startswith("--lines="): value = arg.split("=", 1)[1]
        elif arg.startswith("-n") and len(arg) > 2: value = arg[2:]
        if value and value.isdigit() and int(value) > 5000:
            return Risk.FORBIDDEN, "journalctl.output-limit", "line count exceeds 5000"
    return Risk.SENSITIVE_READ, "journalctl.read", "journalctl reads potentially sensitive logs"


def _dmesg(argv: tuple[str, ...]) -> tuple[Risk, str, str]:
    for arg in argv[1:]:
        if arg in {"-C", "--clear", "-c", "--read-clear", "-D", "--console-off", "-E", "--console-on", "-n", "--console-level"}:
            return Risk.PRIVILEGED, "dmesg.mutate", "dmesg option changes kernel logging state"
        if arg in {"-F", "--file", "-K", "--kmsg-file"} or arg.startswith(("--file=", "--kmsg-file=")):
            return Risk.FORBIDDEN, "dmesg.external-file", "dmesg cannot read model-selected files"
        if arg in {"-w", "--follow", "-W", "--follow-new", "--noescape"}:
            return Risk.FORBIDDEN, "dmesg.unbounded", "unbounded/unescaped dmesg mode is forbidden"
    return Risk.SENSITIVE_READ, "dmesg.read", "dmesg reads kernel messages"


def _docker(argv: tuple[str, ...]) -> tuple[Risk, str, str]:
    if any(arg in {"-H", "--host", "--context", "--config", "--tlscacert", "--tlscert", "--tlskey"} or arg.startswith(("--host=", "--context=", "--config=")) for arg in argv[1:]):
        return Risk.FORBIDDEN, "docker.remote", "docker daemon/context overrides are forbidden"
    sub = next((arg for arg in argv[1:] if not arg.startswith("-")), "")
    if sub in {"run", "exec", "attach", "build", "compose", "plugin", "context", "save", "load", "cp", "import", "export"}:
        return Risk.FORBIDDEN, "docker.code-exec", f"docker {sub} opens an execution or escape channel"
    if sub in {"start", "stop", "restart", "kill", "rm", "rmi", "pause", "unpause", "rename", "update", "prune", "pull", "push", "tag"}:
        return Risk.MUTATE, "docker.mutate", f"docker {sub} changes runtime state"
    if sub in {"ps", "images", "inspect", "logs", "stats", "top", "info", "version", "events", "network", "volume"}:
        if sub in {"logs", "events"} and any(arg in {"-f", "--follow"} for arg in argv[1:]):
            return Risk.FORBIDDEN, "docker.follow", "unbounded stream is forbidden"
        if sub == "stats" and "--no-stream" not in argv[1:]:
            return Risk.FORBIDDEN, "docker.stats-stream", "docker stats requires --no-stream"
        return Risk.SENSITIVE_READ, "docker.read", f"docker {sub} inspects runtime state"
    return Risk.FORBIDDEN, "docker.unknown", "unrecognized docker subcommand"


def _kubectl(argv: tuple[str, ...]) -> tuple[Risk, str, str]:
    if any(arg == "--raw" or arg.startswith("--raw=") for arg in argv[1:]):
        return Risk.FORBIDDEN, "kubectl.raw", "kubectl --raw bypasses typed policy"
    sub = next((arg for arg in argv[1:] if not arg.startswith("-")), "")
    if sub in {"exec", "debug", "attach", "run", "cp", "port-forward", "proxy", "edit", "kustomize"}:
        return Risk.FORBIDDEN, "kubectl.code-exec", f"kubectl {sub} opens an execution or tunnel channel"
    if sub == "cluster-info" and "dump" in argv[1:]:
        return Risk.FORBIDDEN, "kubectl.cluster-info-dump", "cluster-info dump is forbidden"
    if sub in {"get", "describe"} and any(arg.lower().split(".", 1)[0].rstrip("s") == "secret" for arg in argv[1:]):
        return Risk.PRIVILEGED, "kubectl.secret-read", "reading Kubernetes Secrets requires explicit approval"
    if sub in {"apply", "delete", "scale", "patch", "replace", "create", "label", "annotate", "taint", "cordon", "uncordon", "drain", "rollout", "set", "autoscale"}:
        return Risk.MUTATE, "kubectl.mutate", f"kubectl {sub} changes cluster state"
    if sub in {"get", "describe", "logs", "top", "version", "cluster-info", "api-resources", "api-versions", "explain", "wait"}:
        return Risk.SENSITIVE_READ, "kubectl.read", f"kubectl {sub} inspects cluster state"
    if sub == "auth" and "can-i" in argv[1:]:
        return Risk.SENSITIVE_READ, "kubectl.auth-can-i", "authorization query"
    return Risk.FORBIDDEN, "kubectl.unknown", "unrecognized kubectl subcommand"


def _find(argv: tuple[str, ...], host: HostConfig, cwd: str | None) -> tuple[Risk, str, str]:
    if any(arg in {"-exec", "-execdir", "-ok", "-okdir"} for arg in argv[1:]):
        return Risk.FORBIDDEN, "find.exec", "find execution actions are forbidden"
    if "-delete" in argv[1:]:
        return Risk.MUTATE, "find.delete", "find -delete removes files"
    if any(arg in {"-fprint", "-fprint0", "-fprintf", "-fls"} for arg in argv[1:]):
        return Risk.MUTATE, "find.file-output", "find file-output actions write files"
    root = next((arg for arg in argv[1:] if not arg.startswith("-")), "")
    if not root or not _under(root, host.allowed_read_roots, cwd):
        return Risk.FORBIDDEN, "find.path", "find root must be inside an allowed read root"
    return Risk.SENSITIVE_READ, "find.read", "find is constrained to allowed read roots"


def _rm(argv: tuple[str, ...]) -> tuple[Risk, str, str]:
    operands = [arg for arg in argv[1:] if not arg.startswith("-")]
    recursive = any(arg in {"-r", "-R", "--recursive", "-rf", "-fr"} or (arg.startswith("-") and "r" in arg.lower()) for arg in argv[1:])
    if "--no-preserve-root" in argv[1:]:
        return Risk.FORBIDDEN, "rm.no-preserve-root", "--no-preserve-root is permanently blocked"
    if recursive and any(ROOT_DESTRUCTIVE_RE.match(posixpath.normpath(path)) or posixpath.normpath(path).startswith("//") for path in operands):
        return Risk.FORBIDDEN, "rm.root", "recursive deletion of root/system paths is permanently blocked"
    return Risk.MUTATE, "rm.mutate", "rm deletes files and requires approval"


def _file_read(argv: tuple[str, ...], host: HostConfig, cwd: str | None) -> tuple[Risk, str, str]:
    command = argv[0]
    value_options = {"-n", "--lines", "-c", "--bytes", "--pid", "--sleep-interval", "--max-unchanged-stats", "--max-depth", "--block-size"}
    paths: list[str] = []
    skip = False
    for arg in argv[1:]:
        if skip:
            skip = False
            continue
        if arg in value_options:
            skip = True
            continue
        if arg == "--":
            continue
        if arg.startswith("-"):
            continue
        paths.append(arg)
    if command == "tail" and any(arg in {"-f", "--follow", "-F"} for arg in argv[1:]):
        return Risk.FORBIDDEN, "tail.follow", "unbounded tail follow is forbidden"
    if not paths or not all(path != "-" and _under(path, host.allowed_read_roots, cwd) for path in paths):
        return Risk.FORBIDDEN, "file-read.path", "file arguments must be inside configured allowed_read_roots"
    return Risk.SENSITIVE_READ, "file-read.allowed-root", "file read is constrained to configured roots"


class CommandPolicy:
    """Conservative default-deny argv policy. Unknown commands never become safe by inference."""

    def evaluate(self, argv: Iterable[str], host: HostConfig, *, kind: RequestKind = RequestKind.COMMAND, cwd: str | None = None, script_language: str | None = None) -> PolicyDecision:
        if kind is RequestKind.SCRIPT:
            if not host.allow_scripts:
                return _decision(host, Risk.FORBIDDEN, "script.disabled", "script execution is disabled for this host")
            if script_language not in {"shell", "python"}:
                return _decision(host, Risk.FORBIDDEN, "script.language", "unsupported script language")
            args = tuple(str(v) for v in argv)
            if any(arg in SHELL_OPERATORS for arg in args):
                return _decision(host, Risk.FORBIDDEN, "script.shell-operator", "shell operators are not valid script arguments")
            return _decision(host, Risk.PRIVILEGED, "script.exact-content-approval", "scripts are arbitrary code and always require exact-content approval")

        try:
            value = _normalize(argv)
        except PolicyError as exc:
            return _decision(host, Risk.FORBIDDEN, "argv.invalid", str(exc))
        if any(arg in SHELL_OPERATORS for arg in value[1:]):
            return _decision(host, Risk.FORBIDDEN, "argv.shell-operator", "pipelines and shell operators are not accepted")
        command = value[0].lower()
        if command in FORBIDDEN_EXECUTABLES:
            return _decision(host, Risk.FORBIDDEN, "executable.escape", f"{command} is an interpreter, wrapper, or escape-capable executable")

        if command in READ_ONLY_SIMPLE:
            risk, rule, reason = Risk.READ, "simple.read", f"{command} is an allowlisted diagnostic"
        elif command in SENSITIVE_SIMPLE:
            risk, rule, reason = Risk.SENSITIVE_READ, "simple.sensitive-read", f"{command} may expose sensitive system data"
        elif command == "systemctl": risk, rule, reason = _systemctl(value)
        elif command == "journalctl": risk, rule, reason = _journalctl(value)
        elif command == "dmesg": risk, rule, reason = _dmesg(value)
        elif command == "pgrep" and any(arg == "--signal" or arg.startswith("--signal=") for arg in value[1:]): risk, rule, reason = Risk.MUTATE, "pgrep.signal", "pgrep --signal changes process state"
        elif command == "pgrep": risk, rule, reason = Risk.SENSITIVE_READ, "pgrep.read", "pgrep inspects process state"
        elif command in {"ss", "netstat"}: risk, rule, reason = (Risk.MUTATE, "ss.kill", "ss --kill terminates sockets") if any(arg in {"-K", "--kill"} for arg in value[1:]) else (Risk.READ, "ss.read", "socket inspection is read-only")
        elif command in {"docker", "podman"}: risk, rule, reason = _docker(value)
        elif command in {"kubectl", "oc"}: risk, rule, reason = _kubectl(value)
        elif command == "find": risk, rule, reason = _find(value, host, cwd)
        elif command in {"awk", "gawk"}: risk, rule, reason = Risk.FORBIDDEN, "awk.dynamic-language", "generic awk is disabled"
        elif command == "git": risk, rule, reason = Risk.FORBIDDEN, "git.repo-hooks", "generic git is disabled because repository config may execute code"
        elif command == "tar": risk, rule, reason = Risk.FORBIDDEN, "tar.external-tools", "generic tar is disabled because options expand the execution surface"
        elif command == "sed": risk, rule, reason = Risk.FORBIDDEN, "generic-writer", "generic sed is forbidden; use a typed capability"
        elif command == "rm": risk, rule, reason = _rm(value)
        elif command in MUTATING_FILE_COMMANDS: risk, rule, reason = Risk.MUTATE, "file.mutate", f"{command} changes filesystem state"
        elif command in {"kill", "pkill", "killall", "renice"}: risk, rule, reason = Risk.MUTATE, "process.mutate", f"{command} changes process state"
        elif command in PACKAGE_MANAGERS: risk, rule, reason = Risk.PRIVILEGED, "package.mutate", f"{command} changes installed software"
        elif command in PRIVILEGED_SYSTEM_COMMANDS: risk, rule, reason = Risk.PRIVILEGED, "system.privileged", f"{command} changes privileged system state"
        elif command == "hostname":
            mutate = any(not arg.startswith("-") or arg in {"-F", "--file", "-b", "--boot"} or arg.startswith("-F") for arg in value[1:])
            risk, rule, reason = (Risk.PRIVILEGED, "hostname.set", "hostname arguments can change system identity") if mutate else (Risk.READ, "hostname.read", "hostname query is read-only")
        elif command == "loginctl":
            if any(arg in {"-H", "--host", "-M", "--machine"} or arg.startswith(("--host=", "--machine=", "-H", "-M")) for arg in value[1:]): risk, rule, reason = Risk.FORBIDDEN, "loginctl.remote", "remote/machine targeting is forbidden"
            elif any(arg in {"terminate-session", "terminate-user", "terminate-seat", "kill-session", "kill-user", "enable-linger", "disable-linger", "lock-session", "unlock-session"} for arg in value[1:]): risk, rule, reason = Risk.PRIVILEGED, "loginctl.mutate", "loginctl changes session state"
            else: risk, rule, reason = Risk.SENSITIVE_READ, "loginctl.read", "loginctl reads session state"
        elif command == "top":
            args = value[1:]
            one = "-n1" in args or ("-n" in args and args.index("-n") + 1 < len(args) and args[args.index("-n") + 1] == "1")
            risk, rule, reason = (Risk.SENSITIVE_READ, "top.read", "bounded top snapshot") if "-b" in args and one else (Risk.FORBIDDEN, "top.interactive", "top must use batch mode with one iteration")
        elif command == "nginx":
            if any(arg in {"-c", "-p", "-g"} or (len(arg) > 2 and arg.startswith(("-c", "-p", "-g"))) for arg in value[1:]): risk, rule, reason = Risk.FORBIDDEN, "nginx.config-override", "nginx config overrides are forbidden"
            elif "-t" in value[1:]: risk, rule, reason = Risk.READ, "nginx.config-test", "nginx -t validates configuration"
            elif "-T" in value[1:]: risk, rule, reason = Risk.SENSITIVE_READ, "nginx.config-dump", "nginx -T dumps configuration"
            elif "-s" in value[1:]: risk, rule, reason = Risk.MUTATE, "nginx.signal", "nginx signal changes process state"
            else: risk, rule, reason = Risk.FORBIDDEN, "nginx.unknown", "unrecognized nginx form"
        elif command == "date":
            mutate = any(arg in {"-s", "--set", "-f", "--file"} or (not arg.startswith("-") and not arg.startswith("+")) for arg in value[1:])
            risk, rule, reason = (Risk.PRIVILEGED, "date.set", "date arguments can change system time") if mutate else (Risk.READ, "date.read", "date query is read-only")
        elif command in {"cat", "head", "tail", "stat", "wc", "du", "ls"}: risk, rule, reason = _file_read(value, host, cwd)
        elif command in {"curl", "wget", "ftp", "tftp"}: risk, rule, reason = Risk.FORBIDDEN, "network.fetch", "generic network fetchers are forbidden"
        elif command in {"crontab", "at", "batch", "systemd-run"}: risk, rule, reason = Risk.FORBIDDEN, "persistence", "persistence mechanisms are forbidden"
        elif command in {"tee", "ed", "ex"}: risk, rule, reason = Risk.FORBIDDEN, "generic-writer", "generic writer tools are forbidden"
        elif command in {"mysql", "psql", "sqlite3", "redis-cli", "mongosh"}: risk, rule, reason = Risk.FORBIDDEN, "database-client", "generic database clients are forbidden in the MVP"
        else: risk, rule, reason = Risk.FORBIDDEN, "command.unknown", "unknown commands are denied by default"
        return _decision(host, risk, rule, reason)
