from __future__ import annotations

import os
import re
import tomllib
import urllib.parse
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .models import HostConfig


class ConfigError(ValueError):
    pass


DEFAULT_TRUSTED_EXECUTABLE_DIRS = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)

_SAFE_REMOTE_ARG_RE = re.compile(r"^[A-Za-z0-9_./:@%+=,-]+$")


@dataclass(frozen=True, slots=True)
class DingTalkConfig:
    enabled: bool = False
    # webhook: legacy custom robot + signed web approval page
    # interactive: same-conversation enterprise-bot interactive card + Stream callback
    # hybrid: interactive first, webhook fallback if delivery context/API is unavailable
    mode: str = "webhook"
    webhook_url_env: str = "OPS_GUARD_DINGTALK_WEBHOOK"
    secret_env: str = "OPS_GUARD_DINGTALK_SECRET"
    client_id_env: str = "OPS_GUARD_DINGTALK_CLIENT_ID"
    client_secret_env: str = "OPS_GUARD_DINGTALK_CLIENT_SECRET"
    card_template_id: str = ""
    # hermes: Hermes owns the only DingTalk Stream connection and forwards signed callbacks.
    # ops_guard: standalone mode; Ops Guard owns the Stream connection itself.
    callback_owner: str = "hermes"
    bridge_secret_env: str = "OPS_GUARD_HERMES_BRIDGE_SECRET"
    bridge_max_age_seconds: int = 60
    allowed_approver_user_ids: tuple[str, ...] = ()
    require_context_sender_match: bool = True
    at_requester: bool = True
    # Useful for a single-user Hermes DM: same-window delivery works without per-tool context.
    default_conversation_type: str = "1"
    default_sender_staff_id: str = ""
    default_conversation_id: str = ""
    default_sender_nick: str = ""
    timeout_seconds: int = 10


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    path: Path
    state_dir: Path
    approval_base_url: str
    approval_link_secret_env: str
    request_ttl_seconds: int
    auto_execute_on_approval: bool
    bind_host: str
    bind_port: int
    trusted_approver_header: str | None
    dingtalk: DingTalkConfig
    hosts: dict[str, HostConfig]

    def get_host(self, host_id: str) -> HostConfig:
        try:
            return self.hosts[host_id]
        except KeyError as exc:
            raise ConfigError(f"unknown host_id: {host_id}") from exc

    def required_secret(self, env_name: str) -> bytes:
        value = os.environ.get(env_name)
        if not value:
            raise ConfigError(f"required environment variable is not set: {env_name}")
        if len(value) < 32:
            raise ConfigError(f"secret in {env_name} must be at least 32 characters")
        return value.encode("utf-8")


@dataclass(frozen=True, slots=True)
class AgentConfig:
    path: Path
    host_id: str
    secret_env: str
    secret_file: Path | None
    nonce_db: Path
    allowed_read_roots: tuple[str, ...]
    allowed_workdirs: tuple[str, ...]
    default_workdir: str
    allow_scripts: bool
    script_interpreters: dict[str, tuple[str, ...]]
    trusted_executable_dirs: tuple[str, ...]
    max_timeout_seconds: int
    max_output_bytes: int

    def secret(self) -> bytes:
        value = os.environ.get(self.secret_env)
        source = self.secret_env
        if not value and self.secret_file is not None:
            try:
                value = self.secret_file.read_text(encoding="utf-8").strip()
                source = str(self.secret_file)
            except OSError as exc:
                raise ConfigError(f"unable to read agent secret file: {self.secret_file}") from exc
        if not value:
            raise ConfigError(
                f"agent secret not found in environment {self.secret_env} or configured secret_file"
            )
        if len(value) < 32:
            raise ConfigError(f"secret in {source} must be at least 32 characters")
        return value.encode("utf-8")


def _absolute_path(base: Path, raw: str) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = (base / path).resolve()
    return path


def _expect_table(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a TOML table")
    return value


def _validated_remote_roots(values: Any, name: str, *, allow_empty: bool) -> tuple[str, ...]:
    if not isinstance(values, list):
        raise ConfigError(f"{name} must be an array")
    result: list[str] = []
    for raw in values:
        value = str(raw)
        if not value.startswith("/") or "\x00" in value or "\n" in value or "\r" in value:
            raise ConfigError(f"{name} entries must be absolute POSIX paths")
        normalized = str(PurePosixPath(value))
        if normalized not in result:
            result.append(normalized)
    if not result and not allow_empty:
        raise ConfigError(f"{name} must not be empty")
    return tuple(result)


def _under_remote_root(path: str, roots: tuple[str, ...]) -> bool:
    normalized = str(PurePosixPath(path))
    return any(
        normalized == root or normalized.startswith(root.rstrip("/") + "/")
        for root in roots
    )


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if parsed < minimum or parsed > maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _validated_remote_command(value: Any, host_id: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigError(f"remote_command for {host_id} must be a non-empty array")
    command = tuple(str(v) for v in value)
    if not command[0].startswith("/"):
        raise ConfigError(
            f"remote_command for {host_id} must use an absolute agent executable path"
        )
    for arg in command:
        if not arg or not _SAFE_REMOTE_ARG_RE.fullmatch(arg):
            raise ConfigError(
                f"remote_command for {host_id} contains an unsafe shell token: {arg!r}"
            )
    return command


def load_gateway_config(path: str | os.PathLike[str]) -> GatewayConfig:
    config_path = Path(path).expanduser().resolve()
    with config_path.open("rb") as handle:
        raw = tomllib.load(handle)

    server = _expect_table(raw.get("server", {}), "server")
    dingtalk_raw = _expect_table(raw.get("dingtalk", {}), "dingtalk")
    base = config_path.parent
    state_dir = _absolute_path(base, str(server.get("state_dir", "./state")))

    hosts: dict[str, HostConfig] = {}
    raw_hosts = raw.get("hosts", [])
    if not isinstance(raw_hosts, list) or not raw_hosts:
        raise ConfigError("at least one [[hosts]] entry is required")

    for item in raw_hosts:
        host = _expect_table(item, "hosts entry")
        host_id = str(host.get("id", "")).strip()
        if not host_id:
            raise ConfigError("each host requires a non-empty id")
        if host_id in hosts:
            raise ConfigError(f"duplicate host id: {host_id}")
        transport = str(host.get("transport", "ssh-agent"))
        if transport not in {"ssh-agent", "local-agent"}:
            raise ConfigError(f"unsupported transport for {host_id}: {transport}")
        remote_command_raw = host.get(
            "remote_command", ["/opt/ops-guard/bin/ops-guard-agent", "execute"]
        )
        identity_file = host.get("identity_file")
        known_hosts_file = host.get("known_hosts_file")
        allowed_read_roots = _validated_remote_roots(
            host.get("allowed_read_roots", []),
            f"hosts[{host_id}].allowed_read_roots",
            allow_empty=True,
        )
        allowed_workdirs = _validated_remote_roots(
            host.get("allowed_workdirs", ["/tmp"]),
            f"hosts[{host_id}].allowed_workdirs",
            allow_empty=False,
        )
        default_workdir = str(host.get("default_workdir", "/tmp"))
        if not default_workdir.startswith("/") or not _under_remote_root(
            default_workdir, allowed_workdirs
        ):
            raise ConfigError(
                f"default_workdir for {host_id} must be inside allowed_workdirs"
            )
        timeout_seconds = _bounded_int(
            host.get("timeout_seconds", 30),
            f"hosts[{host_id}].timeout_seconds",
            1,
            600,
        )
        max_output_bytes = _bounded_int(
            host.get("max_output_bytes", 1_048_576),
            f"hosts[{host_id}].max_output_bytes",
            1024,
            16 * 1024 * 1024,
        )
        remote_command = (
            _validated_remote_command(remote_command_raw, host_id)
            if transport == "ssh-agent"
            else tuple(str(v) for v in remote_command_raw)
        )
        hosts[host_id] = HostConfig(
            host_id=host_id,
            environment=str(host.get("environment", "dev")),
            transport=transport,
            approve_sensitive_reads=bool(host.get("approve_sensitive_reads", False)),
            allow_scripts=bool(host.get("allow_scripts", False)),
            allowed_read_roots=allowed_read_roots,
            allowed_workdirs=allowed_workdirs,
            default_workdir=default_workdir,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            ssh_host=host.get("ssh_host"),
            ssh_user=host.get("ssh_user"),
            ssh_port=int(host.get("ssh_port", 22)),
            identity_file=(
                str(_absolute_path(base, str(identity_file))) if identity_file else None
            ),
            known_hosts_file=(
                str(_absolute_path(base, str(known_hosts_file))) if known_hosts_file else None
            ),
            remote_command=remote_command,
            agent_secret_env=str(host.get("agent_secret_env", "OPS_GUARD_AGENT_SECRET")),
        )
        if transport == "ssh-agent":
            if not hosts[host_id].ssh_host or not hosts[host_id].ssh_user:
                raise ConfigError(f"ssh-agent host {host_id} requires ssh_host and ssh_user")
            if not re.fullmatch(r"[A-Za-z0-9_.:-]+", str(hosts[host_id].ssh_host)):
                raise ConfigError(f"ssh_host for {host_id} contains unsafe characters")
            if not re.fullmatch(r"[A-Za-z0-9._-]+", str(hosts[host_id].ssh_user)):
                raise ConfigError(f"ssh_user for {host_id} contains unsafe characters")
            if not 1 <= hosts[host_id].ssh_port <= 65535:
                raise ConfigError(f"ssh_port for {host_id} must be between 1 and 65535")
            if not hosts[host_id].known_hosts_file:
                raise ConfigError(f"ssh-agent host {host_id} requires known_hosts_file")
        elif hosts[host_id].environment.lower() in {"prod", "production"}:
            raise ConfigError(
                f"local-agent transport is development-only and cannot target {host_id} production"
            )

    approval_base_url = str(
        server.get("approval_base_url", "http://127.0.0.1:8765")
    ).rstrip("/")
    parsed_approval_url = urllib.parse.urlparse(approval_base_url)
    if parsed_approval_url.scheme not in {"http", "https"} or not parsed_approval_url.netloc:
        raise ConfigError("server.approval_base_url must be an absolute http(s) URL")
    request_ttl_seconds = _bounded_int(
        server.get("request_ttl_seconds", 300),
        "server.request_ttl_seconds",
        30,
        3600,
    )
    bind_port = _bounded_int(server.get("bind_port", 8765), "server.bind_port", 0, 65535)

    dingtalk_mode = str(dingtalk_raw.get("mode", "webhook")).strip().lower()
    if dingtalk_mode not in {"webhook", "interactive", "hybrid"}:
        raise ConfigError("dingtalk.mode must be webhook, interactive, or hybrid")
    approvers_raw = dingtalk_raw.get("allowed_approver_user_ids", [])
    if not isinstance(approvers_raw, list):
        raise ConfigError("dingtalk.allowed_approver_user_ids must be an array")
    if bool(dingtalk_raw.get("enabled", False)) and dingtalk_mode in {"interactive", "hybrid"}:
        if not str(dingtalk_raw.get("card_template_id", "")).strip():
            raise ConfigError("dingtalk.card_template_id is required for interactive/hybrid mode")
        callback_owner = str(dingtalk_raw.get("callback_owner", "hermes")).strip().lower()
        if callback_owner not in {"hermes", "ops_guard"}:
            raise ConfigError("dingtalk.callback_owner must be hermes or ops_guard")
        default_type = str(dingtalk_raw.get("default_conversation_type", "1")).strip()
        if default_type not in {"1", "2"}:
            raise ConfigError("dingtalk.default_conversation_type must be '1' or '2'")
        default_sender = str(dingtalk_raw.get("default_sender_staff_id", "")).strip()
        default_conversation = str(dingtalk_raw.get("default_conversation_id", "")).strip()
        if default_type == "2" and default_sender and not default_conversation:
            raise ConfigError("group default DingTalk target requires default_conversation_id")

    return GatewayConfig(
        path=config_path,
        state_dir=state_dir,
        approval_base_url=approval_base_url,
        approval_link_secret_env=str(
            server.get("approval_link_secret_env", "OPS_GUARD_APPROVAL_SECRET")
        ),
        request_ttl_seconds=request_ttl_seconds,
        auto_execute_on_approval=bool(server.get("auto_execute_on_approval", True)),
        bind_host=str(server.get("bind_host", "127.0.0.1")),
        bind_port=bind_port,
        trusted_approver_header=(
            str(server["trusted_approver_header"])
            if server.get("trusted_approver_header")
            else None
        ),
        dingtalk=DingTalkConfig(
            enabled=bool(dingtalk_raw.get("enabled", False)),
            mode=str(dingtalk_raw.get("mode", "webhook")).strip().lower(),
            webhook_url_env=str(
                dingtalk_raw.get("webhook_url_env", "OPS_GUARD_DINGTALK_WEBHOOK")
            ),
            secret_env=str(dingtalk_raw.get("secret_env", "OPS_GUARD_DINGTALK_SECRET")),
            client_id_env=str(
                dingtalk_raw.get("client_id_env", "OPS_GUARD_DINGTALK_CLIENT_ID")
            ),
            client_secret_env=str(
                dingtalk_raw.get("client_secret_env", "OPS_GUARD_DINGTALK_CLIENT_SECRET")
            ),
            card_template_id=str(dingtalk_raw.get("card_template_id", "")).strip(),
            callback_owner=str(dingtalk_raw.get("callback_owner", "hermes")).strip().lower(),
            bridge_secret_env=str(
                dingtalk_raw.get("bridge_secret_env", "OPS_GUARD_HERMES_BRIDGE_SECRET")
            ),
            bridge_max_age_seconds=_bounded_int(
                dingtalk_raw.get("bridge_max_age_seconds", 60),
                "dingtalk.bridge_max_age_seconds",
                10,
                300,
            ),
            allowed_approver_user_ids=tuple(
                str(item).strip()
                for item in dingtalk_raw.get("allowed_approver_user_ids", [])
                if str(item).strip()
            ),
            require_context_sender_match=bool(
                dingtalk_raw.get("require_context_sender_match", True)
            ),
            at_requester=bool(dingtalk_raw.get("at_requester", True)),
            default_conversation_type=str(
                dingtalk_raw.get("default_conversation_type", "1")
            ).strip(),
            default_sender_staff_id=str(
                dingtalk_raw.get("default_sender_staff_id", "")
            ).strip(),
            default_conversation_id=str(
                dingtalk_raw.get("default_conversation_id", "")
            ).strip(),
            default_sender_nick=str(dingtalk_raw.get("default_sender_nick", "")).strip(),
            timeout_seconds=_bounded_int(
                dingtalk_raw.get("timeout_seconds", 10),
                "dingtalk.timeout_seconds",
                1,
                60,
            ),
        ),
        hosts=hosts,
    )


def load_agent_config(path: str | os.PathLike[str]) -> AgentConfig:
    config_path = Path(path).expanduser().resolve()
    with config_path.open("rb") as handle:
        raw = tomllib.load(handle)
    agent = _expect_table(raw.get("agent", {}), "agent")
    base = config_path.parent
    host_id = str(agent.get("host_id", "")).strip()
    if not host_id:
        raise ConfigError("agent.host_id is required")
    raw_interpreters = _expect_table(
        agent.get(
            "script_interpreters",
            {"shell": ["/bin/bash", "--noprofile", "--norc"], "python": ["/usr/bin/python3", "-I", "-B"]},
        ),
        "agent.script_interpreters",
    )
    interpreters: dict[str, tuple[str, ...]] = {}
    for name, command in raw_interpreters.items():
        if not isinstance(command, list) or not command:
            raise ConfigError(f"script interpreter {name} must be a non-empty array")
        interpreters[str(name)] = tuple(str(v) for v in command)

    allowed_read_roots = _validated_remote_roots(
        agent.get("allowed_read_roots", []),
        "agent.allowed_read_roots",
        allow_empty=True,
    )
    allowed_workdirs = _validated_remote_roots(
        agent.get("allowed_workdirs", ["/tmp"]),
        "agent.allowed_workdirs",
        allow_empty=False,
    )
    default_workdir = str(agent.get("default_workdir", "/tmp"))
    if not default_workdir.startswith("/") or not _under_remote_root(
        default_workdir, allowed_workdirs
    ):
        raise ConfigError("agent.default_workdir must be inside agent.allowed_workdirs")
    trusted_executable_dirs = _validated_remote_roots(
        agent.get("trusted_executable_dirs", list(DEFAULT_TRUSTED_EXECUTABLE_DIRS)),
        "agent.trusted_executable_dirs",
        allow_empty=False,
    )

    return AgentConfig(
        path=config_path,
        host_id=host_id,
        secret_env=str(agent.get("secret_env", "OPS_GUARD_AGENT_SECRET")),
        secret_file=(
            _absolute_path(base, str(agent["secret_file"]))
            if agent.get("secret_file")
            else None
        ),
        nonce_db=_absolute_path(base, str(agent.get("nonce_db", "./agent-nonces.sqlite3"))),
        allowed_read_roots=allowed_read_roots,
        allowed_workdirs=allowed_workdirs,
        default_workdir=default_workdir,
        allow_scripts=bool(agent.get("allow_scripts", False)),
        script_interpreters=interpreters,
        trusted_executable_dirs=trusted_executable_dirs,
        max_timeout_seconds=_bounded_int(
            agent.get("max_timeout_seconds", 120),
            "agent.max_timeout_seconds",
            1,
            600,
        ),
        max_output_bytes=_bounded_int(
            agent.get("max_output_bytes", 1_048_576),
            "agent.max_output_bytes",
            1024,
            16 * 1024 * 1024,
        ),
    )
