#!/usr/bin/env bash
set -Eeuo pipefail

APPLY=0
HOST_ID=""
PUBLIC_KEY_FILE=""
WHEEL_FILE=""
USER_NAME="ops-guard"
VENV_DIR="/opt/ops-guard"
CONFIG_DIR="/etc/ops-guard"
STATE_DIR="/var/lib/ops-guard"
WORK_DIR="/tmp/ops-guard"

usage() {
  cat <<USAGE
Usage:
  $0 --host-id HOST --public-key-file KEY.pub --wheel FILE.whl [--apply]

Default is dry-run. Pass --apply to make changes.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --host-id) HOST_ID=${2:?}; shift 2 ;;
    --public-key-file) PUBLIC_KEY_FILE=${2:?}; shift 2 ;;
    --wheel) WHEEL_FILE=${2:?}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$HOST_ID" && -f "$PUBLIC_KEY_FILE" && -f "$WHEEL_FILE" ]] || { usage >&2; exit 2; }

run() {
  printf '+ '; printf '%q ' "$@"; printf '\n'
  if [[ "$APPLY" -eq 1 ]]; then "$@"; fi
}

write_file() {
  local path=$1 mode=$2 owner=$3 content=$4
  echo "+ write $path mode=$mode owner=$owner"
  if [[ "$APPLY" -eq 1 ]]; then
    local tmp; tmp=$(mktemp)
    printf '%s' "$content" >"$tmp"
    install -o "${owner%%:*}" -g "${owner##*:}" -m "$mode" "$tmp" "$path"
    rm -f "$tmp"
  fi
}

if [[ "$EUID" -ne 0 ]]; then
  echo "Run as root (dry-run also checks intended root operations)." >&2
  exit 1
fi

if ! id "$USER_NAME" >/dev/null 2>&1; then run useradd --create-home --shell /bin/sh "$USER_NAME"; fi
run install -d -o root -g "$USER_NAME" -m 0750 "$CONFIG_DIR"
run install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$STATE_DIR" "$WORK_DIR"
run install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "/home/$USER_NAME/.ssh"
run python3 -m venv "$VENV_DIR"
run "$VENV_DIR/bin/pip" install --upgrade "$WHEEL_FILE"

secret=$(openssl rand -hex 32)
agent_config="[agent]
host_id = \"$HOST_ID\"
secret_env = \"OPS_GUARD_AGENT_SECRET\"
secret_file = \"$CONFIG_DIR/agent.secret\"
nonce_db = \"$STATE_DIR/nonces.sqlite3\"
allowed_read_roots = [\"/var/log\"]
allowed_workdirs = [\"$WORK_DIR\"]
default_workdir = \"$WORK_DIR\"
allow_scripts = false
trusted_executable_dirs = [\"/usr/local/sbin\", \"/usr/local/bin\", \"/usr/sbin\", \"/usr/bin\", \"/sbin\", \"/bin\"]
max_timeout_seconds = 60
max_output_bytes = 1048576

[agent.script_interpreters]
shell = [\"/bin/bash\", \"--noprofile\", \"--norc\"]
python = [\"/usr/bin/python3\", \"-I\", \"-B\"]
"
write_file "$CONFIG_DIR/agent.toml" 0640 "root:$USER_NAME" "$agent_config"
write_file "$CONFIG_DIR/agent.secret" 0640 "root:$USER_NAME" "$secret"$'\n'

public_key=$(tr -d '\r\n' <"$PUBLIC_KEY_FILE")
forced="restrict,command=\"$VENV_DIR/bin/ops-guard-agent --config $CONFIG_DIR/agent.toml execute\" $public_key"
write_file "/home/$USER_NAME/.ssh/authorized_keys" 0600 "$USER_NAME:$USER_NAME" "$forced"$'\n'

cat <<SUMMARY

Installation plan complete.
Mode: $([[ "$APPLY" -eq 1 ]] && echo APPLY || echo DRY-RUN)
Host ID: $HOST_ID
Agent HMAC secret (copy once to the gateway host-specific environment variable):
$secret

Review and narrow allowed_read_roots/allowed_workdirs before production use.
Do not grant this account general sudo.
SUMMARY
