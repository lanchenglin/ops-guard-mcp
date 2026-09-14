#!/usr/bin/env bash
set -euo pipefail
printf 'OPS_GUARD_APPROVAL_SECRET=%s\n' "$(openssl rand -hex 32)"
printf 'OPS_GUARD_AGENT_SECRET_LOCAL=%s\n' "$(openssl rand -hex 32)"
printf 'OPS_GUARD_HERMES_BRIDGE_SECRET=%s\n' "$(openssl rand -hex 32)"
