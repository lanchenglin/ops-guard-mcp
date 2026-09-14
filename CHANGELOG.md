# Changelog

## 0.2.2 - 2026-08-26

- Added a production-oriented Dockerfile and Docker Compose deployment for standalone DingTalk Stream mode.
- Added a non-root, read-only, capability-dropped container profile with no published approval port by default.
- Added `docs/DOCKER_COMPOSE_STANDALONE.md` with image build, approval smoke tests, SSH key handling, Hermes stdio integration, backup and upgrade steps.
- Added `docker/.env.example` and `docker/ops-guard.toml.example`.
- Added a Compose `dingtalk-discover` tools profile for deployment-time DingTalk ID discovery.
- Added a fixed root-owned `ops-guard-mcp-stdio` wrapper and sudoers example so Hermes does not need docker-group access.
- Documented that Remote Agent remains a least-privilege host service by default rather than a privileged host-management container.
- Added Docker runtime secret/key exclusions to `.gitignore` and build-context exclusions to `.dockerignore`.

## 0.2.1 - 2026-08-26

- Added the full standalone DingTalk Stream deployment runbook.
- Added `config/ops-guard.standalone-stream.example.toml`.
- Added `scripts/dingtalk-discover-context.py` for deployment-time DingTalk user/group ID discovery.
- Fixed the administration CLI to use the interactive/hybrid DingTalk notifier instead of the legacy webhook notifier.
- Added standalone Stream startup preflight for SDK and credentials.
- Made unexpected standalone Stream termination stop the daemon so systemd can restart it.
- Documented approval-only first deployment with `auto_execute_on_approval=false`.

## 0.2.0 - 2026-08-26

- Added DingTalk enterprise interactive-card delivery to the same Hermes DM/group.
- Added `callback_owner = "hermes" | "ops_guard"`; Hermes mode does not create a competing DingTalk Stream connection.
- Added deterministic Hermes DingTalk callback integration under `integrations/hermes/`.
- Added signed `/integrations/dingtalk/decision` bridge using HMAC-SHA256, timestamp validation and SQLite one-use nonces.
- Added DingTalk approver userId allowlist and originating/default user matching.
- Removed DingTalk approval routing from the model-visible MCP tool schema; routing is administrator/trusted-connector controlled.
- Added default DM/fixed-group DingTalk target support.
- Made APPROVED and REJECTED immutable opposite decisions.
- Retained legacy custom-robot signed confirmation page as webhook/hybrid fallback.
- Added DingTalk card template integration guide and Hermes deployment guide.
- Expanded security regression suite from 42 to 51 tests.

## 0.1.0 - 2026-08-25

- Initial security-first MVP.
- MCP Python SDK v2 server with structured argv tools.
- Default-deny command policy and argument-level escape checks.
- Immutable SHA256 script staging and static findings preview.
- SQLite approval state machine with exact digest binding and expiry.
- DingTalk custom-robot ActionCard notification and signed confirmation links.
- Remote agent HMAC verification, replay protection, second policy evaluation, minimal environment, timeout and output limits.
- SSH transport with fixed administrator-owned remote command and strict host-key checking.
- Redacted hash-chained JSONL audit log.
