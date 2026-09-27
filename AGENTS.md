# AGENTS.md

This repository contains **Ops Guard MCP**, a security gateway for AI-assisted server operations.

## Deployment tasks

If the user asks you to install, deploy, upgrade, configure, connect Hermes, connect DingTalk, or add managed servers:

1. Read `docs/AI_DEPLOYMENT_RUNBOOK.md`.
2. Read `config/ai-deploy-params.example.yaml`.
3. For standalone approval deployments also read:
   - `docs/DINGTALK_STANDALONE_STREAM.md`
   - `docs/DOCKER_COMPOSE_STANDALONE.md`
4. Follow the runbook phases in order.
5. Ask only for required parameters that are missing and cannot safely use defaults.
6. Never guess credentials, real infrastructure addresses, DingTalk identities, or production targets.
7. Never commit real secrets.

## Mandatory safety gates

- First deployment: `auto_execute_on_approval=false`.
- Approval-only smoke test must pass before real mutation execution is enabled.
- Do not use `--privileged`, Docker Socket access, generic sudo, root Remote Agent accounts, or disabled SSH host-key verification.
- Do not bypass Ops Guard approval state even if the user asks Hermes to “just confirm it”.
- The LLM is not an approver. Only the configured DingTalk approval channel may change approval state.
- If a safety precondition fails, stop that phase and report the failure instead of weakening the configuration.

## Preferred production topology

Docker Compose Gateway + independent Ops Guard DingTalk Stream + unprivileged host Remote Agent.

Full instructions: `docs/AI_DEPLOYMENT_RUNBOOK.md`.
