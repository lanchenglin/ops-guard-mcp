# Ops Guard MCP v0.2.2 Release Notes

发布日期：2026-08-26

本版基于 v0.2.1，新增正式 Docker / Docker Compose 部署资产，重点服务于**独立 Ops Guard DingTalk Stream**部署。Risk Routing v0.3.0 仍只保留设计，不在本版实现。

主要变化：

- 新增根目录 `Dockerfile`，基于 Python 3.12 slim，默认非 root 用户 `10001:10001`。
- 新增 `docker-compose.yml`，默认启动独立 Stream approval daemon。
- Compose 默认 `read_only`、`cap_drop: ALL`、`no-new-privileges`、tmpfs、named state volume，且不发布 8765 到宿主机。
- 新增 `docs/DOCKER_COMPOSE_STANDALONE.md`，覆盖从构建镜像、DingTalk ID discovery、审批 smoke test、Agent 接入、SSH key、Hermes stdio 到备份升级的完整 Runbook。
- 新增 `docker/.env.example` 和 `docker/ops-guard.toml.example`。
- 新增 Compose `dingtalk-discover` tools profile，可在 daemon 停止时获取 DingTalk `conversationId/userId`。
- 新增 `docker/ops-guard-mcp-stdio` 固定 launcher 与 sudoers 示例，供宿主机 Hermes 在**不加入 docker group**的情况下连接容器内 stdio MCP。
- 明确禁止为了 MCP 接入给 Hermes 容器挂 `/var/run/docker.sock`。
- 明确生产 Remote Agent 默认继续使用宿主机最小权限 systemd 部署，而不是 privileged 容器。
- 新增 Docker secrets/runtime 文件的 `.gitignore` 与 `.dockerignore` 保护。

部署入口：

```text
docs/DOCKER_COMPOSE_STANDALONE.md
```

钉钉后台与独立 Stream 细节仍参考：

```text
docs/DINGTALK_STANDALONE_STREAM.md
```
