# Docker Compose：独立 DingTalk Stream 部署

适用版本：v0.2.2。推荐容器化 **Gateway / Approval Daemon / DingTalk Stream / MCP Runtime**，生产 Remote Agent 仍部署在被管主机宿主机上。

## 安全边界

Compose 默认：非 root UID 10001、read-only rootfs、`cap_drop: ALL`、`no-new-privileges`、tmpfs、state named volume、SSH key 只读挂载，且不发布 8765。不要给 Ops Guard 或 Hermes 挂 `/var/run/docker.sock`，不要为了 Agent 管宿主机而使用 privileged + `/` bind mount。

## 1. 准备

要求 Docker Engine 和 Docker Compose v2。克隆仓库后：

```bash
cp docker/.env.example docker/.env
cp docker/ops-guard.toml.example docker/ops-guard.toml
chmod 600 docker/.env
mkdir -p docker/ssh
touch docker/ssh/.gitkeep
```

编辑 `docker/.env`，填独立 Ops Guard DingTalk Client ID/Secret、approval secret 和测试 Agent secret。编辑 `docker/ops-guard.toml`，填 card template ID、审批人 userId、审批群 conversationId。

首次部署保持：

```toml
auto_execute_on_approval = false
```

## 2. 构建镜像

```bash
docker compose build --pull
```

检查配置：

```bash
docker compose config
```

## 3. 获取 DingTalk IDs

正式 daemon 未启动时：

```bash
docker compose --profile tools run --rm dingtalk-discover
```

给机器人发私聊或在审批群 @机器人，记录 `sender_staff_id` 和 `conversation_id`，然后 Ctrl+C 退出。不要同时启动 discovery 和正式 daemon。

## 4. 启动

```bash
docker compose up -d ops-guard
docker compose ps
docker compose logs -f --tail=200 ops-guard
```

健康检查在容器内部访问 `127.0.0.1:8765/health`，宿主机默认没有公开端口。

## 5. 审批-only smoke test

使用容器 CLI 提交测试请求：

```bash
docker compose exec ops-guard \
  ops-guard --config /etc/ops-guard/ops-guard.toml \
  run local-dev --reason 'standalone approval smoke test' \
  systemctl restart nginx
```

预期：返回 pending、独立审批群收到卡片、管理员点击后状态为 approved，但由于自动执行关闭不会真正执行修改。

查看状态：

```bash
docker compose exec ops-guard \
  ops-guard --config /etc/ops-guard/ops-guard.toml status REQUEST_ID
```

完成错误用户、重复 callback、过期和重启恢复测试后，再把配置改为：

```toml
auto_execute_on_approval = true
```

然后：

```bash
docker compose restart ops-guard
```

## 6. SSH 到 Remote Agent

Gateway 专用私钥和 known_hosts 放到 `docker/ssh/`，Compose 只读挂载到 `/etc/ops-guard/ssh`。权限建议宿主机 0600 私钥、0644 known_hosts；不要把真实 key 提交 Git。

TOML 中使用容器内路径：

```toml
identity_file = "/etc/ops-guard/ssh/prod-web-01"
known_hosts_file = "/etc/ops-guard/ssh/known_hosts"
```

每个远端 Agent 的 HMAC secret 通过 `docker/.env` 的独立环境变量传入。

## 7. Hermes 连接容器内 stdio MCP

MCP 当前是 stdio，不是假 HTTP 服务。Hermes 在宿主机时，不要把 Hermes 用户加入 docker group。安装固定 wrapper：

```bash
sudo install -o root -g root -m 0755 docker/ops-guard-mcp-stdio /usr/local/sbin/ops-guard-mcp-stdio
sudo cp docker/sudoers.ops-guard-mcp.example /etc/sudoers.d/ops-guard-mcp
sudo chmod 0440 /etc/sudoers.d/ops-guard-mcp
sudo visudo -cf /etc/sudoers.d/ops-guard-mcp
```

Hermes MCP command 指向：

```text
sudo /usr/local/sbin/ops-guard-mcp-stdio
```

wrapper 不接受参数、清空 Docker 环境变量，只执行固定本机 `docker exec -i ops-guard ops-guard-mcp`。不要给 Hermes Docker Socket。

Hermes 自身也在容器时，v0.2.2 不建议为了 stdio 连接共享 Docker Socket；优先由宿主机固定 launcher 承担，后续可增加专门的网络 MCP transport。

## 8. 数据持久化与备份

状态位于 named volume `ops-guard-state`，包含 SQLite、artifact 和 audit。备份前可停止服务：

```bash
docker compose stop ops-guard
docker run --rm -v ops-guard-state:/data -v "$PWD/backups":/backup alpine \
  sh -c 'tar czf /backup/ops-guard-state.tgz -C /data .'
docker compose start ops-guard
```

备份包含审批状态和审计信息，应按敏感运维数据保护。

## 9. 升级

```bash
git pull
docker compose build --pull
docker compose up -d --remove-orphans
docker compose ps
docker compose logs --tail=200 ops-guard
```

升级前备份 state volume，升级后先运行只读命令和审批 smoke test。

## 10. 故障排查

- `unhealthy`：查看容器日志和 `/health`；确认 daemon 未因 DingTalk Stream preflight 失败退出。
- Stream 启动失败：检查 `[dingtalk] callback_owner="ops_guard"`、SDK、Client ID/Secret、是否存在第二个同凭据 consumer。
- SSH 失败：检查 key 挂载、known_hosts、容器到服务器网络、远端 force-command 和 HMAC secret。
- Hermes MCP 起不来：检查固定 wrapper、sudoers、容器名必须为 `ops-guard`。

## 11. 生产检查表

- [ ] `docker/.env` 和 `docker/ops-guard.toml` 未提交 Git。
- [ ] 容器非 root、read-only、capabilities 全 drop。
- [ ] 8765 未发布公网。
- [ ] Hermes 无 docker group / Docker Socket。
- [ ] 独立 DingTalk 应用和固定审批群。
- [ ] 审批白名单非空。
- [ ] approval-only smoke test 已通过再开启自动执行。
- [ ] Remote Agent 无通用 sudo，生产脚本关闭。
