# AI / Hermes 自动部署 Runbook

适用版本：Ops Guard MCP v0.2.2+

本文档是给 **Hermes、Codex、Claude Code、ChatGPT Work、其他具备 SSH / Shell / Git 能力的 AI Agent** 使用的部署执行说明。

目标：AI 读取本仓库后，只要用户补充少量部署参数，就可以完成 Ops Guard 的安装、配置、审批链验证、Remote Agent 接入和 Hermes MCP 接入，而不需要用户重新解释整个架构。

> 默认推荐部署形态：**Docker Compose Gateway + 独立 Ops Guard DingTalk Stream + 宿主机 Remote Agent**。

---

## 1. AI 执行契约

当你是负责部署本项目的 AI Agent 时：

1. 先阅读：
   - `README.md`
   - 本文件
   - `docs/DINGTALK_STANDALONE_STREAM.md`
   - `docs/DOCKER_COMPOSE_STANDALONE.md`
   - `docs/SECURITY_MODEL.md`
   - `config/ai-deploy-params.example.yaml`
2. 以用户提供的参数为准，不猜测真实 IP、账号、userId、conversationId、Client Secret、SSH key 或生产目录。
3. 仅询问**仍缺失且无法安全使用默认值**的参数。
4. 所有 secret 只能写入运行环境或未跟踪的 `.env` / env file，禁止提交 Git。
5. 第一次部署必须保持：
   `auto_execute_on_approval = false`
6. 必须先完成 approval-only smoke test，再允许开启自动执行。
7. 不允许为了省事：
   - 使用 `--privileged`；
   - 挂载 `/var/run/docker.sock` 给 Hermes / Ops Guard；
   - 暴露 approval HTTP 端口到公网；
   - 使用 root 作为 Remote Agent 日常账号；
   - 给 Remote Agent 通用 sudo；
   - 关闭 host-key 校验；
   - 把真实密钥写入仓库；
   - 绕过 Ops Guard 的审批数据库直接执行高风险动作。
8. 任何安全前置条件失败时，停止在当前阶段，报告失败点，不自动降低安全配置。
9. 部署结束必须输出“部署结果摘要”，但不得打印 Client Secret、HMAC Secret、私钥内容或其他 secret。

---

## 2. 推荐拓扑

```text
Hermes / AI
     |
     | MCP stdio
     v
Ops Guard Gateway / Daemon
(Docker Compose)
     |
     | high-risk request
     v
独立 Ops Guard DingTalk App
     |
     v
独立运维审批群
 [批准一次] [拒绝]
     |
     | DingTalk Stream
     v
Ops Guard Approval Controller
     |
     | signed request
     v
Remote Agent
(unprivileged host service)
```

默认要求：

- Hermes DingTalk App 与 Ops Guard Approval App 使用不同 Client ID / Secret；
- Ops Guard 独立持有自己的 Stream；
- Remote Agent 安装在被管主机宿主机；
- Gateway 与 Agent 之间固定 SSH key、known_hosts 和 HMAC secret；
- 生产默认关闭通用脚本执行。

---

## 3. 用户需要提供的参数

推荐让用户按 `config/ai-deploy-params.example.yaml` 提供。

### 3.1 最小必需参数

| 参数 | 是否必需 | 说明 |
|---|---|---|
| gateway_host | 是 | 部署 Ops Guard Gateway 的服务器 |
| gateway_ssh_user | 是 | AI 用于部署 Gateway 的 SSH 用户 |
| deploy_mode | 否 | 默认 `docker_compose` |
| install_dir | 否 | 默认 `/opt/ops-guard-mcp` |
| dingtalk_client_id | 是 | 独立 Ops Guard 企业应用 Client ID |
| dingtalk_client_secret | 是 | 只通过 secret/env 输入，不入 Git |
| card_template_id | 是 | DingTalk 互动卡片模板 ID |
| approver_user_ids | 是 | 至少一个真实审批人 userId/staffId |
| approval_group_conversation_id | 是 | 独立审批群 conversationId |
| primary_approver_user_id | 是 | 默认 @/上下文用户 |
| auto_execute_after_validation | 否 | 默认 `false`，测试通过后用户可设为 true |

### 3.2 接生产服务器时额外需要

每台被管服务器至少提供：

- `host_id`
- `ssh_host`
- `ssh_port`（默认 22）
- `ssh_user`（推荐 `ops-guard`）
- `environment`（dev/staging/prod）
- `allowed_read_roots`
- `allowed_workdirs`
- `default_workdir`

Gateway 使用的 SSH 私钥应由部署流程生成或由用户指定现有专用 key；禁止复用个人 root/admin 私钥。

---

## 4. 参数缺失处理规则

AI 不要一次性重新询问全部参数。

只检查：

1. 用户是否已经给过；
2. 能否使用文档里的安全默认值；
3. 是否属于 secret / 真实身份 /真实地址等不可猜参数。

可安全默认：

```yaml
deploy_mode: docker_compose
install_dir: /opt/ops-guard-mcp
repo_url: https://github.com/lanchenglin/ops-guard-mcp.git
branch: main
approval_mode: standalone_stream
auto_execute_after_validation: false
approval_http_public: false
remote_agent_allow_scripts: false
```

不可猜：

```text
真实服务器 IP / 域名
SSH 登录账号
DingTalk Client ID / Secret
审批人 userId
审批群 conversationId
互动卡片 Template ID
现有 SSH 私钥路径
真实生产服务名称
```

---

## 5. 阶段 A：Gateway 主机预检

通过 SSH 登录 Gateway 主机后，检查：

```bash
uname -a
id
docker --version
docker compose version
git --version
df -h
```

要求：

- Docker Engine 可用；
- Docker Compose v2 可用；
- 安装目录所在文件系统空间足够；
- 当前部署账号有合法 Docker 管理能力；
- 不把 Hermes 用户加入 docker group 作为 MCP 连接方案。

若 Docker 不存在，使用目标系统官方/受信任包源安装；不要执行来源不明的远程安装脚本。

---

## 6. 阶段 B：拉取固定仓库版本

推荐：

```bash
sudo mkdir -p /opt
cd /opt
sudo git clone https://github.com/lanchenglin/ops-guard-mcp.git
sudo chown -R "$USER":"$USER" /opt/ops-guard-mcp
cd /opt/ops-guard-mcp
git status
git rev-parse HEAD
```

若目录已存在：

```bash
cd /opt/ops-guard-mcp
git fetch --all --prune
git status
```

已有本地修改时不要直接覆盖；先报告差异。

生产环境建议部署用户给出明确 commit/tag；若只给 `main`，部署前记录最终 commit SHA 到结果摘要。

---

## 7. 阶段 C：创建 Docker 运行配置

```bash
cd /opt/ops-guard-mcp
cp docker/.env.example docker/.env
cp docker/ops-guard.toml.example docker/ops-guard.toml
chmod 600 docker/.env
mkdir -p docker/ssh
```

### 7.1 写入 docker/.env

必须使用用户真实参数填入，但不要在日志/最终答复打印 secret。

至少：

```dotenv
OPS_GUARD_LOG_LEVEL=INFO
OPS_GUARD_APPROVAL_SECRET=<随机生成>
OPS_GUARD_AGENT_SECRET_LOCAL=<随机生成>
OPS_GUARD_DINGTALK_CLIENT_ID=<用户提供>
OPS_GUARD_DINGTALK_CLIENT_SECRET=<用户提供>
```

随机 secret 使用：

```bash
openssl rand -hex 32
```

### 7.2 修改 docker/ops-guard.toml

第一次部署必须保证：

```toml
[server]
auto_execute_on_approval = false
```

DingTalk 独立审批：

```toml
[dingtalk]
enabled = true
mode = "interactive"
callback_owner = "ops_guard"
card_template_id = "<用户提供>"
allowed_approver_user_ids = ["<用户提供>"]
require_context_sender_match = false
default_conversation_type = "2"
default_sender_staff_id = "<primary approver userId>"
default_conversation_id = "<approval group conversationId>"
```

禁止把真实 Client Secret 写入 TOML。

---

## 8. 阶段 D：若 DingTalk userId / conversationId 尚未知

只有当用户没有这些 ID 时才执行 discovery。

先确保正式 daemon 未运行：

```bash
docker compose stop ops-guard 2>/dev/null || true
docker compose --profile tools run --rm dingtalk-discover
```

让审批人在目标私聊/审批群向机器人发送消息。

记录：

- `sender_staff_id`
- `conversation_id`
- `conversation_type`

完成后退出 discovery。

**不要让 discovery 和正式 Ops Guard daemon 同时持有同一套 Stream 凭据。**

---

## 9. 阶段 E：构建并启动

```bash
docker compose config
docker compose build --pull
docker compose up -d ops-guard
docker compose ps
docker compose logs --tail=200 ops-guard
```

必须确认：

- 容器为 running/healthy；
- DingTalk Stream preflight 成功；
- 没有第二个相同 Client ID 的 Stream consumer；
- `8765` 没有被发布到公网。

如果 daemon 因 DingTalk preflight 失败退出，先修复，不要关闭 fail-fast。

---

## 10. 阶段 F：Approval-only smoke test

这是正式执行前的强制门槛。

保持：

```toml
auto_execute_on_approval = false
```

提交一个测试审批请求。

预期流程：

```text
request
  -> pending_approval
  -> 独立审批群收到卡片
  -> 未授权用户不能批准
  -> 授权管理员点击
  -> approved
  -> 不自动执行真实修改
```

至少验证：

- 合法审批人可以批准；
- 非白名单 userId 不可批准；
- 重复 callback 不改变最终状态；
- 过期请求不能批准；
- daemon 重启后状态仍存在；
- Stream 重连正常。

任何一项失败，不进入下一阶段。

---

## 11. 阶段 G：安装 Remote Agent

只有用户要求接入真实服务器时才执行。

原则：

- 每台/每组主机专用 HMAC secret；
- 专用 `ops-guard` OS 用户；
- 不给通用 sudo；
- SSH authorized_keys 使用 force-command/restrict；
- fixed known_hosts；
- 生产默认 `allow_scripts=false`。

先构建 wheel：

```bash
cd /opt/ops-guard-mcp
python3 -m venv .build-venv
.build-venv/bin/pip install -U pip build
.build-venv/bin/python -m build
```

对目标主机先 dry-run：

```bash
sudo scripts/install-agent.sh \
  --host-id <HOST_ID> \
  --public-key-file <GATEWAY_PUBLIC_KEY> \
  --wheel dist/ops_guard_mcp-0.2.2-py3-none-any.whl
```

人工/AI 检查 dry-run 输出后才使用 `--apply`。

把生成的 Agent HMAC secret 只写入 Gateway 的 `docker/.env` 对应变量。

再把主机加入 `docker/ops-guard.toml`：

```toml
[[hosts]]
id = "prod-web-01"
environment = "prod"
transport = "ssh-agent"
allow_scripts = false
ssh_host = "..."
ssh_user = "ops-guard"
identity_file = "/etc/ops-guard/ssh/prod-web-01"
known_hosts_file = "/etc/ops-guard/ssh/known_hosts"
agent_secret_env = "OPS_GUARD_AGENT_SECRET_PROD_WEB_01"
```

不要设置 `StrictHostKeyChecking=no`。

---

## 12. 阶段 H：开启自动执行

只有以下条件全部成立：

- approval-only smoke test 通过；
- Remote Agent 连通；
- known_hosts 已固定；
- Agent HMAC 一致；
- 只读诊断测试成功；
- 用户参数明确允许 `auto_execute_after_validation=true`。

然后才改：

```toml
[server]
auto_execute_on_approval = true
```

并：

```bash
docker compose restart ops-guard
docker compose logs --tail=100 ops-guard
```

先验证只读命令，再验证一个低影响、用户明确允许的审批动作。

---

## 13. 阶段 I：连接 Hermes

Hermes 与 Ops Guard Gateway 在同一宿主机时，推荐固定 stdio launcher。

安装：

```bash
sudo install -o root -g root -m 0755 docker/ops-guard-mcp-stdio /usr/local/sbin/ops-guard-mcp-stdio
sudo cp docker/sudoers.ops-guard-mcp.example /etc/sudoers.d/ops-guard-mcp
sudo chmod 0440 /etc/sudoers.d/ops-guard-mcp
sudo visudo -cf /etc/sudoers.d/ops-guard-mcp
```

Hermes MCP command：

```text
sudo /usr/local/sbin/ops-guard-mcp-stdio
```

不要：

- 把 Hermes 加入 docker group；
- 给 Hermes Docker Socket；
- 让 Hermes 直接拿 Gateway SSH 私钥；
- 给 Hermes approve/reject API。

验证 Hermes 能看到：

- `ops_list_hosts`
- `ops_run_command`
- `ops_stage_script`
- `ops_request_status`
- `ops_pending_approvals`
- `ops_execute_approved`
- `ops_audit_tail`

高风险请求必须仍由 DingTalk 独立审批通道改变状态。

---

## 14. 部署完成验证

AI 必须执行并记录结果：

```bash
docker compose ps
docker compose logs --tail=100 ops-guard
git rev-parse HEAD
```

并检查：

- 容器 healthy；
- DingTalk Stream 在线；
- SQLite/state volume 可持久化；
- 审批群可收到卡片；
- 非授权 userId 不能审批；
- approval-only 测试已通过；
- Remote Agent（若配置）只读诊断成功；
- Hermes（若配置）能发现 MCP tools；
- Git 工作区没有 secret 被跟踪。

检查 Git：

```bash
git status --short
git check-ignore docker/.env docker/ops-guard.toml docker/ssh/* || true
```

---

## 15. 回滚规则

### Gateway 配置错误

恢复备份配置，然后：

```bash
docker compose up -d --force-recreate ops-guard
```

### 新镜像异常

回到部署前记录的 commit：

```bash
git checkout <PREVIOUS_COMMIT>
docker compose build
docker compose up -d --force-recreate
```

### 审批链异常

立即：

```toml
auto_execute_on_approval = false
```

重启 Gateway。

不要通过关闭审批或开放任意 shell 来“临时恢复”。

### Remote Agent 异常

从 Gateway 配置中暂时禁用该 host，保留审计和审批状态，不删除历史记录。

---

## 16. AI 最终输出格式

部署完成后，AI 应返回类似：

```text
Ops Guard 部署结果

版本/Commit:
部署模式: Docker Compose
审批模式: 独立 DingTalk Stream
Gateway:
容器状态:
DingTalk Stream:
审批群:
审批人数量:
auto_execute_on_approval:
Remote Hosts:
Hermes MCP:
安全测试:
Git 工作区:
待处理事项:
```

绝对不要打印：

- DingTalk Client Secret；
- Approval HMAC secret；
- Agent HMAC secret；
- SSH 私钥；
- 任何 token/password。

---

## 17. 一次性交给 AI 的推荐指令

用户以后可以直接对 Hermes / Codex / 其他 AI 说：

```text
请读取仓库 lanchenglin/ops-guard-mcp 的 AGENTS.md、
docs/AI_DEPLOYMENT_RUNBOOK.md 和 config/ai-deploy-params.example.yaml。

按仓库定义的安全部署流程部署 Ops Guard。
使用我下面给的参数；已有参数不要重复问，只有缺少且不能安全使用默认值的参数才询问我。
第一次必须以 auto_execute_on_approval=false 完成 approval-only smoke test，
全部验证通过后，只有当 auto_execute_after_validation=true 时才开启自动执行。
不得把 secret 提交 Git，不得使用 privileged / Docker Socket / 通用 sudo，
不得跳过 DingTalk 人工审批。

参数：
<粘贴参数>
```

---

## 18. 相关文档

- `README.md`
- `docs/DINGTALK_STANDALONE_STREAM.md`
- `docs/DOCKER_COMPOSE_STANDALONE.md`
- `docs/HERMES_DINGTALK.md`
- `docs/SECURITY_MODEL.md`
- `config/ai-deploy-params.example.yaml`
