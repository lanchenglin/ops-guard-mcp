# Ops Guard MCP

面向 AI/Hermes 日常运维排障的安全 MCP：**只读诊断尽量自动化，高风险变更必须由真实人工审批；模型没有 SSH 私钥、没有任意 shell、没有 approve 工具。**

当前版本：`0.2.2`（2026-08-26）

## v0.2.0 的重点：Hermes + 钉钉同会话审批

推荐使用方式：

```text
你（钉钉单聊/群聊）
        ↕
      Hermes
        │ MCP：只能申请操作/查状态
        ▼
   Ops Guard MCP
        │
        ├─ LOW / 已知只读 → 自动执行
        │
        └─ HIGH / 修改操作
               │
               ├─ 创建不可变 request + digest
               └─ DingTalk REST 投放互动卡片到原聊天窗口
                         │
                         ▼
              [批准一次] [拒绝]
                         │
                  真实用户点击
                         │ DingTalk Stream callback
                         ▼
            Hermes DingTalk 平台适配器
              （确定性代码，不进入 LLM）
                         │ HMAC + timestamp + nonce
                         ▼
       /integrations/dingtalk/decision
                         │
                         ▼
              Ops Guard Approval
                         │
                  PENDING → APPROVED
                         │
                         ▼
                Remote Executor
```

这里 **Hermes 的 LLM 不能批准请求**：

- MCP 工具中不存在 `approve()` / `reject()`；
- MCP 返回值不包含审批 token/URL；
- 审批路由不由模型控制；
- 真正的决定来自钉钉卡片回调里的 `userId`；
- Hermes 平台适配器只做确定性转发，并用独立 HMAC 桥接；
- Ops Guard 再做审批人白名单、请求摘要、TTL、nonce 和状态机检查；
- 已经批准/拒绝的决定不能反向改写。

> 安全边界说明：普通“LLM 幻觉”或 MCP prompt injection 无法凭自然语言把状态改成 APPROVED。若攻击者已经能在 **Hermes Python 进程内部执行任意代码/读取进程内存**，则 Hermes 平台进程本身已被攻陷，需通过 OS/容器隔离或独立审批接入进一步加固。详见 `docs/SECURITY_MODEL.md`。

## 为什么不是普通 SSH MCP

普通 SSH MCP 常见接口：

```text
ssh_exec(command: "任意 shell 字符串")
```

这种接口很难可靠拦截，模型可以利用：

- `bash -c` / `sh -c`；
- Python/Perl/Node 等解释器；
- `find -exec`、`xargs`、`awk system()`；
- 重定向、command substitution；
- 下载后执行；
- 先上传脚本，再绕过命令关键字检查。

Ops Guard 改成：

```text
AI / MCP Client
      │ structured argv / immutable script
      ▼
Security Gateway
  ├─ default-deny policy
  ├─ exact request digest
  ├─ SQLite approval state machine
  ├─ DingTalk interactive approval
  └─ hash-chained audit
      │ signed JSON envelope over fixed SSH command
      ▼
Remote Agent
  ├─ HMAC verification
  ├─ one-use nonce
  ├─ policy re-evaluation
  ├─ script SHA256 re-check
  └─ subprocess argv, shell=False
      ▼
Dedicated unprivileged OS account
```

## 已实现

### MCP / 策略

- MCP Python SDK v2 stdio server。
- `argv: list[str]`，不接收任意 shell 字符串。
- 未知命令默认拒绝。
- 模型不能指定 executable 路径，只能使用裸命令名。
- 拒绝通用 shell/解释器/wrapper/隧道/下载执行入口。
- `find -exec/-execdir` 等直接拒绝；写入型参数进入修改审批。
- Docker/Kubernetes/systemd/进程/文件操作按参数语义判级。
- MCP schema **不暴露审批路由参数**，模型不能决定把卡片发给谁。

### 脚本

- 脚本先保存在 Gateway 的内容寻址仓库。
- 审批绑定完整 `SHA256(content)`。
- 批准后只传输被批准的同一字节内容。
- Agent 执行前重新计算 SHA256。
- 不存在“先批准 `/tmp/fix.sh`，再覆盖同名脚本”的 TOCTOU 窗口。
- 生产 `allow_scripts=false` 默认关闭。

### 审批

- SQLite 原子状态机：`pending_approval -> approved/rejected -> executing -> succeeded/failed`。
- APPROVED 与 REJECTED 是不可翻转的决定。
- request digest 绑定 host、argv、cwd、风险、原因、申请人、TTL、nonce、脚本 hash 等。
- 互动卡片同会话审批。
- 钉钉 `userId` 白名单。
- 可要求“点击用户必须等于原会话用户/默认审批用户”。
- Hermes bridge：HMAC-SHA256 + 时间窗 + 一次性 nonce。
- 旧版自定义机器人 + 外部双确认页仍作为 `webhook` / `hybrid` fallback 保留。

### 远端执行

- SSH 固定管理员配置的远端 Agent 命令。
- StrictHostKeyChecking、known_hosts、无 PTY、无 forwarding、无密码认证。
- Agent 独立验证 HMAC、host、digest、approval、expiry、nonce。
- Agent 独立重新判级，拒绝 Gateway 风险降级。
- executable 仅从管理员可信且 Agent 用户不可写目录解析。
- `subprocess` 结构化 argv，`shell=False`。
- 最小环境、timeout、output cap、进程组清理。

### 审计

- JSONL 哈希链。
- 不保存原始 stdout/stderr 到审计链，只保存长度和 SHA256。
- 记录 DingTalk 用户、桥接来源、拒绝原因、request digest。

## 风险默认值

| 能力 | 默认行为 |
|---|---|
| `uptime/free/df/ps/ss/journalctl` 等已知诊断 | 自动执行 |
| 敏感只读 | 按主机策略自动或审批 |
| `systemctl restart/stop` | 审批 |
| `kill/rm/chmod/chown` | 审批 |
| `kubectl apply/delete/scale` | 审批 |
| Kubernetes Secret 读取 | 高风险审批 |
| shell / Python / Perl / Node 通用入口 | 拒绝 |
| `docker exec/run/build` 通用入口 | 拒绝 |
| `kubectl exec/debug/cp/port-forward` | 拒绝 |
| `curl/wget` 通用下载 | 拒绝 |
| 未知命令 | 拒绝 |
| 生产脚本 | 默认关闭 |

## 快速安装

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
cp config/ops-guard.example.toml config/ops-guard.toml

export OPS_GUARD_CONFIG="$PWD/config/ops-guard.toml"
export OPS_GUARD_APPROVAL_SECRET="$(openssl rand -hex 32)"
export OPS_GUARD_AGENT_SECRET_LOCAL="$(openssl rand -hex 32)"
```

开发测试：

```bash
ops-guard-daemon --config "$OPS_GUARD_CONFIG"
ops-guard-mcp
```

## Hermes + DingTalk 同窗口审批配置

详细步骤见：[`docs/HERMES_DINGTALK.md`](docs/HERMES_DINGTALK.md)。

独立审批机器人 / 独立 Stream 生产部署见：[`docs/DINGTALK_STANDALONE_STREAM.md`](docs/DINGTALK_STANDALONE_STREAM.md)。

Docker / Docker Compose 独立 Stream 部署见：[`docs/DOCKER_COMPOSE_STANDALONE.md`](docs/DOCKER_COMPOSE_STANDALONE.md)。

Docker 快速入口：

```bash
cp docker/.env.example docker/.env
cp docker/ops-guard.toml.example docker/ops-guard.toml
chmod 600 docker/.env
docker compose build --pull
docker compose up -d ops-guard
```

> Docker 版默认只容器化 Gateway/Daemon/DingTalk Stream。生产 Remote Agent 仍建议以最小权限宿主机服务部署；不要为了“全容器化”给 Agent 或 Hermes 挂 Docker Socket / privileged。

最小配置示例：

```toml
[dingtalk]
enabled = true
mode = "interactive"
client_id_env = "OPS_GUARD_DINGTALK_CLIENT_ID"
client_secret_env = "OPS_GUARD_DINGTALK_CLIENT_SECRET"
card_template_id = "YOUR_CARD_TEMPLATE_ID"

# Hermes 已经持有 DingTalk Stream 连接，所以推荐这个模式。
callback_owner = "hermes"
bridge_secret_env = "OPS_GUARD_HERMES_BRIDGE_SECRET"
bridge_max_age_seconds = 60

allowed_approver_user_ids = ["your_dingtalk_user_id"]
require_context_sender_match = true

# 单用户 Hermes 私聊：固定投放回当前机器人私聊。
default_conversation_type = "1"
default_sender_staff_id = "your_dingtalk_user_id"
default_sender_nick = "运维管理员"
```

环境变量：

```bash
export OPS_GUARD_DINGTALK_CLIENT_ID='dingxxxxxxxx'
export OPS_GUARD_DINGTALK_CLIENT_SECRET='xxxxxxxx'
export OPS_GUARD_HERMES_BRIDGE_SECRET="$(openssl rand -hex 32)"
```

然后把：

```text
integrations/hermes/ops_guard_bridge.py
```

复制进 Hermes DingTalk plugin，并按：

```text
integrations/hermes/HERMES_PATCH.md
```

注册卡片回调 handler。

**不要让 Ops Guard 再启动同一个 DingTalk Client ID 的第二条 Stream。** `callback_owner="hermes"` 就是为这个场景准备的。

## 钉钉互动卡片模板

模板字段、按钮 action 配置见：

```text
integrations/dingtalk/CARD_TEMPLATE.md
```

两个按钮必须分别回传：

```text
ops_guard_approve
ops_guard_reject
```

Ops Guard 从回调 `cardPrivateData.params.action` 获取动作，从 DingTalk 回调对象获取真实 `userId`。

## MCP 工具

- `ops_list_hosts`
- `ops_run_command`
- `ops_stage_script`
- `ops_request_status`
- `ops_pending_approvals`
- `ops_execute_approved`
- `ops_audit_tail`

高风险示例：

```json
{
  "host_id": "prod-web-01",
  "argv": ["systemctl", "restart", "nginx"],
  "reason": "nginx 配置检查正常但 worker 无响应，需要重启",
  "requester": "hermes"
}
```

返回类似：

```json
{
  "status": "pending_approval",
  "approval_request": {
    "required": true,
    "notification_sent": true
  }
}
```

不会返回 `approve_url`、`approval_token` 或 `approve()` 能力。

即使 Hermes 再调用：

```text
ops_execute_approved(request_id)
```

只要 SQLite 仍是 `pending_approval`，执行器就不会执行。

## 两种互动回调所有权

### 推荐：Hermes 模式

```toml
callback_owner = "hermes"
```

Hermes 的现有 DingTalk Stream 收卡片 callback，确定性 adapter 转发给 Ops Guard。

优点：

- 同一个 DingTalk 应用只有一个 Stream consumer；
- 卡片仍然出现在 Hermes 原对话窗口；
- 不需要 Ops Guard 争抢 Hermes 的 Stream 连接。

### 独立模式

```toml
callback_owner = "ops_guard"
```

生产推荐让 Ops Guard 使用**独立 DingTalk 企业应用、独立 Client ID / Secret、独立审批群**。不要与 Hermes 共用同一套 Stream 凭据。

```bash
pip install -e '.[dingtalk]'
```

完整从 0 部署、获取 `userId/conversationId`、卡片模板、systemd、审批-only smoke test、安全测试、故障排查见：

```text
docs/DINGTALK_STANDALONE_STREAM.md
```

辅助发现审批群/审批人 ID：

```bash
python scripts/dingtalk-discover-context.py
```

v0.2.1 在独立 Stream 模式增加 fail-fast preflight；SDK/Client ID/Secret 缺失时 daemon 不再以“审批 Stream 已死但主进程仍正常”的状态继续运行。

## 旧版外部审批页

仍支持：

```toml
mode = "webhook"
```

流程是自定义机器人 ActionCard -> 签名 URL -> GET 预览 -> POST 确认。它适合作为 fallback，但同会话互动卡片的用户身份更清晰。

## 远端服务器生产要求

- 专用 `ops-guard` OS 用户，不用 root。
- 无通用 sudo。
- SSH `authorized_keys` 建议 `restrict,command=...`。
- 每台/每组主机独立 Agent HMAC secret。
- known_hosts 固定。
- `trusted_executable_dirs` 必须是管理员控制且 Agent 用户不可写。
- 生产默认关闭脚本。
- 高权限动作逐步改造成 typed privileged helper。
- Gateway/Hermes/Agent 最好使用不同 OS 用户或容器隔离。

## 测试

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

v0.2.1 当前回归集：`51 tests`。

覆盖包括：

- shell/解释器/wrapper 绕过；
- executable 路径冒充；
- SQLite digest/TTL/原子领取；
- APPROVED/REJECTED 不可翻转；
- immutable script SHA256；
- Agent HMAC/nonce/风险二次判级；
- DingTalk 错误审批用户；
- Hermes bridge 签名篡改；
- Hermes bridge nonce 重放；
- HTTP bridge 真实状态迁移；
- timeout/output cap；
- hash-chain audit。

## 重要文档

- `docs/ARCHITECTURE.md`
- `docs/HERMES_DINGTALK.md`
- `docs/SECURITY_MODEL.md`
- `docs/IMPLEMENTATION_STATUS.md`
- `docs/RESEARCH_SUMMARY.md`
- `docs/ROADMAP.md`
- `integrations/hermes/HERMES_PATCH.md`
- `integrations/dingtalk/CARD_TEMPLATE.md`

## License

Apache-2.0
