# 独立 Ops Guard DingTalk Stream 完整部署手册

适用版本：Ops Guard MCP v0.2.2。

本模式使用**独立的钉钉企业应用、独立 Client ID/Secret、独立审批群**。Hermes 只负责通过 MCP 申请操作，不参与审批 callback，也不能把自然语言“确认”转换成 APPROVED。

## 1. 生产拓扑

```text
DingTalk/Hermes chat
       |
       | MCP request
       v
Ops Guard Gateway
       |-- read -> execute
       |
       `-- mutation -> PENDING
                      |
                      v
           Ops Guard DingTalk App
                      |
               独立运维审批群
                 [批准] [拒绝]
                      |
               DingTalk Stream
                      |
                      v
             Approval Controller
                      |
                DB APPROVED
                      |
                 Executor/SSH
                      |
                 Remote Agent
```

安全原则：Hermes 与 Ops Guard **不要共用同一个 DingTalk Client ID/Secret**。同一企业应用应只保留一个 Stream consumer。

## 2. 准备独立钉钉应用

在钉钉开放平台创建企业内部应用，例如 `Ops Guard Approval`，启用机器人和 Stream 模式。记录：

- Client ID / AppKey；
- Client Secret / AppSecret；
- 机器人可见范围；
- 审批管理员 userId；
- 审批群 conversationId；
- 互动卡片 template ID。

不要把 Client Secret 写入 TOML、Git 或镜像；只通过环境变量注入。

## 3. 创建审批群

建议单独建立 `生产运维审批群`，把 Ops Guard 机器人加入。管理员通过 `allowed_approver_user_ids` 白名单控制，群成员并不自动拥有审批权。

固定群推荐：

```toml
[dingtalk]
callback_owner = "ops_guard"
allowed_approver_user_ids = ["admin-user-id-a", "admin-user-id-b"]
require_context_sender_match = false
default_conversation_type = "2"
default_sender_staff_id = "admin-user-id-a"
default_conversation_id = "cidXXXXXXXX"
```

## 4. 获取 userId / conversationId

安装依赖后，在 Ops Guard daemon **未运行**时执行：

```bash
export OPS_GUARD_DINGTALK_CLIENT_ID='ding_xxx'
export OPS_GUARD_DINGTALK_CLIENT_SECRET='xxx'
python scripts/dingtalk-discover-context.py
```

审批人在私聊或审批群里给机器人发消息，终端会打印：

```json
{
  "conversation_type": "2",
  "conversation_id": "cid...",
  "sender_staff_id": "user-id...",
  "sender_nick": "..."
}
```

记录 ID 后按 Ctrl+C 退出。不要让 discovery 工具和正式 daemon 同时持有同一套 Stream 凭据。

## 5. 创建互动审批卡片

按 `integrations/dingtalk/CARD_TEMPLATE.md` 创建模板，至少展示：目标主机、风险、策略规则、操作、原因、请求摘要、有效期和状态。

两个按钮私有参数必须精确为：

```json
{"action":"ops_guard_approve"}
```

```json
{"action":"ops_guard_reject"}
```

记录卡片 Template ID。

## 6. 安装 Gateway（Python/systemd）

```bash
sudo useradd --system --home /var/lib/ops-guard --shell /usr/sbin/nologin ops-guard-gateway || true
sudo install -d -o ops-guard-gateway -g ops-guard-gateway -m 0700 /var/lib/ops-guard
sudo install -d -o root -g ops-guard-gateway -m 0750 /etc/ops-guard
sudo install -d -o root -g root -m 0755 /opt/ops-guard-mcp
```

把源码放到 `/opt/ops-guard-mcp` 后：

```bash
cd /opt/ops-guard-mcp
python3 -m venv .venv
.venv/bin/pip install -U pip
.venv/bin/pip install -e '.[dingtalk]'
```

复制配置：

```bash
sudo cp config/ops-guard.standalone-stream.example.toml /etc/ops-guard/gateway.toml
sudo chown root:ops-guard-gateway /etc/ops-guard/gateway.toml
sudo chmod 0640 /etc/ops-guard/gateway.toml
```

## 7. 第一阶段必须关闭自动执行

首次联调：

```toml
[server]
auto_execute_on_approval = false
```

先只验证：

```text
申请 -> PENDING -> 卡片 -> 真实管理员点击 -> APPROVED
```

此阶段即便批准，也不会执行服务器修改。

## 8. 环境变量

生成密钥：

```bash
openssl rand -hex 32
```

`/etc/ops-guard/gateway.env` 示例：

```bash
OPS_GUARD_APPROVAL_SECRET=<random-64-hex>
OPS_GUARD_AGENT_SECRET_LOCAL=<random-64-hex>
OPS_GUARD_DINGTALK_CLIENT_ID=ding_xxx
OPS_GUARD_DINGTALK_CLIENT_SECRET=<secret>
```

权限：

```bash
sudo chown root:ops-guard-gateway /etc/ops-guard/gateway.env
sudo chmod 0640 /etc/ops-guard/gateway.env
```

## 9. 启动 systemd

```bash
sudo cp systemd/ops-guard-daemon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ops-guard-daemon
sudo systemctl status ops-guard-daemon --no-pager
sudo journalctl -u ops-guard-daemon -n 100 --no-pager
```

独立模式启动时会检查 `dingtalk-stream` SDK、Client ID、Secret；缺失则 fail-fast。Stream 线程异常退出时 daemon 会退出，由 systemd 重启，避免“主进程还活着但审批通道已经死掉”。

## 10. Approval-only smoke test

在另一个终端加载 Gateway 环境后提交一个无害的测试变更请求，例如在 `local-dev` 使用项目自带 CLI。预期：

1. CLI 返回 `pending_approval`；
2. 审批群出现互动卡片；
3. 未授权人员点击显示 denied，DB 仍 pending；
4. 授权管理员点击后变为 approved；
5. 因 `auto_execute_on_approval=false`，不会自动执行。

还要测试：重复点击、过期请求、错误 userId、Stream 重连、daemon 重启后的状态保持。

## 11. 打开自动执行

确认审批链路无误后：

```toml
[server]
auto_execute_on_approval = true
```

重启：

```bash
sudo systemctl restart ops-guard-daemon
```

先在 `local-dev` 或隔离测试服务器验证一次，再接生产主机。

## 12. 安装 Remote Agent

生产主机使用专用 `ops-guard` 用户，无通用 sudo。推荐构建 wheel 后先 dry-run：

```bash
sudo scripts/install-agent.sh \
  --host-id prod-web-01 \
  --public-key-file /path/to/ops-guard.pub \
  --wheel dist/ops_guard_mcp-0.2.2-py3-none-any.whl
```

确认后加 `--apply`。脚本会生成 Agent HMAC secret，并用 `restrict,command=...` 写入 authorized_keys。把 secret 只复制到 Gateway 对应环境变量。

生产配置必须固定：known_hosts、专用 SSH key、允许读取目录、工作目录和 Agent secret；生产默认 `allow_scripts=false`。

## 13. 上线安全检查

- Hermes 和 Ops Guard 使用不同 DingTalk 应用。
- `allowed_approver_user_ids` 非空。
- 只有一个 Ops Guard Stream consumer。
- `auto_execute_on_approval=false` 的审批-only 测试已通过。
- 错误审批人无法改变状态。
- 请求过期、nonce 重放、digest mismatch 都 fail closed。
- Gateway SSH key 权限最小；Remote Agent 无通用 sudo。
- 审计链可执行 `ops-guard verify-audit` 验证。

## 14. 故障排查

### 没有卡片

检查 daemon 日志、Client ID/Secret、卡片 template ID、conversationId、机器人是否在审批群、应用可见范围。

### 卡片有但点击没反应

确认 `callback_owner="ops_guard"`、SDK 已安装、同 Client ID 没有第二个 Stream consumer，并查看 daemon Stream callback 日志。

### 点击后 denied

核对 callback `userId` 与 `allowed_approver_user_ids`。固定多人群通常设置 `require_context_sender_match=false`，授权仍由白名单决定。

### 请求 approved 但不执行

首次部署若 `auto_execute_on_approval=false` 属正常现象。启用自动执行后再检查 Worker、SSH、known_hosts、Agent HMAC secret 和远端 force-command。

## 15. 回退

若独立互动卡片暂时不可用，可暂时切换 `mode="webhook"` 使用旧版签名审批页；不要为了恢复业务而绕过数据库审批状态或临时开放任意 SSH/shell。
