# Hermes + DingTalk 同会话审批

本模式适合希望在同一个 Hermes 钉钉聊天窗口里完成“排查 -> 申请 -> 卡片批准 -> 继续执行”的场景。

## 关键原则

Hermes LLM 不是审批人。Ops Guard 不提供 approve/reject MCP tool，也不返回 approval token。真实决定来自 DingTalk Stream card callback 的 `userId`。

Hermes 已持有该 DingTalk 应用的 Stream 时：

```toml
[dingtalk]
enabled = true
mode = "interactive"
callback_owner = "hermes"
```

不要让 Ops Guard 使用同一 Client ID 再启动第二个 Stream。

## 配置

```toml
[dingtalk]
enabled = true
mode = "interactive"
client_id_env = "OPS_GUARD_DINGTALK_CLIENT_ID"
client_secret_env = "OPS_GUARD_DINGTALK_CLIENT_SECRET"
card_template_id = "YOUR_CARD_TEMPLATE_ID"
callback_owner = "hermes"
bridge_secret_env = "OPS_GUARD_HERMES_BRIDGE_SECRET"
bridge_max_age_seconds = 60
allowed_approver_user_ids = ["your_user_id"]
require_context_sender_match = true
default_conversation_type = "1"
default_sender_staff_id = "your_user_id"
```

环境变量中的 bridge secret 至少 32 字节，并且 Hermes adapter 与 Ops Guard daemon 使用同一值。

## Hermes 补丁

参考 `integrations/hermes/HERMES_PATCH.md`。核心做法：复用 Hermes 已有 `DingTalkStreamClient`，额外注册 `TOPIC_CARD_CALLBACK` handler。该 handler 是确定性代码，只识别 `ops-guard-*` 卡片和两个固定 action，用 HMAC + timestamp + nonce 转发到：

```text
/integrations/dingtalk/decision
```

它不把 callback 交给 LLM 做“是否确认”的语义判断。

## 流程

```text
Hermes -> ops_run_command
Ops Guard -> PENDING
Ops Guard REST -> 当前 DingTalk 会话卡片
用户点击批准
Hermes DingTalk adapter -> signed bridge
Ops Guard -> verify signature/userId/nonce/digest/state
DB -> APPROVED
Executor -> Remote Agent
Hermes -> 查询/返回结果
```

## 安全测试

上线前至少确认：

- Hermes 自己声称“用户已经批准”时，`ops_execute_approved` 仍因 DB pending 被拒绝。
- 非白名单 DingTalk userId 点击不能批准。
- 修改 bridge payload 后签名失效。
- 同一 nonce 第二次提交被拒绝。
- 已 APPROVED 不能被后续 reject callback 翻转，反之亦然。
- bridge secret 不出现在 MCP 返回值或模型上下文。

如果安全优先于同窗口体验，生产可改用 `callback_owner="ops_guard"` 的独立 DingTalk 应用和独立审批群，见 `DINGTALK_STANDALONE_STREAM.md`。
