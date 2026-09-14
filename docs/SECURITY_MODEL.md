# Security Model v0.2.2

## 目标

假设 AI 可能幻觉、被 prompt injection、组合命令绕过规则、生成脚本、重复调用工具或错误宣称“用户已经批准”。目标不是让 AI 永远做对，而是让这些行为**没有未经授权的危险能力**。

## 核心不变量

1. AI 不持有服务器 SSH 私钥。
2. AI 不获得通用 SSH/shell tool。
3. MCP 接收结构化 argv，不把模型字符串交给 shell。
4. unknown command = deny。
5. 模型不能指定 executable path。
6. Agent 使用 `shell=False`。
7. 高风险请求只有数据库真实状态为 APPROVED 才能领取执行。
8. MCP schema 中没有 `approve` / `reject`。
9. 审批 capability URL/token 默认不返回模型。
10. 审批动作来自 DingTalk card callback 的 `userId` + 固定 action，不是聊天文本。
11. Hermes bridge 请求必须通过 HMAC、时间窗和 one-use nonce。
12. APPROVED/REJECTED 决定不能翻转。
13. 脚本审批绑定完整 SHA256。
14. Agent 再验 request digest、审批、nonce 和风险等级。
15. 最终 blast radius 由远端最小权限 OS 账户决定。

## Hermes 幻觉确认威胁

即使 Hermes 再调用 `ops_execute_approved(req)`，DB 状态仍是 `pending_approval` 时 claim 会失败，不会执行。只有真实 DingTalk card click -> callback userId -> deterministic handler/controller -> approver policy -> DB APPROVED 才能改变状态。

## 独立 Ops Guard Stream

`callback_owner = "ops_guard"` 时卡片 callback 不经过 Hermes：DingTalk Stream SDK -> `userId` -> Approval Controller -> allowlist -> DB decision。Hermes 与 Ops Guard 应使用不同 DingTalk 应用凭据。这样普通 Hermes 幻觉、prompt injection，甚至 Hermes 平台进程被攻陷，都不能直接伪造独立审批 Stream 回调。

## Hermes bridge 信任边界

桥接模式能防 LLM 幻觉、模型伪造确认、普通 MCP prompt injection、payload 篡改、重放、错误用户点击和终态反转。但若攻击者能在 Hermes Python 同一进程执行任意代码或读取内存，则属于 platform process compromise，应通过 OS/容器隔离进一步加固。

## 脚本

批准脚本等价于批准任意代码在 `ops-guard` OS 用户权限下执行。因此生产默认 `allow_scripts=false`；静态扫描只提供提示；script hash 从 Gateway stage 到 Agent execute 全链路一致；高权限需求最终应迁移为 typed helper。

## Fail closed

DingTalk 通知失败、签名错误、超时、nonce 重放、审批人不匹配、digest mismatch、策略分类失败、Agent secret/known_hosts 缺失、executable 不可信、script SHA256 不一致等情况都不会自动放行。

## 生产检查

- Hermes、Gateway、Remote Agent 分离 OS 用户/容器。
- `allowed_approver_user_ids` 明确非空。
- 独立审批模式使用独立 DingTalk Client ID / Secret 且只有一个 Stream consumer。
- SSH key 仅 Gateway 可读；known_hosts 固定；authorized_keys force-command/restrict。
- Remote Agent 无通用 sudo；生产脚本关闭；trusted executable dirs 对 Agent 用户不可写。
- 审计外送独立存储并定期执行 bypass/replay/regression tests。
