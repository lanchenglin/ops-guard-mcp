# Ops Guard DingTalk 互动卡片模板

Ops Guard v0.2.0 不把卡片模板 JSON 硬编码进程序；先在钉钉卡片平台创建/导入企业互动卡片模板，然后把模板 ID 填入：

```toml
[dingtalk]
card_template_id = "YOUR_CARD_TEMPLATE_ID"
```

## Card Data 变量

程序创建卡片时会提供这些 `cardParamMap` 字段：

| 变量 | 用途 |
|---|---|
| `title` | 标题 |
| `hostId` | 目标主机 |
| `risk` | 风险等级 |
| `ruleId` | 命中的策略规则 |
| `requester` | 申请来源/申请人标签 |
| `reason` | 操作原因 |
| `operation` | 结构化命令或脚本 SHA256 |
| `requestDigest` | 完整不可变请求摘要 |
| `requestDigestShort` | 摘要前 16 位 |
| `expiresAt` | 请求过期时间（Unix timestamp） |
| `status` | `pending/approved/rejected/denied/error` |
| `statusText` | 展示状态 |
| `decisionUser` | 做决定的 DingTalk userId |

建议卡片展示 `hostId / risk / operation / reason / requestDigestShort / expiresAt`。

## 两个按钮

卡片必须包含两个交互按钮，并让点击事件的私有参数最终出现在：

```text
cardPrivateData.params.action
```

批准按钮：

```json
{"action": "ops_guard_approve"}
```

拒绝按钮：

```json
{"action": "ops_guard_reject"}
```

Ops Guard **不根据按钮文字**判断审批，而只接受这两个精确 action 值。

## 回调模式

当前 Hermes 推荐模式创建卡片时使用：

```text
callbackType = STREAM
```

回调 topic：

```text
/v1.0/card/instances/callback
```

Hermes 已有 DingTalk Stream 连接，因此不要再用相同 Client ID 启动第二条 Ops Guard Stream。详见 `../hermes/HERMES_PATCH.md`。

## 状态更新

卡片点击后 Ops Guard 返回卡片更新数据：

```text
status
statusText
decisionUser
```

模板可以根据 `status != pending` 隐藏/禁用按钮；即使模板没有隐藏，服务端状态机也会阻止把一个最终决定翻转成另一个决定。
