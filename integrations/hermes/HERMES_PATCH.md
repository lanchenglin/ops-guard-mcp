# Hermes DingTalk 集成补丁

目标：复用 Hermes 已有的 DingTalk Stream 长连接接收 Ops Guard 互动卡片点击，**不让 LLM 参与审批判断**。

## 可选：自动补丁脚本

先 dry-run：

```bash
python integrations/hermes/install_patch.py /path/to/hermes-agent
```

确认目标正确后：

```bash
python integrations/hermes/install_patch.py /path/to/hermes-agent --apply
```

脚本会备份 `adapter.py`，复制 `ops_guard_bridge.py`，并只在当前已验证的 Hermes 代码结构匹配时插入 callback handler；结构不匹配会直接退出，要求手工按下面步骤修改。

## 1. 复制桥接模块

把本目录 `ops_guard_bridge.py` 放到 Hermes：

```text
plugins/platforms/dingtalk/ops_guard_bridge.py
```

## 2. 修改 `plugins/platforms/dingtalk/adapter.py`

在 DingTalk 相关 import 附近增加：

```python
from .ops_guard_bridge import OpsGuardCardCallbackHandler
```

在当前已有的机器人消息注册代码后面增加：

```python
self._stream_client.register_callback_handler(
    dingtalk_stream.ChatbotMessage.TOPIC,
    handler,
)

ops_guard_handler = OpsGuardCardCallbackHandler.from_env()
if ops_guard_handler is not None:
    self._stream_client.register_callback_handler(
        dingtalk_stream.CallbackHandler.TOPIC_CARD_CALLBACK,
        ops_guard_handler,
    )
```

不要创建第二个 `DingTalkStreamClient`。Hermes 和 Ops Guard 使用同一个 DingTalk 应用时，只由 Hermes 持有 Stream 连接。

## 3. Hermes 进程环境

```bash
export OPS_GUARD_DINGTALK_BRIDGE_ENABLED=true
export OPS_GUARD_DINGTALK_BRIDGE_URL=http://127.0.0.1:8765/integrations/dingtalk/decision
export OPS_GUARD_HERMES_BRIDGE_SECRET='至少32字节随机值'
```

`OpsGuardCardCallbackHandler.from_env()` 会在启动时读取并从 `os.environ` 删除桥接密钥，避免 Hermes 后续启动的普通 shell/tool 子进程直接继承该密钥。

Ops Guard daemon 进程需要独立设置**同一个值**：

```bash
export OPS_GUARD_HERMES_BRIDGE_SECRET='同一个随机值'
```

## 4. 安全边界

- Hermes MCP 工具没有 `approve`/`reject`。
- LLM 只能得到 `request_id` 和 `PENDING_APPROVAL` 状态。
- 卡片点击中的 `userId` 来自 DingTalk Stream 回调。
- Hermes 适配器只转发 `ops-guard-*` 卡片，且使用 HMAC + timestamp + 一次性 nonce。
- Ops Guard 再校验审批人白名单/原始会话用户和不可变请求摘要。
- 如果 LLM 具备“在 Hermes Python 进程内执行任意代码”的能力，应把 Hermes 平台网关与 Agent 工具执行器做 OS/容器隔离；本桥接设计防的是 LLM/MCP 权限绕过，不把整个 Hermes 进程视为敌对内核。
